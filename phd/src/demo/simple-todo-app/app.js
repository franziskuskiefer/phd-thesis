const express = require('express');
const app = express();
const mongoose = require('mongoose');
const crypto = require('crypto');
const url = require("url");
const clientSessions = require("client-sessions");

/* DEFAULT PATH */
var DEFAULT_PATH = "/";

/* parse request bodies */
app.use(express.bodyParser());

/* static content directory */
app.use(express.static(__dirname + '/public'));

/* mongoose connection */
mongoose.connect('mongodb://localhost/todo');
var todoSchema = mongoose.Schema({ user: String, text: String });
var todo = mongoose.model('todo', todoSchema);

/* escaping strings against xss */
function encode(s) {
	return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
};

/* fix for lighttpd fuu -> parse plain/text post requests */
app.use(function(req, res, next){
	if (req.is('text/*')) {
		req.text = '';
		req.setEncoding('utf8');
		req.on('data', function(chunk){ req.text += chunk });
		req.on('end', next);
	} else {
		next();
	}
});

/* USER MANAGEMENT CONFIG */

/* includes */
var config = require("./config");
//var login = require("./login");
var db = require("./db");

/* connect db */
db.connect();

/* parameters */
var mobileParams = {
	sessionID: '',
	authURL: config.AUTH_URL,
	url: config.URL,
	branding: config.IMAGE_URL
};

var browserParams = {
	sessionID: '',
	versions: ["POW_v1_tSOKE_secp192r1_SHA256_certHash"],
	msg: "POWServerHello",
	authURL: "https://www.franziskuskiefer.de/pow/login/pow.php",
	sitename: "Test POW site",
	description: "Welcome to the test of the POW secure password authentication system. Please enter your username and password.",
	imgURL: "https://developer.cdn.mozilla.net/media/img/mdn-logo-sm.png",
	usernameLabel: "Login name",
	passwordLabel: "Password",
	forgotURL: "http://www.example.net/forgotURL"
};


/* SECURITY --- CHECK USER AUTH */

/* client side session cookie */
app.use(clientSessions({
  secret: crypto.randomBytes(256).toString('hex'), // TODO: is this good randomness?
  requestKey: 'my_session', // name of session in request --- defaults to session_state
  cookieName: 'userhandler', // let's give that cookie a name
  duration: 24 * 60 * 60 * 1000, // how long the session will stay valid in ms
  cookie: {
    // path: '/api', // cookie will only be sent to requests under '/api'
    // maxAge: 60000, // duration of the cookie in milliseconds, defaults to duration above
    ephemeral: true, // when true, cookie expires when the browser closes
    httpOnly: true, // when true, cookie is not accessible from javascript
    secure: false   // when true, cookie will only be sent over SSL
  }
}));

/* check user (is only done for api calls) */
function checkAuth(req, res, next) {
	if (!req.my_session || !req.my_session.username) {
		console.log("welcome stranger!");
		res.send("sorry... not logged in :|");
	} else {
		next();
	}
};

/* ROUTING */

function renderPage(req, res, device){
	var username = req.my_session.username;
	console.log('hello "'+username+'"');
		res.render('index.jade', {user: username, mobile: 0, params: JSON.stringify(browserParams)});
};

/* serve website */
app.get('/', function(req, res){
	var ua = req.headers['user-agent']; // mobile or desktop browser?
	var device = {};
	if (/mobile/i.test(ua))
		device.Mobile = true;
	if (/Android/.test(ua)){
		device.Android = true;
	}

	// generate new session id if user has none
	if (!req.my_session || !req.my_session.sid) {
		console.log("genIDs ... ");
		var sessionID = crypto.randomBytes(64).toString('hex');
		
		/* store session to db */
		var params = ''
		if (device.Android)
			params = mobileParams
		else
			params = browserParams
		params.sessionID = sessionID;
		db.setupSession(sessionID, JSON.stringify(params), config.SUCCESS_URL);

		// set session id in cookie
		req.my_session.sid = sessionID; 
	} 
	
	// render page
	renderPage(req, res, device);
});

/* TODO_API */

/* get all todos for user */
app.get('/todo/api', checkAuth, function(req, res){
	todo.find({ user: req.my_session.username }).lean().exec(function(err, entries){
		var result = {'todos': []};
		for(var i = 0; i < entries.length; i++) {
 			var entry = entries[i];
 			result.todos.push({'id': entry._id, 'text': encode(entry.text)});
		}
		res.json(result);
	});
});

/* save todo */
app.post('/todo/api', checkAuth, function(req, res){
	var make = new todo({ user: req.my_session.username,  text: req.text});
	make.save(function (err, make) {
		if (err)
			console.log("ERROR: "+err);
		res.send('ok');
	});
});

/* delete todo */
app.delete('/todo/api', checkAuth, function(req, res){
	todo.remove({ _id: req.query.id, user: req.my_session.username }, function(err) { //XXX: have to use query due to jQuery bug
		if (!err) {
//			console.log('deleted '+req.query.id);
		} else {
			console.log('ERROR: '+err);
		}
	});
	res.send('ok');
});

/* LOGIN API */

app.post('/user/loginDone', function(req, res){
	if (req.my_session) {
		console.log(req.body.username);
		console.log(req.body.key);
		db.getSessionKey(req.body.username, function(err, result) {
			db.dropSessionKey(req.body.username);
			if (result[0] && result[0].secret != null && result[0].secret == req.body.key) {
				console.log("browser login done ... "+JSON.stringify(result));
				req.my_session.username = result[0].username;
				res.redirect(DEFAULT_PATH);
			}
		});
	} else {
		// TODO: error handling
		res.redirect(DEFAULT_PATH);
	}
});

app.get('/user/api', function(req, res){
	var parsedUrl = url.parse(req.url, true); // true to get query as object
	var queryAsObject = parsedUrl.query;
		
	if (queryAsObject && queryAsObject.sessionID && req.my_session && req.my_session.sid) { // read server auth1 from database to check
		db.getSession(queryAsObject.sessionID, function(err, result) {
			if (result[0] && result[0].success != null) {
				if (queryAsObject.key && result[0].success == "1" && queryAsObject.key == result[0].a3 && queryAsObject.sessionID == req.my_session.sid) {
					req.my_session.username = result[0].username;
					// delete session from DB -> no one else can use it and we don't have so much waste in that DB
					db.dropSession(req.my_session.sid);
					var app = req.header('MobilePoWApp');
					res.redirect(DEFAULT_PATH); // TODO: send result[0].a2 back
				} else {
					res.redirect(DEFAULT_PATH+'user/loginerror');
					console.log("wrong username or password (or sth. else) !!! 1");
					/* TODO: make YOUR LOGIN FAILED popup */
					/* TODO: we have to remove the session from the DB at some point, even if something went wrong and the user never comes back! */
				}
			} else {
				res.redirect(DEFAULT_PATH+'user/loginerror');
				console.log("wrong username or password (or sth. else) !!! 2");
				/* TODO: we have to remove the session from the DB at some point, even if something went wrong and the user never comes back! */
			}
		});
	} else if(req.my_session.sid) { // browser login => just check if the success bit is set correctly
		db.getSession(req.my_session.sid, function(err, result) {
			console.log("browser login done ... "+JSON.stringify(result));
			if (result[0] && result[0].success != null && result[0].success == "1") {
				req.my_session.username = result[0].username;
				db.dropSession(req.my_session.sid);
				res.redirect(DEFAULT_PATH);
			}
		});
	} else {
		res.redirect(DEFAULT_PATH+'user/loginerror');
	}
});

app.get('/user/logout', checkAuth, function (req, res) {
	var app = req.header('MobilePoWApp');
	req.my_session.reset();
	if (app) {
		res.send('logged out');
	} else {
		res.redirect(DEFAULT_PATH);
	}
});

app.get('/user/loginerror', function (req, res) {
  req.my_session.reset();
  res.redirect(DEFAULT_PATH);
});

app.listen(8200);
console.log('Listening on port 8200 ...');
