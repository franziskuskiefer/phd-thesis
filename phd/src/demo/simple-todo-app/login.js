const mustache = require('mustache');
const fs = require('fs');
const crypto = require('crypto');

/* get config */
const config = require("./config");

var loginObject = function(){
	
	this.params = {
		sessionID: '',
		authURL: config.AUTH_URL,
		url: config.URL,
		branding: config.IMAGE_URL
	};
	
	// stuff for extension
	if (false) {
		this.params = {
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
	}
	
	this.template = fs.readFileSync('./login.html')+'';
}

loginObject.prototype = new function(){
	
	/* generate new session ids */
	this.genIDs = function(db) {
		this.params.sessionID = crypto.randomBytes(64).toString('hex');
		console.log("genIDs ... ");
		
		/* store session to db */
		db.setupSession(this.params.sessionID, JSON.stringify(this.params), config.SUCCESS_URL);
	};
	
	this.render = function(ua, app, sid) {
	
		/* XXX: set correct sid ---  not nice here, sholud refactor this! */
		this.params.sessionID = sid;
		
		return mustache.to_html(this.template, {params: JSON.stringify(this.params), TTPSOURCE: this.params.TTPSOURCE});

//		/* check for mobile device */
//		var device = {};
//		if (/mobile/i.test(ua))
//			device.Mobile = true;
//		if (/Android/.test(ua))
//		//	device.Android = /Android ([0-9\.]+)[\);]/.exec(ua)[1];
//			device.Android = true;
//		
//		
//		if (device.Android) { // maybe we want only 4.x ?
//			// TODO: make the scheme something like webcryptography.tk...
//			// TODO: build url nicer
////			var url = "pow://?"+encodeURIComponent(JSON.stringify(this.params));
////			return url;
//			return mustache.to_html(this.template, {params: JSON.stringify(this.params), TTPSOURCE: this.params.TTPSOURCE});
//		} else /* desktop browser */
//			return mustache.to_html(this.template, {params: JSON.stringify(this.params), TTPSOURCE: this.params.TTPSOURCE});
	};
		
}

module.exports = new loginObject();
