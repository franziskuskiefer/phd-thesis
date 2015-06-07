
var mysql = require('mysql');

// server includes
var config = require("./config");

var dbObject = function(){
	
	/* db config */
	this.db_config = {
	  	host     : config.DB_HOST,
	  	user     : config.DB_USERNAME,
	  	password : config.DB_PASSWORD,
	  	database : config.DB_DATABASE
	};
	
	/* database connection */
	this.connection = mysql.createConnection(this.db_config);
	
}

dbObject.prototype = new function(){
	
	this.connect = function() {
		this.handleDisconnect();
	};
	
	this.setupSession = function(sessionID, conf, successURL) {
		var queryString = "INSERT INTO sessions (sessionID, msgPOWServerHello, successURL) VALUES ('" + sessionID + "', '" + conf + "', '" + successURL + "')";
		var query = this.connection.query(queryString, function(err, result) {
			if (!result || result.message != "") {
				console.log("Something went wrong while inserting session to DB -> nothing will work from now on !!!");
				console.log("Error: "+JSON.stringify(err));
			}
		});
	};
	
	this.getSession = function(sessionID, callback) {
		this.connection.query("SELECT a1,a2,a3,username,success FROM sessions WHERE sessionID='"+sessionID+"'", function(err, result){callback(err, result);});
	};
	
	this.dropSession = function(sessionID) {
		this.connection.query("DELETE FROM sessions WHERE sessionID='"+sessionID+"'", function(err, result){ 
				if (err)
					console.log("Error while deleting session! "+JSON.stringify(err));
			});
	};
	
	this.handleDisconnect = function() {
	  this.connection = mysql.createConnection(this.db_config); // Recreate the connection

	  this.connection.connect(function(err) {              // The server is either down
		if(err) {                                     // or restarting (takes a while sometimes).
		  console.log('error when connecting to db:', err);
		  setTimeout(handleDisconnect, 2000); // We introduce a delay before attempting to reconnect,
		}                                     // to avoid a hot loop, and to allow our node script to
	  });                                     // process asynchronous requests in the meantime.
		                                      // If you're also serving http, display a 503 error.
	  var parent = this;
	  this.connection.on('error', function(err) {
		console.log('db error', err);
		if(err.code === 'PROTOCOL_CONNECTION_LOST') { // Connection to the MySQL server is usually
		  parent.handleDisconnect();                  // lost due to either server restart, or a
		} else {                                      // connnection idle timeout (the wait_timeout
		  throw err;                                  // server variable configures this)
		}
	  });
	}
		
}

module.exports = new dbObject();












