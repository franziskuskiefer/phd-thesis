
var config = function(){

	this.POW_ID = "POW-fe748ad9-37f9-4b56-80a8-5c73b73e3e88";	
	this.SESSION_TRANS = "msgPOWServerHello";

	// Configure the login process as you wish
	this.MAX_NUM_PWD = "3";
	this.FORGOT_URL = "http://www.example.net/forgotURL";
	this.SITE_NAME = "Test POW site";
	this.DESCRIPTION = "Please enter your username and password.";
	this.IMAGE_URL = "https://www.franziskuskiefer.de/pow/demo/images/list-bullets-white.png";
	this.LOGIN_NAME_LABEL = "Login name";
	this.LOGIN_PASSWORD_LABEL = "Password";
	this.SUCCESS_URL_PATH = '?success=1';
	this.AUTH_URL = "https://www.franziskuskiefer.de/pow/mobile/index.php";
//	this.RE_AUTH_URL = "https://www.franziskuskiefer.de/pow/demo/login/sake/index.php";
	this.SUCCESS_URL = "https://www.franziskuskiefer.de/pow/demo/user/api";
	this.ERROR_URL = "https://www.franziskuskiefer.de/pow/user/loginerror";
//	this.TTP = "https://www.crypto.cf";
//	this.TTP_SOURCE = "https://www.crypto.cf/ttp/login.html";
	this.URL = "franziskuskiefer.de/pow/demo/";

	// your SQL settings
	this.DB_HOST = '127.0.0.1';
	this.DB_USERNAME = 'root';
	this.DB_PASSWORD = 'root';
	this.DB_DATABASE = 'pow';
}

config.prototype = new function(){
	
	this.fuu = function(i) {
		console.log("fuu: "+i);
	};
		
}

module.exports = new config();
