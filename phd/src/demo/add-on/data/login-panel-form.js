
// get login form from login-panel.html
//var loginForm = document.getElementById("login-form");
//var loginSubmit = document.getElementById("login-submit");
document.getElementById("login-submit").addEventListener('click', function () {
	var form = document.forms['login-form'];
	var email = form.elements['email'].value;
	var pwd = form.elements['password'].value;
	
	// send entered data to addon-code
	addon.port.emit("user-login", [email, pwd]);
	
	// remove entered data
	form.reset();
});
