
// set focus
//document.getElementById("fuu").focus();
	
// get register form from panel.html
var registerForm = document.getElementById("register-form");
var registerSubmit = document.getElementById("register-submit");
registerSubmit.addEventListener('click', function () {
	var email = document.forms['register-form'].elements['email'].value;
	var pwd1 = document.forms['register-form'].elements['password'].value;
	var pwd2 = document.forms['register-form'].elements['confirm-password'].value;
	
	// send entered data to addon-code
	addon.port.emit("user-registered", [email, pwd1, pwd2]);
	
	// remove entered data
	document.forms['register-form'].reset();
});
