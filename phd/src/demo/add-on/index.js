var self = require('sdk/self');
var buttons = require('sdk/ui/button/action');
var {ToggleButton} = require('sdk/ui/button/toggle');
var tabs = require("sdk/tabs");
var tab_utils = require("sdk/tabs/utils");
var windows = require("sdk/windows").browserWindows;
var {viewFor} = require("sdk/view/core");
var panels = require("sdk/panel");
var {ChromeWorker} = require("chrome");
var Request = require("sdk/request").Request;
var urls = require("sdk/url");
let { Cc, Ci } = require('chrome');

var serverURL = '';
var postURL = '';
var finalURL = '';
var params = '';
var registerForm = ''; // [user, pwd1, pwd2]
var ADD_ON_WEBSITE_UUID = "24920b44-3a8b-486b-a3f9-8f359bd1fbb2";
var ADD_ON_WEBSITE_UUID_APP = "7b0a1359-9328-4a6c-a204-0d4a6649a0a2";

// bprClient worker messages
var w;
var COM, RES;
var browser;
var certHash;

// UI elements

var loginPanel = panels.Panel({
	focus: true,
  contentURL: "./login-panel.html",
  onHide: handleHide
});

var registerPanel = panels.Panel({
	focus: true,
  contentURL: "./panel.html",
  onHide: handleHide
});

var panel;

var button = ToggleButton({
				id: "register-button",
				label: "Register",
				icon: {
					"16": "./login-icon-16.png",
					"32": "./login-icon-32.png",
					"64": "./login-icon-64.png"
				},
				onChange: handleChange,
				disabled: true
			});

function checkTLS(browser, scheme){
	if (scheme != "https:") return;
	var ui = browser.securityUI;
	if (ui)
		var status = ui.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
	if (status)
		certHash = status.serverCert.sha1Fingerprint.replace(new RegExp(":","gm"),"");
}

// handle tabs (enable/disable the button)
tabs.on('ready', function(tab) {
  // get the XUL tab that corresponds to this high-level tab
  var lowLevelTab = viewFor(tab);
  // now we can, for example, access the tab's content directly
  var browser = tab_utils.getBrowserForTab(lowLevelTab);
  var surl = urls.URL(tabs.activeTab.url);
	serverURL = surl.protocol+"//"+surl.host;
	if (surl.port)
		serverURL += ":"+surl.port
	checkTLS(browser, tab.url.split('/')[0]);
	console.log("certHash: "+certHash);
  if (browser.contentDocument && browser.contentDocument.body && browser.contentDocument.getElementById(ADD_ON_WEBSITE_UUID) && certHash) {
 		enableForThisTab(registerPanel);
 		panel = registerPanel;
  } else if (browser.contentDocument && browser.contentDocument.body && browser.contentDocument.getElementById(ADD_ON_WEBSITE_UUID_APP) && certHash) {
 		enableForThisTab(loginPanel);
 		panel = loginPanel;
  } else {
  	disableForThisTab();
  }
//	  console.log(browser.contentDocument.getElementById('24920b44-3a8b-486b-a3f9-8f359bd1fbb2')); //body.innerHTML
});

function enableForThisTab(aPanel) {
  button.state("tab", {
    disabled: false
  });
  console.log("url: "+serverURL);
//  // also show button menu
//	button.state('window', {checked: true});
//	aPanel.show({ // seems like a bug that I have to do this manually as well ...
//	  position: button
//	});
}

function disableForThisTab(state) {
  button.state("tab", {
    disabled: true
  });
}

// the magic starts here ! --- get data from registration form and start BPR
registerPanel.port.on("user-registered", function (form) {
	registerForm = form;

  var browser = tab_utils.getBrowserForTab(viewFor(tabs.activeTab));
  w = new ChromeWorker(self.data.url('lib/bprClientWorker.js')) // not sure why we need the self.data.url bit here ...
 	params = browser.contentDocument.getElementById(ADD_ON_WEBSITE_UUID).textContent.trim();
	params = JSON.parse(params);
	postURL = params.postURL;
	finalURL = params.finalURL;
	
	w.onmessage = handleBprClient;
	
	console.log("starting bprClient worker ...");
	w.postMessage({ "args": [0, params, form] });
	
	// hide password popup and show loading page
  registerPanel.hide();
  loadingWindow.show({
  	focus: false
  });
});

function handleBprClient(m) {
	
	// handle first result from bprClient (COM)
	if (m.isTrusted && m.data.X == "0") {
		COM = m.data.COM;
		console.log(JSON.stringify(COM).length);
		
		if (COM == "-1") { // XXX: error handling
			console.log("Sorry, your passwords don't match!");
			alertWindow.show();
			return;
		}
		
		// add username to first message
		console.log(registerForm);
		COM.name = registerForm[0];
		COM.X = "COM";

		// send out COM to server		
		var COMrequest = Request({
			url: serverURL+postURL,
			contentType: "application/json",
			content: JSON.stringify(COM),
			onComplete: getChallenges
		});
		COMrequest.post();
	} if (m.isTrusted && m.data.X == "1") {
		RES = m.data.RES;
		
		if (RES == "-1") { // XXX: error handling
			console.log("Sorry, something went wrong ...");
			alertWindow.show();
			return;
		}
		
		RES.X = "RES";
		
		// send out RES to server		
		var RESrequest = Request({
			url: serverURL+postURL,
			contentType: "application/json",
			content: JSON.stringify(RES),
			onComplete: finalise
		});
		RESrequest.post();
		
	}
}

// receive challenges from bprServer and call bprClient to get final message
function getChallenges(response)  {
	var result = response.json;
	w.postMessage({ "args": [1, result.CH] });
//	console.log(result.CH);
}

function handleChange(state) {
  if (state.checked) {
    panel.show({
    	focus: true,
      position: button
    });
  }
}

function finalise(response) {
	// TODO: do UX stuff to finalise this
//	var result = response.json;
	console.log("done, hope we're good ...\n"+JSON.stringify(response.json));
	loadingWindow.hide();
	tabs.activeTab.url = response.json.goto;
}


// the other magic starts here ! --- get data from login form and start PACCE with SOKE
loginPanel.port.on("user-login", function (form) {
	
	loginForm = form;

  var browser = tab_utils.getBrowserForTab(viewFor(tabs.activeTab));
  w = new ChromeWorker(self.data.url('lib/tSokeClientWorker.js'));
 	params = browser.contentDocument.getElementById(ADD_ON_WEBSITE_UUID_APP).textContent.trim();
	params = JSON.parse(params);
	postURL = params.postURL;
	finalURL = params.finalURL;
	
	w.onmessage = handleTSokeClient;
	
	console.log("starting tSokeClient worker ...");
	console.log("params: "+JSON.stringify(params));
	console.log("form: "+form);
	var args = [0, params, form[0], form[1]];
	w.postMessage({ "args": args });
	
	// hide password popup and show loading page
  panel.hide();
  loadingWindow.show({
  	focus: false
  });
});


function handleTSokeClient(m) {
	
	// handle first result from tSokeClient (X)
	if (m.isTrusted && m.data.M == "0") {
		var X = m.data.X;
		
		if (X == "-1") { // XXX: error handling
			console.log("Sorry, your there was an error in tSOKE!");
			alertWindow.show();
			return;
		}
		
		var mout = {"X": X};
		mout.M = "X";
		mout.name = loginForm[0];
		console.log("Sending out "+JSON.stringify(mout));
		console.log("Sending to "+serverURL+postURL);
		
		// send out X to server		
		var Xrequest = Request({
			url: serverURL+postURL,
			contentType: "application/json",
			content: JSON.stringify(mout),
			onComplete: getServerMsg
		});
		Xrequest.post();
	} else if (m.isTrusted && m.data.M == "1") {
		var a1 = m.data.a1;
		
		if (a1 == "-1") { // XXX: error handling
			console.log("Sorry, your there was an error in tSOKE!");
			alertWindow.show();
			return;
		}
		
		var mout = {"a1": a1};
		mout.M = "a1";
		console.log("Sending out "+JSON.stringify(mout));
		console.log("Sending to "+serverURL+postURL);
		
		// send out X to server		
		var Xrequest = Request({
			url: serverURL+postURL,
			contentType: "application/json",
			content: JSON.stringify(mout),
			onComplete: finishTSoke
		});
		Xrequest.post();
	} else if (m.isTrusted && m.data.done) {
		var result = m.data.done;
		if (result) {
			console.log("done with tSoke, going to app ...");
			loadingWindow.hide();
			tabs.activeTab.url = serverURL+finalURL;
		} else {
			// TODO: ERROR HANDLING
		}
	}
	
}


// receive Y,H1,sH from tSokeServer and call tSokeClient to get auh1
function getServerMsg(response) {
	var result = response.json;
	w.postMessage({ "args": [1, result, certHash] });
}

function finishTSoke(response) {
	var result = response.json;
	w.postMessage({ "args": [2, result] });
}


// UI STUFF
var alertWindow = require("sdk/panel").Panel({
  contentURL: self.data.url("alert.html")
});

alertWindow.on("show", function() {
  alertWindow.port.emit("show");
});

var loadingWindow = require("sdk/panel").Panel({ //XXX: make this 100% and not escapeable
	width: 200,
	height: 200,
	focus: false,
  contentURL: self.data.url("loading.html")
});

//loadingWindow.on("show", function() {
//  loadingWindow.port.emit("show");
//});

function handleHide() {
  button.state('window', {checked: false});
}

disableForThisTab();






