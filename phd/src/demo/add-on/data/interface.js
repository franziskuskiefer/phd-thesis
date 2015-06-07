
// check for registration ID on website and disable or enable button
if (document.getElementById("24920b44-3a8b-486b-a3f9-8f359bd1fbb2")) {
	console.log("this is a BPR supporting website -> display button");
	self.port.emit("bpr-interface-response", "show-button");
} else {
	self.port.emit("bpr-interface-response", "disable-button");
}

// handle communication with add-on
self.port.on("bpr-addon-message", handleMessage);

function handleMessage(message) {
//  alert(message);
//  self.port.emit("bpr-interface-response", "Response from content script");
}
