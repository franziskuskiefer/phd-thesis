importScripts('jsbn.js', 'jsbn2.js', 'prng4.js', 'rng.js', 'ec.js', 'sec.js', 'util.js', 'pwdEncoding.js', 'pedersen.js', 'pwdHash.js', 'bprClient.js');

self.addEventListener("message", function(e) {
	var args = e.data.args;

	var client = new bprClient({"R": "ds", "minimum": 5});
	COM = client.commit("1a3", args);
	
	postMessage(COM);
}, false);

// w = new Worker('static/js/test.js')
