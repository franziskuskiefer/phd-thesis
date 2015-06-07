importScripts('jsbn.js', 'jsbn2.js', 'prng4.js', 'rng.js', 'ec.js', 'sec.js', 'util.js', 'pwdEncoding.js', 'pedersen.js', 'pwdHash.js', 'tSokeClient.js');

var state;

self.addEventListener("message", function(e) {
	var args = e.data.args;

	// initial request -> compute g^x
	if (args[0] == 0) {
		dump("computing g^x\n");

		var m = tSokeClient.firstMessage();
		
		if (m != -1)	 {
			state = m[1];
			postMessage({"M": "0", "X": m[0]});
		} else {
			postMessage({"M": "0", "X": m});
		}
	} else if (args[0] == 1) { // second request -> get authentication token a1
		args.shift();
		dump("computing RES\n");
		
		var client = new bprClient();
		var m = client.respond(state, args[0]);
		
		postMessage({"M": "1", "A2": m});
	}
}, false);

