importScripts('jsbn.js', 'jsbn2.js', 'prng4.js', 'rng.js', 'ec.js', 'sec.js', 'util.js', 'pwdEncoding.js', 'pedersen.js', 'pwdHash.js', 'bprClient.js');

var state;

self.addEventListener("message", function(e) {
	var args = e.data.args;

	// initial request -> compute COM
	if (args[0] == 0) {
		args.shift();
		dump("computing COM\n");

		var client = new bprClient();
		var m = client.commit(args);
		
		if (m != -1)	 {
			state = m[1];
			postMessage({"X": "0", "COM": m[0]});
		} else {
			postMessage({"X": "0", "COM": m});
		}
	} else if (args[0] == 1) { // second request -> get CH and compute RES
		args.shift();
		dump("computing RES\n");
		
		var client = new bprClient();
		var m = client.respond(state, args[0]);
		
		postMessage({"X": "1", "RES": m});
	}
}, false);

// w = new Worker('static/js/test.js')
// w.postMessage({ "args": [{"f": "lala"}, ["alice", "1", "1"]] })
