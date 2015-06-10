importScripts('jsbn.js', 'jsbn2.js', 'prng4.js', 'rng.js', 'ec.js', 'sec.js', 'util.js', 'pwdEncoding.js', 'pedersen.js', 'pwdHash.js', 'sjcl.js', 'tSokeClient.js');

var state;

self.addEventListener("message", function(e) {
try {
	var args = e.data.args;
dump("args: "+args+"\n");
	// initial request -> compute g^x
	if (args[0] == 0) {
		dump("computing g^x\n");

		var m = tSokeClient.firstMessage();
		
		if (m != -1)	 {
			state = m[1];
			state.username = args[2];
			state.pwd = args[3];
			postMessage({"M": "0", "X": m[0]});
		} else {
			postMessage({"M": "0", "X": m});
		}
	} else if (args[0] == 1) { // second request -> get authentication token a1
		args.shift();
		dump("computing authentication tokens\n");
		
		var m = tSokeClient.authenticationTokens(state, args[0], args[1]);
		state = m[1]
		postMessage({"M": "1", "a1": m[0]});
	} else if (args[0] == 2) { // last message -> check authentication token a2
	dump("a2(C): "+state.a2+"\n");
	dump("a2(S): "+args[1].a2+"\n");
		if (args[1].a2 == state.a2)
			postMessage({"done": 1, "secret": args[1].secret})
		else
			postMessage({"done": 0})
	}
} catch(err) {
	dump("EXCEPTION (tSokeClientWorker): "+err.message+"\n");
}
}, false);

