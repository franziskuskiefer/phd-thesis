function tSokeClient() {}

tSokeClient.firstMessage = function() {

	var state = {};
	var mout;
	
	var curve = getSECCurveByName("secp192r1");
	var q = curve.getN();
	var p = curve.getCurve().getQ();
	var g = curve.getG();
	var h = util.secp192r1H;
	
	var x = util.generateRandom(q);
	var X = g.multiply(x);
	
	mout = util.point2json(X);

	state.x = x;
	state.X = X;

	return [mout, state];

}

tSokeClient.authenticationTokens = function(state, args, certHash) {

	var curve = getSECCurveByName("secp192r1");
	var q = curve.getN();
	var p = curve.getCurve().getQ();
	var g = curve.getG();
	var h = util.secp192r1H;

	var Y = JSON.parse(args["Y"].replace(/'/g, "\""));
	var Yast = util.readHexPoint(Y["x"], Y["y"]);
	var salt = JSON.parse(args["salt"].replace(/'/g, "\""));
	var sH = new BigInteger(""+salt["sH"], 16);
	var H1 = util.readHexPoint(salt["H1"][0], salt["H1"][1]);

	// compute hash from pwd, sH, and H1
	var pwd = state.pwd;
	var H2 = new pwdHash().fixedHash(pwd, H1, sH);
	H2x = H2.getX().toBigInteger(); // we use only X for hash 
	
	var tmp = h.multiply(H2x.mod(q)).negate();
	var Y = Yast.add(tmp);
	var Z = Y.multiply(state.x);
	
	var hashInput = state.username;
	hashInput += util.point2Hashstring(H2);
	hashInput += certHash;
	hashInput += util.point2Hashstring(state.X);
	hashInput += util.point2Hashstring(Yast);
	hashInput += util.point2Hashstring(Z);
	var K = sjcl.hash.sha256.hash(hashInput);
	K = sjcl.codec.hex.fromBits(K);
	
	var a1 = sjcl.hash.sha256.hash(K + "auth1");
	a1 = sjcl.codec.hex.fromBits(a1);
	
	var a2 = sjcl.hash.sha256.hash(K + "auth2");
	a2 = sjcl.codec.hex.fromBits(a2);
	state.a2 = a2;
	
	return [a1, state];
}
