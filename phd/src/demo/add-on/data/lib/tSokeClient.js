function tSokeClient() {}

tSokeClient.firstMessage() {

	var state = {};
	var mout;
	
	var curve = getSECCurveByName("secp192r1");
	var q = curve.getN();
	var p = curve.getCurve().getQ();
	var g = curve.getG();
	var h = util.secp192r1H;

	mout = "1";

	return [mout, state];

}
