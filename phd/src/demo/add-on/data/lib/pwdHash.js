// implementation of a password hashing scheme using randomised Pedersen
// commitments

// Copyright (c) 2014  Franziskus Kiefer
// All Rights Reserved.
// See "LICENSE" for details.

function pwdHash() {

	// compute password hash on input of password pw (String or BigInteger)
	// output is (H1, H2, sP, sH, g^sP)
	this.hash = function(pw){

		// initialise curve and h
		var curve = getSECCurveByName("secp192r1");
		var q = curve.getN();
		var g = curve.getG();
		var h = util.secp192r1H;
	
		// generate randomness
		var rng = new SecureRandom();
		var q1 = q.subtract(BigInteger.ONE);
		var r = new BigInteger(q.bitLength(), rng);
		var sP = r.mod(q1).add(BigInteger.ONE);
		r = new BigInteger(q.bitLength(), rng);
		var sH = r.mod(q1).add(BigInteger.ONE);
	
		// encode password pw to integer pi if necessary
		var pi;
		if (typeof pw == "string") {
			var encoding = new pwdEncoding();
			pi = encoding.encodeString(pw);
		} else {
			pi = pw;
		}
		
		// g^sP
		var gp = g.multiply(sP)
		
		// H1 <- g^(sP*pi)
		var H1 = gp.multiply(pi)
		
		// H2 <- H1 * h^sH
		
		var H2 = h.multiply(sH);
		H2 = H1.add(H2);

		return {'H1': gp, 'H2': H2, 'sP': sP, 'sH': sH}; // , 'gp': gp
	};


}
