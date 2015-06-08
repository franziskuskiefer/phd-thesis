// implementation of a password hashing scheme using randomised Pedersen
// commitments

// Copyright (c) 2014  Franziskus Kiefer
// All Rights Reserved.
// See "LICENSE" for details.

function pwdHash() {

	this.fixedHash = function(pw, gp, sH) {
	
		// initialise curve and h
		var curve = getSECCurveByName("secp192r1");
		var q = curve.getN();
		var g = curve.getG();
		var h = util.secp192r1H;
		
		// encode password pw to integer pi
		var encoding = new pwdEncoding();
		var pi = encoding.encodeString(pw);
		
		// H1 <- g^(sP*pi)
		var H1 = gp.multiply(pi)
		
		// H2 <- H1 * h^sH
		var H2 = h.multiply(sH);
		H2 = H1.add(H2);

		return H2;
	}

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

dump("H1: "+util.point2Hashstring(gp)+"\n");
dump("H2: "+util.point2Hashstring(H2)+"\n");
dump("sH: "+sH+"\n");

		return {'H1': gp, 'H2': H2, 'sP': sP, 'sH': sH}; // , 'gp': gp
	};


}
