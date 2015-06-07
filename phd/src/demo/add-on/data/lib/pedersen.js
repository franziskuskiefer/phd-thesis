// implementation of Pedersen commitment scheme

// Copyright (c) 2014  Franziskus Kiefer
// All Rights Reserved.
// See "LICENSE" for details.

function pedersen() {

	// initialise curve and h
	this.curve = getSECCurveByName("secp192r1");
	this.q = this.curve.getN();
	this.g = this.curve.getG();
	this.h = util.secp192r1H;

	// compute Pedersen commitment on input m (BigInteger)
	// output is (commitment, randomness)
	this.commit = function(m){
	
		// generate randomness
		var rng = new SecureRandom();
		var q1 = this.q.subtract(BigInteger.ONE);
		var r = new BigInteger(this.q.bitLength(), rng);
		r = r.mod(q1).add(BigInteger.ONE);
	
		// C <- g^m * h^r
		var hr = this.h.multiply(r);
		var C = this.g.multiply(m).add(hr);

		return {'C': C, 'r': r};
	};
	
	// compute a new commitment to an already existing one
	// output is (commitment, randomness)
	// RETURNS ONLY NEW RANDOMNESS
	this.recommit = function(C) {
		
		// generate randomness
		var rng = new SecureRandom();
		var q1 = this.q.subtract(BigInteger.ONE);
		var r = new BigInteger(this.q.bitLength(), rng);
		r = r.mod(q1).add(BigInteger.ONE);
		
		// compute new commitment C2 <- C * h^r
		var hr = this.h.multiply(r);
		var C2 = C.C.add(hr);
		
		return {'C': C2, 'r': r}
	}


}
