// implementation of the client side of the BPR protocol

// Copyright (c) 2015  Franziskus Kiefer
// All Rights Reserved.
// See "LICENSE" for details.

function bprClient(f) {

	// initialise curve and h
	// FIXME: make this global on the site (is used everywhere)
	this.curve = getSECCurveByName("secp192r1");
	this.q = this.curve.getN();
	this.g = this.curve.getG();
	this.h = util.secp192r1H;
	this.R = f.R;
	this.minimum = f.minimum;
	
//	console.log("g: 0x"+this.g.getX().toBigInteger().toString(16));

	// commitment phase:
	// * compute password hash on input of password pw (String)
	// * compute Pedersen commitments to all characters in pw
	// * compute product of character commitments
	// * compute shuffle of character commitments
	// ------
	// * compute commitment phase of SMP proofs
	// * compute commitment phase of ZKP for H2 and C contain the same pi
	// * compute commitment phase of shuffling proof
	// ------
	// output is (H1, H2, sP, sH, g^sP)
	this.commit = function(pw, params){
console.log(JSON.stringify(params));
		// generate randomness
		var rng = new SecureRandom();
		var sP = util.generateRandom(this.q);
		var sH = util.generateRandom(this.q);
	
		// encode pw to pi
		var encoding = new pwdEncoding();
		var pi = encoding.encodeString(pw);
		console.log("pi: "+pi);
			
		// hash pw to H = {'H1': H1, 'H2': H2, 'sP': sP, 'sH': sH, 'gp': gp}
		var H = new pwdHash().hash(pi); 
//		console.log("H1: "+util.point2string(H['H1']));
//		console.log("H2: "+util.point2string(H['H2']));
		
		// create local copy of R and RSets (character sets for R)
		var R = this.R;
		var RSets = [];
		for (var i = 0; i < R.length; ++i) {
			RSets.push(util.cSets[R[i]]);
		}

		// compute commitments and shuffled commitments
		var Cs = [], rs = [];
		var Cps = [], rps = [];
		var pis = [];
		var ks = [];
		var tss = [], sss = [], css = [];
		var com = new pedersen();
		
		for (var i = 0; i < pw.length; ++i) {
			console.log("i: "+i+" ("+pw[i]+")");
		
			// compute commitment
			var pi = encoding.encodeChar(pw[i]);
			var C = com.commit(pi);
			pis.push(pi);
			Cs.push(C.C);
			rs.push(C.r);
			
			// compute second commitment
			var C2 = com.recommit(C);
			Cps.push(C2.C);
			rps.push(C2.r);
			
			// choose shuffling index for C2
			do {
				r = new BigInteger(Math.ceil(Math.log(pw.length) / Math.log(2)), rng).intValue();
			} while (ks.indexOf(r) != -1 || r > pw.length-1);
			ks.push(r);
			
			// PROOF1: compute SMP for Cp in Rj or Sigma
			
			// first identify set omega to use
			var omega;
			var l;
			for (var j = 0; j < RSets.length; ++j) {
				var lt = 0;
				if ((lt = RSets[j].indexOf(pw[i])) != -1) {
					omega = RSets[j];
					l = lt;
					RSets.splice(j, 1);
					break;
				} else {
					omega = util.cSets.chars;
					l = util.cSets.chars.indexOf(pw[i]);
				}
			}
			
			// compute ...
			var ss = [], cs = [], ts = [];
			var k;
			for (var j = 0; j < omega.length; ++j) {
				if (j == l) {
					k = util.generateRandom(this.q);
					var t = this.g.multiply(pi).add(this.h.multiply(k));
					ts.push(t);
					ks.push(k);
				} else {
					var s = util.generateRandom(this.q);
					var c = util.generateRandom(this.q);
					ss.push(s);
					cs.push(c);
					
//					console.log(omega[j]+" - "+util.cEncodings['chars'][omega[j]]);	
					var pit = util.cEncodings['chars'][omega[j]];
					var piInv = pi.modInverse(this.q);
					var t = this.g.multiply(new BigInteger(""+pit)).add(this.h.multiply(s));
					t = t.add(C.C.add(this.g.multiply(piInv)).multiply(c));
					ts.push(t);
				}
			}
			
			tss.push(ts);
			sss.push(ss);
			css.push(cs);
		}
		
//		console.log(tss);
//		console.log(sss);
//		console.log(css);

		return [tss, sss, css];
	};


}
