// implementation of the client side of the BPR protocol

// Copyright (c) 2015  Franziskus Kiefer
// All Rights Reserved.
// See "LICENSE" for details.

var base = new BigInteger("100000");

var ZERO = new BigInteger("0");
var ONE = new BigInteger("1");
var TWO = new BigInteger("2");
var THREE = new BigInteger("3");

function bprClient() {

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
	this.commit = function(params){
		try {
	
		curve = getSECCurveByName("secp192r1");
		q = curve.getN();
		p = curve.getCurve().getQ();
		g = curve.getG();
		h = util.secp192r1H;

		// read params
		var f = params[0].f;
		var R = params[0].regex;
		var Rf = R.split("")
		var minimum = params[0].minlength;
		var user = params[1][0];
		var pw = params[1][1];
		var pwd2 = params[1][2];
		
		// abort if passwords don't match
		if (pw !== pwd2 || pw == '' || user == '')
			return -1;
		
		dump("user: "+user+"\n");
		dump("pw: "+pw+"\n");
		dump("policy: "+R+", "+minimum+"\n");

		// generate randomness
		var rng = new SecureRandom();
		var sP = util.generateRandom(q);
		var sH = util.generateRandom(q);
	
		// encode pw to pi
		var encoding = new pwdEncoding();
		var pif = encoding.encodeString(pw);
		dump("pi: "+pif+"\n");
			
		// hash pw to H = {'H1': H1, 'H2': H2, 'sP': sP, 'sH': sH, 'gp': gp}
		var H = new pwdHash().hash(pif); 
		
		// create RSets (character sets for R)
		var RSets = [];
		for (var i = 0; i < R.length; ++i) {
			RSets.push(util.cSets[R[i]]);
		}

		// compute commitments and shuffled commitments
		var Cs = [], rs = [];
		var Cps = [], rps = [];
		var pis = [];
		var ks = [], krhos = [];
		var tss = [], sss = [], css = [];
		var com = new pedersen();
		var omegas = [], omegaSs = [];
		var ls = [];
		var rSum = new BigInteger("0");
		
		for (var i = 0; i < pw.length; ++i) {
		
			// compute commitment
			var pi = encoding.encodeChar(pw[i]);
			var C = com.commit(pi);
			pis.push(pi);
			Cs.push(util.point2json(C.C));
			rs.push(C.r);
			rSum = rSum.add(base.pow(i).multiply(C.r));
			
			// compute second commitment
			var C2 = com.recommit(C);
			Cps.push(util.point2json(C2.C));
			rps.push(C2.r);
			
			// choose shuffling index for C2
			var r = -1;
			do {
//				r = new BigInteger(Math.ceil(Math.log(pw.length) / Math.log(2)), rng).intValue();
				r = r+1;
			} while (ks.indexOf(r) != -1 || r > pw.length-1);
			ks.push(r);
			
		/********************************** 
		************	PoM *****************
		***********************************/
		// compute SMP for Cp in Rj or Sigma
			
			// first identify set omega to use
			var omega, omegaS;
			var l;
			var found = false;
			for (var j = 0; j < RSets.length; ++j) {
				var lt = 0;
				if ((lt = RSets[j].indexOf(pw[i])) != -1) {
					omega = RSets[j];
					omegaS = Rf[j]; //util.getSymbolesForSets(omega)
					l = lt;
					RSets.splice(j, 1);
					Rf.splice(j, 1);
					found = true;
					break;
				}
			}
			if (!found) {
				omega = util.cSets.chars;
				omegaS = "*";
				l = util.cSets.chars.indexOf(pw[i]);
			}
			omegas.push(omega);
			omegaSs.push(omegaS);
			ls.push(l)
			
			// compute PoM
			var ss = [], cs = [], ts = [];
			for (var j = 0; j < omega.length; ++j) {
				if (j == l) {
					var krho = util.generateRandom(q);
					var t = g.multiply(pi).add(h.multiply(krho));
					ts.push(util.point2json(t));
					krhos.push(krho);
				} else {
					var s = util.generateRandom(q);
					var c = util.generateRandom(q);
					ss.push(s);
					cs.push(c);
					
					var pit = new BigInteger(""+util.cEncodings['chars'][omega[j]]);
					var t = g.multiply(pit);
					t = t.add(h.multiply(s));
					var gpin = g.multiply(pit).negate();
					gpin = C2.C.add(gpin).multiply(c);
					t = t.add(gpin);
					ts.push(util.point2json(t));
				}
			}
			
			tss.push(ts);
			sss.push(ss);
			css.push(cs);
		}
		
		// shuffle omega, Cps, rps tss, sss, css according to ks
		dump("ks: "+ks+"\n");
		var omegaSsTMP = [], CpsTMP = [], rpsTMP = [], tssTMP = [], sssTMP = [], cssTMP = [], krhosTMP = [], lsTMP = [], omegasTMP = [];
		for (var k in ks) {
			omegaSsTMP.push(omegaSs[ks[k]]);
			omegasTMP.push(omegas[ks[k]]);
			CpsTMP.push(Cps[ks[k]]);
			rpsTMP.push(rps[ks[k]]);
			tssTMP.push(tss[ks[k]]);
			sssTMP.push(sss[ks[k]]);
			cssTMP.push(css[ks[k]]);
			krhosTMP.push(krhos[ks[k]]);
			lsTMP.push(ls[ks[k]]);
		}
		omegaSs = omegaSsTMP;
		omegas = omegasTMP;
		Cps = CpsTMP;
		rps = rpsTMP;
		tss = tssTMP;
		sss = sssTMP;
		css = cssTMP;
		krhos = krhosTMP;
		ls = lsTMP;

		/********************************** 
		************	PoE *****************
		***********************************/
		var ksp = util.generateRandom(q);
		var kpi = util.generateRandom(q);
		var krast = util.generateRandom(q);
		
		var tsp = g.multiply(ksp);
		var th = H['H1'].multiply(kpi);
		var tcast = g.multiply(kpi).add(h.multiply(krast));
		
		/********************************** 
		************	PoS *****************
		***********************************/
		
		// choose randome A'
		var Ap = [];
		for (var i = -4; i < pw.length+1; ++i) {
				Ap.push(util.generateRandom(q));
		}

		// compute matrix A
		var A = [];
		for (var i = -4; i < pw.length+1; ++i) { // choose random values, set re-randomiser and set shuffle matrix, fill the rest with 0
				var At = [];
				for (var j = 0; j < pw.length+1; ++j) { 
						if (j == 0 || i == -1) {
								At.push(util.generateRandom(q));
						} else if (i == 0) {
								At.push(rps[j-1]);
						} else if (i > 0 && i-1 == ks[j-1]) {
								At.push(ONE);
						} else {
								At.push(ZERO);
						}
				}
				A.push(At);
		}
		
		for (var j = 1; j < pw.length+1; ++j){ //replace 0s with the correct values
				for (var v = 1; v < pw.length+1; ++v){
						A[0][j] = A[0][j].add(TWO.multiply(A[v+4][0]).multiply(A[v+4][j])).mod(q);
						A[1][j] = A[1][j].add(THREE.multiply(A[v+4][0]).multiply(A[v+4][j])).mod(q);
						A[2][j] = A[2][j].add(THREE.multiply((A[v+4][0]).modPow(TWO, q)).multiply(A[v+4][j])).mod(q);
				}
		}

		// get f-points
		var fv = [];
		for (var j = -4; j < pw.length+1; ++j) {
				fv.push(util.readHexPoint(f["f"+j]["x"], f["f"+j]["y"]));
		}

		// commit to A
		var fpv = [];
		var fmf = fv[0];
		for (var v = 0; v < pw.length+1; ++v){
				var fj = fmf.multiply(A[0][v]);
				for (var j = -3; j < pw.length+1; ++j){
						fj = fj.add(fv[j+4].multiply(A[j+4][v]));
				}
				fpv.push(util.point2json(fj));
		}
		
		var ftil = fv[0].multiply(Ap[0]);
		for (var j = -3; j < pw.length+1; ++j) {
				ftil = ftil.add(fv[j+4].multiply(Ap[j+4]));
		}
		
		var piSum = pis[0].multiply(A[5][0]).mod(q);
		var rSumSC = A[4][0].add(rs[0].multiply(A[5][0])).mod(q);
		for (var j = 1; j < pw.length; ++j){
				piSum = piSum.add(pis[j].multiply(A[j+5][0])).mod(q);
				rSumSC = rSumSC.add(rs[j].multiply(A[j+5][0])).mod(q);
		}
		var Cp0 = g.multiply(piSum).add(h.multiply(rSumSC));
		
		var w = ZERO.subtract(A[2][0]).subtract(Ap[1]).mod(q);
		var wtil = A[0][0].negate();
		for (var j = 0; j < pw.length; ++j){
				var Aj0 = A[j+5][0];
				var tmp = Aj0.modPow(TWO, q);
				wtil = wtil.add(tmp).mod(q);
				tmp = tmp.multiply(Aj0).mod(q)
				w = w.add(tmp).mod(q);
		}

		// build messages
		var COM_PoM = {"t": tss, "omega": omegaSs};
		var COM_PoE = {"tsp": util.point2json(tsp), "th": util.point2json(th), "tcast": util.point2json(tcast)};
		var COM_PoS = {"Cp0": util.point2json(Cp0), "ftil": util.point2json(ftil), "fp": fpv, "w": w.toString(16), "wtil": wtil.toString(16)}
		var verifier = {"sH": H['sH'].toString(16), "H1": util.point2json(H['H1']), "H2": util.point2json(H['H2'])};

		var state = {"H": H, "css": css, "sss": sss, "krhos": krhos, "ls": ls, "rs": rs, "rps": rps, "omegas": omegas, "R": omegaSs, "ks": ks, "pw": pw, "ksp": ksp, "kpi": kpi, "krast": krast, "pi": pif, "rSum": rSum, "A": A, "Ap": Ap, "w": w, "wtil": wtil, "Cp0": Cp0};
		
		// output message to server
		var mout = {"C": Cs, "Cp": Cps, "v": verifier, "COM_PoM": COM_PoM, "COM_PoE": COM_PoE, "COM_PoS": COM_PoS};

				}
		catch(err) {
				dump("EXCEPTION (commit): "+err.message+"\n");
		}

		return [mout, state];
	};


	// we need: (PoM) Cps.r, Cs.r, (ks), omegas, css, sss, ls, CH_PoM
	this.respond = function(state, CH) {
		
		try {
		
		curve = getSECCurveByName("secp192r1");
		q = curve.getN();
		p = curve.getCurve().getQ();
		g = curve.getG();
		h = util.secp192r1H;

		// read state
		var H = state.H;
		var css = state.css;
		var sss = state.sss;
		var krhos = state.krhos;
		var omegas = state.omegas;
		var Cs = state.Cs;
		var Cps = state.Cps;
		var rs = state.rs;
		var rps = state.rps;
		var ks = state.ks;
		var ls = state.ls;
		
		/********************************** 
		************	PoM *****************
		***********************************/
		var challenge = new BigInteger(""+CH['CH_PoM']);
		for (i in omegas) {
				var cl = challenge;
				var cs = css[i];
				for (var j = 0; j < omegas[i].length-1; ++j) {
						cl = cl.xor(cs[j]);
				}
				var r = rs[ks[i]].add(rps[i]); //rs[ks[i]].add(rps[i])
				var hr = h.multiply(r);
				var encoding = new pwdEncoding();
				var m = encoding.encodeChar(state.pw[ks[i]])
				var C = g.multiply(m).add(hr);
				var sl = krhos[i].subtract(cl.multiply((r))).mod(q);
				css[i].splice(ls[i], 0, cl);
				sss[i].splice(ls[i], 0, sl);
		}
		
		// sss and css have to be converted to strings
		var sssTMP = [], cssTMP = [];
		for (i in sss) {
				var ssTMP = [], csTMP = [];
				for (j in sss[i]) {
						ssTMP.push(sss[i][j].toString(16))
						csTMP.push(css[i][j].toString(16))
				}
				sssTMP.push(ssTMP);
				cssTMP.push(csTMP);
		}
		sss = sssTMP;
		css = cssTMP;
		
		
		/********************************** 
		************	PoE *****************
		***********************************/
		challenge = new BigInteger(""+CH['CH_PoE']);
		
		var ssp = state.ksp.subtract(challenge.multiply(H["sP"])).mod(q);
		var spi = state.kpi.subtract(challenge.multiply(state.pi)).mod(q);
		var srast = state.krast.subtract(challenge.multiply(state.rSum)).mod(q);
		
		/********************************** 
		************	PoS *****************
		***********************************/
		var A = state.A, Ap = state.Ap;
		var challenges = CH['CH_PoS'];
		challenges.splice(0, 0, "1"); // insert 1 for c_0
		
		var s = [], sp = [];
		for (var v = -4; v < state.pw.length+1; ++v) {
				var sv = A[v+4][0];
				var svp = Ap[v+4];
				for (var j = 1; j < state.pw.length+1; ++j) {
						var ch = new BigInteger(challenges[j]).mod(q);
						sv = sv.add(A[v+4][j].multiply(ch.modPow(ONE, q)).mod(q)).mod(q);
						svp = svp.add(A[v+4][j].multiply(ch.modPow(TWO, q)).mod(q)).mod(q);
				}
				s.push(sv.mod(q).toString(16));
				sp.push(svp.mod(q).toString(16));
		}
		
		// build RES message and return it
		var RES_PoM = {"s": sss, "c": css};
		var RES_PoE = {"ssp": ssp.toString(16), "spi": spi.toString(16), "srast": srast.toString(16)}
		var RES_PoS = {"s": s, "sp": sp}
		var mout = {"RES_PoM": RES_PoM, "RES_PoE": RES_PoE, "RES_PoS": RES_PoS};
		
		dump("done with BPR, returning last message ...\n");
		
		return mout;
		
						}
		catch(err) {
				dump("EXCEPTION (respond): "+err.message+"\n");
		}
	
	};

}
