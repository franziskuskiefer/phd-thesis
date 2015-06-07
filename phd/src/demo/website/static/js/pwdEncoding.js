// implementation of a secure password encoding from character strings to 
// integers

// Copyright (c) 2014  Franziskus Kiefer
// All Rights Reserved.
// See "LICENSE" for details.

function pwdEncoding() {

	var base = new BigInteger("100000", 10);

	// compute encoding (BigInteger) of input c (Char)
	this.encodeChar = function(c){
		return new BigInteger(""+(c.charCodeAt(0) - 32), 10);
	};
	
	// compute encoding (BigInteger) of input c (Char) depending on position
	this.encodeCharPosition = function(c, i){
		return base.pow(i).multiply(this.encodeChar(c));
	};

	// compute encoding (BigInteger) of input s (String)
	this.encodeString = function(s){

		var n = new BigInteger("0", 10);

		for (var i = 0; i < s.length; ++i) {
			var ni = base.pow(i).multiply(this.encodeChar(s[i]));
			n = n.add(ni);
		}

		return n;
	};
	


}
