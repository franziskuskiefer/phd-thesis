function util() {

}

util.secp192r1H = getSECCurveByName("secp192r1").getCurve().decodePointHex("0487656f2b5fee3821b53b00d78bd61a8d407ce4393ea48906b52e5b337ca8f667935a63d02d6f6fec689c7f18a640a8a5");
//"048da36f68628a18107650b306f22b41448cb60fe5712dd57a1f64a649852124528a09455de6aad151b4c0a9a8c2e8269c"

Object.extend = function(destination, source) {
    for (var property in source) {
        if (source.hasOwnProperty(property)) {
            destination[property] = source[property];
        }
    }
    return destination;
};
	
// character sets
util.cSets = {
		d: ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
		l: ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"],
		u: ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "L", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"],
		s: ['!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~'],
};
util.cSets['chars'] = util.cSets.d.concat(util.cSets.l).concat(util.cSets.u).concat(util.cSets.s);
	
util.cEncodings = {
		d: {'0': 16, '1': 17, '2': 18, '3': 19, '4': 20, '5': 21, '6': 22, '7': 23, '8': 24, '9': 25},
		u: {'A': 33, 'B': 34, 'C': 35, 'D': 36, 'E': 37, 'F': 38, 'G': 39, 'H': 40, 'I': 41, 'J': 42, 'K': 43, 'L': 44, 'M': 45, 'N': 46, 'O': 47, 'P': 48, 'Q': 49, 'R': 50, 'S': 51, 'T': 52, 'U': 53, 'V': 54, 'W': 55, 'X': 56, 'Y': 57, 'Z': 58},
		l: {'a': 65, 'b': 66, 'c': 67, 'd': 68, 'e': 69, 'f': 70, 'g': 71, 'h': 72, 'i': 73, 'j': 74, 'k': 75, 'l': 76, 'm': 77, 'n': 78, 'o': 79, 'p': 80, 'q': 81, 'r': 82, 's': 83, 't': 84, 'u': 85, 'v': 86, 'w': 87, 'x': 88, 'y': 89, 'z': 90},
		s: {'!': 1, '"': 2, '#': 3, '$': 4, '%': 5, '&': 6, "'": 7, '(': 8, ')': 9, '*': 10, '+': 11, ',': 12, '-': 13, '.': 14, '/': 15, ':': 26, ';': 27, '<': 28, '=': 29, '>': 30, '?': 31, '@': 32, '[': 59, '\\': 60, ']': 61, '^': 62, '_': 63, '`': 64, '{': 91, '|': 92, '}': 93, '~': 94}
};
//util.cEncodings['chars'] = $.extend({}, util.cEncodings.d, util.cEncodings.l, util.cEncodings.u, util.cEncodings.s); 
util.cEncodings['chars'] = {
'0': 16, '1': 17, '2': 18, '3': 19, '4': 20, '5': 21, '6': 22, '7': 23, '8': 24, '9': 25,
'A': 33, 'B': 34, 'C': 35, 'D': 36, 'E': 37, 'F': 38, 'G': 39, 'H': 40, 'I': 41, 'J': 42, 'K': 43, 'L': 44, 'M': 45, 'N': 46, 'O': 47, 'P': 48, 'Q': 49, 'R': 50, 'S': 51, 'T': 52, 'U': 53, 'V': 54, 'W': 55, 'X': 56, 'Y': 57, 'Z': 58,
'a': 65, 'b': 66, 'c': 67, 'd': 68, 'e': 69, 'f': 70, 'g': 71, 'h': 72, 'i': 73, 'j': 74, 'k': 75, 'l': 76, 'm': 77, 'n': 78, 'o': 79, 'p': 80, 'q': 81, 'r': 82, 's': 83, 't': 84, 'u': 85, 'v': 86, 'w': 87, 'x': 88, 'y': 89, 'z': 90,
'!': 1, '"': 2, '#': 3, '$': 4, '%': 5, '&': 6, "'": 7, '(': 8, ')': 9, '*': 10, '+': 11, ',': 12, '-': 13, '.': 14, '/': 15, ':': 26, ';': 27, '<': 28, '=': 29, '>': 30, '?': 31, '@': 32, '[': 59, '\\': 60, ']': 61, '^': 62, '_': 63, '`': 64, '{': 91, '|': 92, '}': 93, '~': 94
}

// generate randomness
// FIXME: check why Douglas did it like this and fix it everywhere
util.generateRandom = function(q) {
	var rng = new SecureRandom();
	var q1 = q.subtract(BigInteger.ONE);
	var r = new BigInteger(q.bitLength(), rng);
	return r.mod(q1).add(BigInteger.ONE);
}

util.base64Fuu = function(str) {
//	escape(atob(byteArrayData)).replace(/%/g, "\\x");
	var bytes = [];
	for (var i = 0; i < str.length; ++i) {
		bytes.push(str.charCodeAt(i));
	}
	return bytes;
}

util.point2string = function(p) {
	return "("+p.getX().toBigInteger().toString(16)+", "+p.getY().toBigInteger().toString(16)+")";
}
