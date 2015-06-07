
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.ecgroup import ECGroup, G, ZR
from charm.toolbox.eccurve import prime192v1
from base64 import *
from binascii import *
import operator
import os.path

class Encoding:

	base = 100000

	@staticmethod
	def encode(m, i = 0):
		if i == 0:
			azt = lambda x : int('%.3d' % ord(x)) - 32
		else:
			azt = lambda x : (int('%.3d' % ord(x)) - 32) * Encoding.base**i
		return int(''.join(map(str, map(azt, m))))

	@staticmethod
	def encodeString(s, pad = 0):
		e = 0
		for i in range(len(s)):
			t = Encoding.encode(s[i], i)
#			if t == 0:
#				e *= 100
#			else:
			e += t
		toPad = pad - len(str(e))
#		for i in range(toPad):
#			e *= 100
		return e

	@staticmethod
	def decode(m):
		m = int(str(m), 0) # could be something else and crash everyhting
		s = str(m)
		result = ''
		for i in range(len(str(m))):
			c = ((m % (Encoding.base**(i+1))) - (m % (Encoding.base**i))) // (Encoding.base**i)
			if c == 0:
				break
			c += 32
			result += chr(c)
		return result
	
	@staticmethod
	def move(m, i):
		return m * (Encoding.base ** i)
		
	digits = {'0': 16, '1': 17, '2': 18, '3': 19, '4': 20, '5': 21, '6': 22, '7': 23, '8': 24, '9': 25}
	upper = {'A': 33, 'B': 34, 'C': 35, 'D': 36, 'E': 37, 'F': 38, 'G': 39, 'H': 40, 'I': 41, 'J': 42, 'K': 43, 'L': 44, 'M': 45, 'N': 46, 'O': 47, 'P': 48, 'Q': 49, 'R': 50, 'S': 51, 'T': 52, 'U': 53, 'V': 54, 'W': 55, 'X': 56, 'Y': 57, 'Z': 58}
	lower = {'a': 65, 'b': 66, 'c': 67, 'd': 68, 'e': 69, 'f': 70, 'g': 71, 'h': 72, 'i': 73, 'j': 74, 'k': 75, 'l': 76, 'm': 77, 'n': 78, 'o': 79, 'p': 80, 'q': 81, 'r': 82, 's': 83, 't': 84, 'u': 85, 'v': 86, 'w': 87, 'x': 88, 'y': 89, 'z': 90}
	symbols = {'!': 1, '"': 2, '#': 3, '$': 4, '%': 5, '&': 6, "'": 7, '(': 8, ')': 9, '*': 10, '+': 11, ',': 12, '-': 13, '.': 14, '/': 15, ':': 26, ';': 27, '<': 28, '=': 29, '>': 30, '?': 31, '@': 32, '[': 59, '\\': 60, ']': 61, '^': 62, '_': 63, '`': 64, '{': 91, '|': 92, '}': 93, '~': 94}
	characters = dict(list(digits.items()) + list(upper.items()) + list(lower.items()) + list(symbols.items()))

	@staticmethod
	def decodeSet(s):
		if s == Encoding.digits:
			return "d"
		elif s == Encoding.upper:
			return "u"
		elif s == Encoding.lower:
			return "l"
		elif s == Encoding.symbols:
			return "s"
			
	@staticmethod
	def encodeSet(s):
		if s == "d":
			return Encoding.digits
		elif s == "u":
			return Encoding.upper
		elif s == "l":
			return Encoding.lower
		elif s == "s":
			return Encoding.symbols
	
class Policy:
	
	def __init__(self, f):
		self.digits = 'd'
		self.upper = 'u'
		self.lower = 'l'
		self.symbols = 's'
		self.characters = '?'
		self.star = '*'
		self.knownSymbols = [self.digits, self.upper, self.lower, self.symbols, self.characters]
		self.encoding = {self.digits: Encoding.digits, self.upper: Encoding.upper, self.lower: Encoding.lower, self.symbols: Encoding.symbols, self.characters: Encoding.characters}
		self.poly = []
		self.polyEncoding = []
		self.charactersEnc = {}
		
		for c in list(f):
			if c in self.knownSymbols:
				if len(self.poly) == 0 or self.poly[-1] != c or c != self.star:
					self.poly.append(c)
					self.polyEncoding.append(self.encoding[c])
			else:
				raise Exception("%c is not a valid character specification for a policy!" % c)
		
#		for i in range(n):
#			for x in Encoding.characters:
#				self.charactersEnc[x+str(i)] = (Encoding.base ** i) * Encoding.characters[x]

class Params:

	@staticmethod
	def paramsExist():
		return os.path.isfile('pc.param')
	
	@staticmethod
	def readPoint(pointX, pointY):
		group = ECGroup(prime192v1)
		point = group.deserialize(b'1:'+b64encode(a2b_hex('03'+pointX.zfill(48))))
		if str(group.coordinates(point)[1]) != str(int(pointY, 16)):
#			print("inverting ("+str(group.coordinates(point)[1])+", "+str(int(pointY, 16))+")")
			point = point ** -1
		return point
	
	@staticmethod
	def serializePoint(point):
		group = ECGroup(prime192v1)
		fuu = "{'x': '"+str(hex(int(str(group.coordinates(point)[0])))[2:])+"', 'y': '"+str(hex(int(str(group.coordinates(point)[1])))[2:])+"'}"
#		fuu2 = "{'x': '"+str(hex(int(str(group.coordinates(point)[0]))))+"', 'y': '"+str(hex(int(str(group.coordinates(point)[1]))))+"'}"
#		result = {"x": str(group.coordinates(point)[0]), "y": str(group.coordinates(point)[1])}
#		print(str(result))
#		print(fuu)
#		print(fuu2)
		return fuu
	
	@staticmethod
	def readScalar(s):
		group = ECGroup(prime192v1)
		return group.deserialize(b'0:'+b64encode(a2b_hex(s.zfill(58))))
		
	@staticmethod
	def initParams():
		group = ECGroup(prime192v1)
		g = Params.readPoint("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", "7192B95FFC8DA78631011ED6B24CDD573F977A11E794811")
		h = Params.readPoint("87656f2b5fee3821b53b00d78bd61a8d407ce4393ea48906", "b52e5b337ca8f667935a63d02d6f6fec689c7f18a640a8a5")
#		g = group.random(G)
#		h = group.random(G)
		params = {'g':g, 'h':h}
		
		# generators for the proof of shuffling
		for i in range(-4, 100): # FIXME: make this 101
			params['f'+str(i)] = group.random(G)
		
		f = open('pc.param', 'wb')
		f.write(objectToBytes(params,group))
		f.close()
		return [params, group]

	@staticmethod
	def readParams(filename = 'pc.param'):
		if (os.path.isfile(filename)):
			group = ECGroup(prime192v1)
			f = open(filename, 'rb')
			params = f.readline()
			f.close()
			params = bytesToObject(params,group)
			return [params, group]
		else:
			raise Exception("I can't find the parameters file. You have to create them first using -n when starting.")
	
	@staticmethod
	def getJSONParams(filename = 'pc.param'):
		allParams = Params.readParams(filename)
		params = allParams[0]
		paramOut = ''
		for k in params:
			paramOut = paramOut+" '"+k+"':"+Params.serializePoint(params[k])+","
		paramOut = paramOut[:-1]
		paramOut = paramOut.replace("'", '"')
		paramsJSON = "{" + paramOut + "}"
		return [allParams, paramsJSON]
		
	@staticmethod
	def encode(g, h, group):
		params = {'g':g, 'h':h}
		return str(objectToBytes(params,group))
