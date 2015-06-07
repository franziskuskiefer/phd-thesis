#!/usr/bin/python3

import argparse
import bprServer.Util as Util
from charm.toolbox.ecgroup import ECGroup, ZR

###################################
# Algebraic Password Hashing
###################################

class Pedersen:

	def __init__(self, params):
		self.g = params[0]['g']
		self.h = params[0]['h']
		self.group = params[1]

	# return [commtiment, randomness]
	def commit(self, m):
		r = Util.Params.readScalar("1")# self.group.random(ZR)
		c = (self.g ** m) * (self.h ** r)
		return [c, r]
	
	# re-randomise a commitment
	def recommit(self, C):
		r = Util.Params.readScalar("1")# self.group.random(ZR)
		c = C[0] * (self.h ** r)
		return [c, r]
	
	def verify(self, m, r, C):
		mc = (self.g ** m) * (self.h ** r)
		if mc == C:
			print("equal")
		else:
			print("not...")
		return [mc, C]

class PHash:

	def __init__(self, params):
		self.g = params[0]['g']
		self.h = params[0]['h']
		self.group = params[1]

	def genSalt(self):
		self.sP = Util.Params.readScalar("1")# self.group.random(ZR)
		self.sH = Util.Params.readScalar("1")# self.group.random(ZR)

	def preHash(self, m):
		self.gp = self.g ** self.sP
		return self.gp ** m

	def pHash(self, P):
		return P * (self.h ** self.sH)

	def Hash(self, m):
		P = self.preHash(m)
		return {'H1': self.gp, 'H2': self.pHash(P)}

# CS enc/dec test main
def main(args):

	# encode the password
	m = Util.Encoding.encode(args.pwd)
	print("encoded pwd: ", m)

	# generate / read parameters
	if args.n:
		params = Util.Params.initParams()
	else:
		params = Util.Params.readParams()

	# generate salts
	pHash = PHash(params)
	pHash.genSalt()
	
	# hash
	h = pHash.Hash(m)
	print("hashed pwd: ", h)

	# generate commitment to characters in pwd
	C = Pedersen(params)
	for i in range(len(args.pwd)):
		Ci = C.commit(Util.Encoding.encode(args.pwd[i]))
		print("C", i, ": ", Ci[0])

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Hash a password and generate commitments for all it characters')
	parser.add_argument('pwd', metavar='\"pwd\"', type=str, help='the password to hash')
	parser.add_argument('-n', action='store_true', help='generate new parameters')
	args = parser.parse_args()
	main(args)
