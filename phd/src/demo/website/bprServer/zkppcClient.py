import Util, PwdHash
import hashlib, random, re
from collections import Counter
from charm.toolbox.ecgroup import ZR, ECGroup
from charm.toolbox.securerandom import OpenSSLRand
from charm.toolbox.conversion import Conversion
from charm.core.math.integer import integer

# dev tools
import inspect

class pcClient:

	def __init__(self):
		self.params = Util.Params.readParams()
		
		# FIXME: check if this can be done better
		self.ZERO = self.params[1].random(ZR)
		self.ZERO -= self.ZERO
	
	# set password pwd and compute hash
	def setPwd(self, pwd):
		self.pwd = pwd
		self.pwdEnc = Util.Encoding.encodeString(pwd)
		
		# generate password verifier
		self.pHash = PwdHash.PHash(self.params)
		self.pHash.genSalt()
		self.v = self.pHash.Hash(self.pwdEnc)
		self.gp = self.v['H1']
		self.H2 = self.v['H2']
		
		# generate commitment to hash salt sH
#		C = PwdHash.Pedersen(self.params)
#		self.Cv = C.commit(self.pHash.sH)
		
	def setPolicy(self, policyString, m, n):
		self.policy = Util.Policy(policyString, m, n)
		self.minLen = m
		self.maxLen = n
		
	
	# commitment phase:
	# * compute Pedersen commitments to all characters in pw
	# * compute product of character commitments
	# * compute shuffle of character commitments
	# ------
	# * compute commitment phase of SMP proofs
	# * compute commitment phase of ZKP for H2 and C contain the same pi
	# * compute commitment phase of shuffling proof
	# ------
	# output is (H1, H2, sP, sH, g^sP)
	def commit(self):

		if len(self.pwd) > self.maxLen:
			raise Exception("The given password is too long to be used with my parameters :(")
		
		if len(self.pwd) < len(self.policy.poly): #or len(self.pwd) < self.minLen
			raise Exception("The given password is too short to fulfil the policy!")
		
		# read group and set local policy
		group = self.params[1]
		g = self.params[0]['g']
		h = self.params[0]['h']
		poly = self.policy.poly
		pwd = self.pwd
		pwdEnc = self.pwdEnc
		R = self.policy.poly
		RSets = self.policy.polyEncoding
		gp = self.gp
		
#		print("R:", R)
#		print("RSets:", RSets)
		
		# encode characters POSITION SPECIFIC
		pis = [] # encoded characters
		for i in range(len(pwd)):
			pi = Util.Encoding.encode(self.pwd[i], i)
			pis.append(pi)
		
		com = PwdHash.Pedersen(self.params)
		self.Cs = [] # commitments
		tss = [] # t commitments for PoM
		self.sss = [] # random s for PoM
		self.css = [] # random c for PoM
		self.krhos = [] # random krho for PoM
		self.xs = [] # index of element in omega for PoM
		self.omegas = [] # sets of R in order used in proofs
		for i in range(len(pwd)):
		
			# generate Commitment
			C = com.commit(pis[i])
			self.Cs.append(C)
			
			omega = {}
			for j in range(len(RSets)):
				RSet = RSets[j]
				if pwd[i]+str(i) in RSet:
					omega = RSet
					del RSets[j]
					break
			if not omega:
				omega = self.policy.charactersEnc
			self.omegas.append(omega)
			
			###########################################
			## compute PoM (OR proof)
			###########################################
			ss = []
			cs = []
			ts = []
			krho = 0
			j = 0
			for e in sorted(omega):
				if pwd[i]+str(i) == e:
					krho = group.random(ZR)
					t = (g ** pis[i]) * (h ** krho)
					ts.append(t)
					self.krhos.append(krho)
					self.xs.append(j)
				else:
					s = group.random(ZR)
					c = group.random(ZR)
					ss.append(s)
					cs.append(c)
					t = (g ** omega[e]) * (h ** s) * ((C[0] * ((g ** omega[e]) ** -1)) ** c)
					ts.append(t)
				j += 1
			tss.append(ts)
			self.sss.append(ss)
			self.css.append(cs)
		## end of for loop over password characters	
		
		###########################################
		## compute PoE
		###########################################
		self.ksp = group.random(ZR)
		self.kpi = group.random(ZR)
		self.ksh = group.random(ZR)
		self.krast = group.random(ZR)
		tsp = g ** self.ksp
		th = gp ** self.kpi * h ** self.ksh
		tcast = (g ** self.kpi) * (h ** self.krast)
		
		# create output message
		# FIXME: only output the commitment NOT randomness
		COM_PoM = {'t': tss, 'omega': self.omegas}
		COM_PoE = {'tsp': tsp, 'th': th, 'tcast': tcast}
		verifier = {'H1': gp, 'H2': self.H2}
		return {'C': self.Cs, 'v': verifier, 'COM_PoM': COM_PoM, 'COM_PoE': COM_PoE}
		
	
	def response(self, mIn): # CH_PoM, CH_PoE, CH_PoS
		# compute responses

		group = self.params[1]

		###########################################
		## compute PoM response
		###########################################
		challenge = mIn['CH_PoM']
		for i in range(len(self.omegas)):
			cl = int(challenge)
			cs = self.css[i]
			for j in range(len(self.omegas[i])-1):
				cl = cl ^ int(cs[j])
			cl = self.ZERO + cl
			sl = self.krhos[i] - cl * self.Cs[i][1]
			self.css[i].insert(self.xs[i], cl)
			self.sss[i].insert(self.xs[i], sl)
		
		
		RES_PoM = {'s': self.sss, 'c': self.css} 
		
		
		###########################################
		## compute PoE response
		###########################################
		challenge = mIn['CH_PoE']
		ssp = self.ksp - challenge * self.pHash.sP
		spi = self.kpi - challenge * self.pwdEnc
		ssh = self.ksh - challenge * self.pHash.sH
		rSum = self.Cs[0][1]
		for i in range(1, len(self.Cs)):
			rSum += self.Cs[i][1]
		srast = (self.krast - challenge * rSum) % group.order()
		
		RES_PoE = {'ssp': ssp, 'ssh': ssh, 'spi': spi, 'srast': srast}
		
		return {'RES_PoM': RES_PoM, 'RES_PoE': RES_PoE} 
		
		
