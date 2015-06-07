import bprServer.Util as Util, bprServer.PwdHash as PwdHash
import hashlib, random, re
from collections import Counter
from charm.toolbox.ecgroup import ZR, ECGroup
from charm.toolbox.securerandom import OpenSSLRand
from charm.toolbox.conversion import Conversion
from charm.core.math.integer import integer

# dev tools
import inspect

class pcClient:

	def __init__(self, params):
		self.params = params #Util.Params.readParams()
		
		# FIXME: check if this can be done better
		self.ZERO = self.params[1].random(ZR)
		self.ZERO -= self.ZERO
		
		self.ONE = Util.Params.readScalar("1")
	
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
		
	def setPolicy(self, policyString):
		self.policy = Util.Policy(policyString)
		self.minLen = 1
		
	
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

		if len(self.pwd) > 100:
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
		
		# encode characters
		pis = [] # encoded characters
		for i in range(len(pwd)):
			pi = Util.Encoding.encode(self.pwd[i])
			pis.append(pi)
		
		com = PwdHash.Pedersen(self.params)
		self.Cs = [] # commitments
		self.C2s = [] # re-randomised commitments
		self.C2rs = [] # re-randomisers for C2s (NOT shuffled)
		self.ks = [] # index for shuffled C2 (XXX: this is different than in the paper)
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
			
			# compute re-randomised commitment
			C2 = com.recommit(C)
			self.C2s.append(C2)
			self.C2rs.append(C2[1])
			
			# choose shuffling index for C2
			sr = random.SystemRandom()
			k = -1
			while 1:
#				k = sr.randint(0, len(pwd)-1)
				k += 1
				if k not in self.ks:
					break
			self.ks.append(k)
			
			omega = {}
			for j in range(len(RSets)):
				RSet = RSets[j]
				if pwd[i] in RSet:
					omega = RSet
					del RSets[j]
					break
			if not omega:
				omega = Util.Encoding.characters
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
				if pwd[i] == e:
					krho = self.ONE #group.random(ZR)
					t = (g ** pis[i]) * (h ** krho)
					ts.append(t)
					self.krhos.append(krho)
					self.xs.append(j) 
				else:
					s = self.ONE #group.random(ZR)
					c = self.ONE #group.random(ZR)
					ss.append(s)
					cs.append(c)
					t = (g ** omega[e]) * (h ** s) * ((C2[0] * ((g ** omega[e]) ** -1)) ** c)
					ts.append(t)
				j += 1
			tss.append(ts)
			self.sss.append(ss)
			self.css.append(cs)
		## end of for loop over password characters	
		
		# shuffle C2s, omegas etc. according to indices ks
		self.C2s = [ self.C2s[i] for i in self.ks]
		self.omegas = [ self.omegas[i] for i in self.ks]
		self.sss = [ self.sss[i] for i in self.ks]
		self.css = [ self.css[i] for i in self.ks]
		self.krhos = [ self.krhos[i] for i in self.ks]
		tss = [ tss[i] for i in self.ks]
		self.xs = [ self.xs[i] for i in self.ks]
			
		###########################################
		## compute PoE
		###########################################
		self.ksp = self.ONE #group.random(ZR)
		self.kpi = self.ONE #group.random(ZR)
		self.krast = self.ONE #group.random(ZR)
		tsp = g ** self.ksp
		th = gp ** self.kpi
		tcast = (g ** self.kpi) * (h ** self.krast)
		
		###########################################
		## compute PoS
		###########################################
		
		# choose randome A'
		Ap = []
		for i in range(-4, len(pwd)+1):
			Ap.append(self.ONE)  #group.random(ZR)
		
		# compute matrix A
		A = []
		for i in range(-4, len(pwd)+1):  # choose random values, set re-randomiser and set shuffle matrix, fill the rest with 0
			At = []
			for j in range(0, len(pwd)+1):
				if j == 0 or i == -1:
					At.append(self.ONE)  #group.random(ZR)
				elif i == 0:
					At.append(self.C2s[j-1][1]) # self.ks[j-1]
				elif i > 0 and i-1 == self.ks[j-1]:
					At.append(1)
				else:
					At.append(0)
			A.append(At)
		
		for j in range(1, len(pwd)+1): ## replace 0s with the correct values
			for v in range(1, len(pwd)+1):
				A[0][j] += 2 * A[v+4][0] * A[v+4][j] # -4,j
				A[1][j] += 3 * A[v+4][0] * A[v+4][j] # -3,j
				A[2][j] += 3 * (A[v+4][0] ** 2) * A[v+4][j] # -2,j
		
		# compute commitment to A
		fpv = []
		for v in range(0, len(pwd)+1):
			fj = self.params[0]['f-4'] ** A[0][v]
			print("fj("+str(v)+"): "+str(fj))
			for j in range(-3, len(pwd)+1):
				print("fv("+str(j+4)+"): "+str(self.params[0]['f'+str(j)]))
				print("A["+str(j+4)+"]["+str(v)+"]: "+str(A[j+4][v]))
				fj *= self.params[0]['f'+str(j)] ** A[j+4][v]
				print("fj("+str(j)+"): "+str(fj))
			fpv.append(fj)
			
		ftil = self.params[0]['f'+str(-4)] ** Ap[0]
		for j in range(-3, len(pwd)+1):
			ftil *= self.params[0]['f'+str(j)] ** Ap[j+4]
		
		piSum = pis[0] * A[5][0]
		rSum = A[4][0] + self.Cs[0][1] * A[5][0]
		for j in range(1, len(pwd)):
			piSum += pis[j] * A[j+5][0]
			rSum += self.Cs[j][1] * A[j+5][0]
		Cp0 = (g ** piSum) * (h ** rSum)
		
		w = -A[2][0] - Ap[1]
		wtil = -A[0][0]
		for j in range(0, len(pwd)):
			w += A[j+5][0] ** 3
			wtil += A[j+5][0] ** 2
		
		# store A and A'
		self.A = A
		self.Ap = Ap
		
		# create output message
		# FIXME: only output the commitment NOT randomness
		COM_PoS = {'Cp0': Cp0, 'ftil': ftil, 'fp': fpv, 'w': w, 'wtil': wtil}
		COM_PoM = {'t': tss, 'omega': self.omegas}
		COM_PoE = {'tsp': tsp, 'th': th, 'tcast': tcast}
		verifier = {'sH': self.pHash.sH, 'H1': gp, 'H2': self.H2}
		return {'C': self.Cs, 'Cp': self.C2s, 'v': verifier, 'COM_PoM': COM_PoM, 'COM_PoE': COM_PoE, 'COM_PoS': COM_PoS}
		
	
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
			sl = self.krhos[i] - cl * (self.Cs[self.ks[i]][1] + self.C2s[i][1])
			self.css[i].insert(self.xs[i], cl)
			self.sss[i].insert(self.xs[i], sl)
		
		
		RES_PoM = {'s': self.sss, 'c': self.css} 
		
		
		###########################################
		## compute PoE response
		###########################################
		challenge = int(mIn['CH_PoE'])
		
		ssp = (self.ksp - challenge * self.pHash.sP) % group.order()
		spi = (self.kpi - challenge * self.pwdEnc) % group.order()
		rSum = self.Cs[0][1]
		for i in range(1, len(self.Cs)):
			rSum += (Util.Encoding.base ** i) * self.Cs[i][1]
		srast = (self.krast - challenge * rSum) % group.order()
		
		RES_PoE = {'ssp': ssp, 'spi': spi, 'srast': srast}
		
		###########################################
		## compute PoS response
		###########################################
		challenges = mIn['CH_PoS']
		challenges.insert(0, 1) # insert 1 for c_0
		
		s = []
		sp = []
		for v in range(-4, len(self.pwd)+1):
			sv = self.A[v+4][0] * int(challenges[0])
			svp = self.Ap[v+4]
			for j in range(1, len(self.pwd)+1):
				sv += self.A[v+4][j] * int(challenges[j])
				svp += self.A[v+4][j] * (int(challenges[j]) ** 2)
			s.append(sv)
			sp.append(svp)
		
		RES_PoS = {'s': s, 'sp': sp}
		
		return {'RES_PoM': RES_PoM, 'RES_PoE': RES_PoE, 'RES_PoS': RES_PoS} 
		
		
