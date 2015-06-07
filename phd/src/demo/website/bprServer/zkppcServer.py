import Util
import hashlib
import sys
from charm.toolbox.ecgroup import ECGroup, ZR

class pcServer:

	def __init__(self, policyString, m, n):
		self.params = Util.Params.readParams()
		self.policy = Util.Policy(policyString, m, n)
		self.minLen = m
		self.maxLen = n
		self.accept = True
		
		# FIXME: check if this can be done better
		self.ZERO = self.params[1].random(ZR)
		self.ZERO -= self.ZERO
		self.ONE = self.ZERO + 1

	# get commtiments from client and return challenges
	def getChallenge(self, clientMessage):
		# TODO: parse and store clientMessage
		self.com = clientMessage
		
		# set-up
		group = self.params[1]
		
		# choose challenges
		self.CH_PoM = group.random(ZR)
		self.CH_PoE = group.random(ZR)

		# FIXME: WHY DO WE HAVE TO COPY THE OUTPUT ARRAY? STRANGE PYTHON THINGY HERE
		return {'CH_PoM': self.CH_PoM, 'CH_PoE': self.CH_PoE} 
				

	def verifyProofs(self, clientMessage):
		# TODO: parse and store clientMessage
		
		css = clientMessage['RES_PoM']['c']
		sss = clientMessage['RES_PoM']['s']
		
		# set-up
		group = self.params[1]
		g = self.params[0]['g']
		h = self.params[0]['h']
		
		Cs = self.com['C']
		
		###########################################
		## verify PoM
		###########################################
		COM_PoM = self.com['COM_PoM']
		omegas = COM_PoM['omega']
		tss = COM_PoM['t']
		
		# loop over set of omegas
		for i in range(len(omegas)):
			cs = css[i]
			
			# compute c as XOR to verify against challenge
			cv = int(cs[0])
			for j in range(1, len(cs)):
				cv = cv ^ int(cs[j])
			cv = self.ZERO + cv
			if cv != self.CH_PoM:
				sys.exit("ERROR IN SET MEMBERSHIP VERIFICATION (challenge)")
			
			# FIXME: add this
#			print("omegas[i]", omegas[i])
#				# also check that everything from the policy is part of omegas
#				if len(omegas[i]) < 94:
#					print("k", k)
#					poly = self.policy.poly[k]
#					print(poly)
#					print(self.policy.encoding[poly])
#					k += 1
		
		# verify PoM responses
		for i in range(len(tss)):
			ts = tss[i]
			j = 0
			for e in sorted(omegas[i]):
				tt = (g ** omegas[i][e]) * (h ** sss[i][j]) * ((Cs[i][0] * ((g ** omegas[i][e]) ** -1)) ** css[i][j])
				if tt != ts[j]:
					sys.exit("ERROR IN SET MEMBERSHIP VERIFICATION (response)")
				i
				j += 1
		
		print("EVERYTHING GOOD SO FAR WITH PoM :)")
		
		
		###########################################
		## verify PoE
		###########################################
		COM_PoE = self.com['COM_PoE']
		ssp = clientMessage['RES_PoE']['ssp']
		spi = clientMessage['RES_PoE']['spi']
		ssh = clientMessage['RES_PoE']['ssh']
		srast = clientMessage['RES_PoE']['srast']
		
		cSum = Cs[0][0]
		for i in range(1, len(Cs)):
			cSum *= Cs[i][0]
		
		tspS = (g ** ssp) * (self.com['v']['H1'] ** self.CH_PoE)
		thS = (self.com['v']['H1'] ** spi) * (h ** ssh) * (self.com['v']['H2'] ** self.CH_PoE)
		tcS = (g ** spi) * (h ** srast) * (cSum ** self.CH_PoE)
		
		if tspS != COM_PoE['tsp'] or thS != COM_PoE['th'] or tcS != COM_PoE['tcast']:
			sys.exit("ERROR IN EQUIVALENCE VERIFICATION (response)")
			
		print("EVERYTHING GOOD SO FAR WITH PoE :)")	
			
		

			
			
			
			
			
			
			
		
