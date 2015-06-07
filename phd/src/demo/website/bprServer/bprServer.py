import bprServer.Util as Util
import hashlib
import sys
from charm.toolbox.ecgroup import ECGroup, ZR

class pcServer:
			
	@staticmethod
	def getChallenge(cLen, minLen, params):
		if cLen < minLen:
			print("ERROR: PASSWORD IS TOO SHORT (getChallenge)")
			return 0
		
		group = params[1]
		
		# choose challenges
		CH_PoM = group.random(ZR)
		CH_PoE = group.random(ZR)
		CH_PoS = []
		for i in range(cLen):
			CH_PoS.append(str(group.random(ZR)))

		return {'CH_PoM': str(CH_PoM), 'CH_PoE': str(CH_PoE), 'CH_PoS': CH_PoS}

	@staticmethod
	def verifyProofs(clientMessage, policyString, params):
	
#		print("clientMessage: "+str(clientMessage))
		
		policy = Util.Policy(policyString)
		
		# FIXME
		ZERO = params[1].random(ZR)
		ZERO -= ZERO
		
		css = clientMessage['RES_PoM']['c']
		sss = clientMessage['RES_PoM']['s']
		CH_PoM = clientMessage['CH_PoM']
		
		# set-up
		group = params[1]
		g = params[0]['g']
		h = params[0]['h']
		f = []
		for i in range(-4, 100):
			f.append(params[0]['f'+str(i)])
		
		Cs = clientMessage['C'][:] # XXX: have to copy this to add something later!
		
		###########################################
		## verify PoM
		###########################################
		COM_PoM = clientMessage['COM_PoM']
		C2s = clientMessage['Cp']
		clientPolicy = COM_PoM['omega']
		tss = COM_PoM['t']
		
		# loop over set of omegas
		polyEncoding = policy.polyEncoding
		omegas = []
		for i in range(len(clientPolicy)):
			if clientPolicy[i] in ["d", "u", "l", "s"]:
				omegas.append(Util.Encoding.encodeSet(clientPolicy[i]))
			else:
				omegas.append(Util.Encoding.characters)
				
			cs = css[i]
			
			# compute c as XOR to verify against challenge
			cv = int(cs[0], 16)
			for j in range(1, len(cs)):
				cv = cv ^ int(cs[j], 16)
			if str(cv) != str(CH_PoM):
				print("ERROR IN SET MEMBERSHIP VERIFICATION (challenge)")
				return 0
			
		
		# verify PoM responses
		for i in range(len(tss)):
			ts = tss[i]
			j = 0
			for e in sorted(omegas[i]):
				C2si = Util.Params.readPoint(C2s[i][0], C2s[i][1])
				sssij = Util.Params.readScalar(sss[i][j])
				cssij = Util.Params.readScalar(css[i][j])
				omegasie = omegas[i][e]
				tt = (g ** omegasie)
				tt = tt * (h ** sssij)
				gpin = ((g ** omegasie) ** -1)
				gpin = ((C2si * gpin) ** cssij)
				tt = tt * gpin
				tsj = Util.Params.readPoint(ts[j][0], ts[j][1])
				if tt != tsj:
					print("ERROR IN SET MEMBERSHIP VERIFICATION (response)")
					return 0
				i
				j += 1
		
		if ''.join(sorted(policy.poly)) not in ''.join(sorted(clientPolicy)):
			print("ERROR IN POLICY VERIFICATION (response)")
			return 0
		
		print("EVERYTHING GOOD WITH PoM :)")
		
		
		###########################################
		## verify PoE
		###########################################
		COM_PoE = clientMessage['COM_PoE']
		CH_PoE = int(clientMessage['CH_PoE'])
		H2 = Util.Params.readPoint(clientMessage['v']['H2'][0], clientMessage['v']['H2'][1])
		H1 = Util.Params.readPoint(clientMessage['v']['H1'][0], clientMessage['v']['H1'][1])
		sH = Util.Params.readScalar(clientMessage['v']['sH'])
		ssp = Util.Params.readScalar(clientMessage['RES_PoE']['ssp'])
		spi = Util.Params.readScalar(clientMessage['RES_PoE']['spi'])
		srast = Util.Params.readScalar(clientMessage['RES_PoE']['srast'])
		
		cSum = Util.Params.readPoint(Cs[0][0], Cs[0][1]) # FIXME: convert points and stuff only once
		for i in range(1, len(Cs)):
			cSum *= (Util.Params.readPoint(Cs[i][0], Cs[i][1]) ** (Util.Encoding.base ** i))
		
		tspS = (g ** ssp) * (H1 ** CH_PoE)
		thS = (H1 ** spi) * (H2 * (h ** sH) ** -1) ** CH_PoE
		tcS = (g ** spi) * (h ** srast) * (cSum ** CH_PoE)
		
		tspC = Util.Params.readPoint(COM_PoE['tsp'][0], COM_PoE['tsp'][1])
		thC = Util.Params.readPoint(COM_PoE['th'][0], COM_PoE['th'][1])
		tcC = Util.Params.readPoint(COM_PoE['tcast'][0], COM_PoE['tcast'][1])
		
		if str(tspS) != str(tspC) or str(thS) != str(thC) or str(tcS) != str(tcC):
			print("ERROR IN EQUIVALENCE VERIFICATION (response)")
			return 0
			
		print("EVERYTHING GOOD WITH PoE :)")	
		
		
		###########################################
		## verify PoS
		###########################################
		COM_PoS = clientMessage['COM_PoS']
		CH_PoS = clientMessage['CH_PoS']
		s = clientMessage['RES_PoS']['s']
		sp = clientMessage['RES_PoS']['sp']
		
		# convert strings to arithmetic objects
		so = []
		spo = []
		for i in range (0, len(s)):
			so.append(Util.Params.readScalar(s[i]))
			spo.append(Util.Params.readScalar(sp[i]))
		s = so
		sp = spo
		
		ch = []
		fp = []
		for j in range(0, len(Cs)):
			ch.append(int(CH_PoS[j]))
			fp.append(Util.Params.readPoint(COM_PoS['fp'][j][0], COM_PoS['fp'][j][1]))
		fp.append(Util.Params.readPoint(COM_PoS['fp'][len(Cs)][0], COM_PoS['fp'][len(Cs)][1]))
		
		# set C_0 = h
		Cs.insert(0, h)
		
		# choose new challenge
		a = group.random(ZR)
		
		f1 = params[0]['f-4'] ** (s[0] + a * sp[0])
		for v in range(-3, len(Cs)):
			f1 *= params[0]['f'+str(v)] ** (s[v+4] + a * sp[v+4])
		
		
		ftil = Util.Params.readPoint(COM_PoS['ftil'][0], COM_PoS['ftil'][1])
		f2 = fp[0] * (ftil ** a)
		for j in range(1, len(Cs)):
			f2 *= fp[j] ** (ch[j-1] + a * ch[j-1] ** 2)
		
		cProd = Cs[0] ** s[4]
		for v in range(1, len(Cs)):
			cProd *= Util.Params.readPoint(Cs[v][0], Cs[v][1]) ** s[v+4]
			
		cpProd = Util.Params.readPoint(COM_PoS['Cp0'][0], COM_PoS['Cp0'][1])
		for j in range(0, len(C2s)):
			C2sj = Util.Params.readPoint(C2s[j][0], C2s[j][1])
			cpProd *= C2sj ** ch[j]
	
		l1 = 0
		l2 = 0
		for j in range(1, len(C2s)+1):
			chj = ch[j-1] ** 2
			sj = s[j+4] ** 2
			l2 += (sj - chj)
			l1 += (sj*s[j+4] - chj*ch[j-1])
	
		w = Util.Params.readScalar(COM_PoS['w'])
		wtil = Util.Params.readScalar(COM_PoS['wtil'])
		r1 = s[2] + sp[1] + w
		r2 = s[0] + wtil
		
	
		if f1 != f2 or cProd != cpProd or l2 != r2 or l1 != r1: # FIXME
			print("ERROR IN SHUFFLING VERIFICATION (response) :(") #sys.exit
			print("l1: "+str(l1))
			print("r1: "+str(r1))
			print("l2: "+str(l2))
			print("r2: "+str(r2))
			print("f1: "+str(f1))
			print("f2: "+str(f2))
			print("cProd: "+str(cProd))
			print("cpProd: "+str(cpProd))
			return 0
			
		print("EVERYTHING GOOD WITH PoS :)")
		
		return 1
