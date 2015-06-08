import bprServer.Util as Util
import hashlib
import sys
import json
from charm.toolbox.ecgroup import ECGroup, ZR

CERT_HASH = "4398FE30320462F01C268C7664912A26805273E2"

class tSokeServer:

	@staticmethod
	def compute(X, params, H, username):
		H = H.replace("'", '"')
		H = json.loads(H)
		group = params[1]
		g = params[0]['g']
		h = params[0]['h']
		H1 = Util.Params.readScalar(H[0]) # using only H.X Util.Params.readPoint(H[0], H[1])
		
		y = group.random(ZR)
		Y = g ** y
		Yast = Y * (h ** H1)
		
		# compute authentication tokens
		X = Util.Params.readPoint(X[0], X[1])
		Z = X ** y
		sha = hashlib.sha256()
		H = Util.Params.readPoint(H[0], H[1])
		hashInput = (username + Util.Params.point2HashString(H) + CERT_HASH + Util.Params.point2HashString(X) + Util.Params.point2HashString(Yast) + Util.Params.point2HashString(Z)).encode('utf-8')
		sha.update(hashInput)
		K = sha.hexdigest()
		
		print("K: "+str(K))
		
		a1 = hashlib.sha256((str(K)+"auth1").encode("utf-8")).hexdigest()
		a2 = hashlib.sha256((str(K)+"auth2").encode("utf-8")).hexdigest()
		
		return [a1, a2, Util.Params.serializePoint(Yast)]
