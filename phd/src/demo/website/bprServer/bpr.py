#!/usr/bin/python3

import argparse, hashlib
import random
from charm.toolbox.ecgroup import ZR, ECGroup

import Util
import PwdHash
import bprServer, bprClient
import zkppcServer, zkppcClient

###################################
# Polic Checker Demo
###################################

def main(args):
	
	print("pwd", args.pwd)
	pi = Util.Encoding.encodeString(args.pwd)
	print("encoded pwd", pi)
	print("decoded pwd", Util.Encoding.decode(pi))
	
	# generate new parameters if there are none
	if not Util.Params.paramsExist():
		params = Util.Params.initParams()

	minLen = args.m
	
	if args.n:
		print("DOING ESORICS STYLE PROOF WITH MAXIMUM PASSWORD LENGTH", args.n)
		
		####################
		# init client & set password
		####################
		ppcClient = zkppcClient.pcClient()
		ppcClient.setPwd(args.pwd)
		ppcClient.setPolicy(args.f, minLen, args.n)
	
		####################
		# init server 
		####################
		ppcServer = zkppcServer.pcServer(args.f, minLen, args.n)
	
		####################
		# do set-up and proofs
		####################
	
		# XXX: client commits to everything 
		clientMessage = ppcClient.commit()
		# XXX: client sends {'C': Cs, 'omega': omegas, 'v': verifier, 'COM_PoM': COM_PoM, 'COM_PoE': COM_PoE}
		serverMessage = ppcServer.getChallenge(clientMessage)
		# XXX: server replies with challenges
		clientMessage = ppcClient.response(serverMessage)
		# XXX: client replies with response
		ppcServer.verifyProofs(clientMessage)
		
		
	else:
		####################
		# init client & set password
		####################
		ppcClient = bprClient.pcClient()
		ppcClient.setPwd(args.pwd)
		ppcClient.setPolicy(args.f, minLen)
	
		####################
		# init server 
		####################
		ppcServer = bprServer.pcServer(args.f, minLen)
	
		####################
		# do set-up and proofs
		####################
	
		# XXX: client commits to PoM, PoE and PoS as well as to the password
		clientMessage = ppcClient.commit()
#		print(clientMessage)
		# XXX: client sends {'C': Cs, 'Cp': C2s, 'omega': omegas, 'v': verifier, 'COM_PoM': COM_PoM, 'COM_PoE': COM_PoE, 'COM_PoS': COM_PoS}
		serverMessage = ppcServer.getChallenge(clientMessage)
		# XXX: server replies with challenges
		clientMessage = ppcClient.response(serverMessage)
		# XXX: client replies with response
		ppcServer.verifyProofs(clientMessage)
	
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Perform "Policy Checker" protocol locally')
	parser.add_argument('f', metavar='\"policy\"', type=str, help='the policy to use')
	parser.add_argument('pwd', metavar='\"pwd\"', type=str, help='the password to use')
	parser.add_argument('-n', metavar='max length', required=False, type=int, help='the maximum password length')
	parser.add_argument('-m', metavar='min length', required=True, type=int, help='the minim password length')
	parser.add_argument('-g', action='store_true', help='generate new parameters')
	args = parser.parse_args()
	main(args)
