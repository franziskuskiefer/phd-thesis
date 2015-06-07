#!/usr/bin/python

from bottle import route, run, template, static_file, post, get, request, app, redirect
import json
import mysql.connector

from beaker.middleware import SessionMiddleware

import bprServer.Util as Util
import bprServer.bprServer as bprServer
import bprServer.bprClient as bprClient

scheme = "http"
domain = "localhost"
port = "8080"
registeredURL = "client/registered"
gotoURL = scheme + "://"+domain+":"+port+"/"+registeredURL

ADD_ON_WEBSITE_UUID = "24920b44-3a8b-486b-a3f9-8f359bd1fbb2";
ADD_ON_WEBSITE_UUID_APP = "7b0a1359-9328-4a6c-a204-0d4a6649a0a2";

session_opts = {
    'session.type': 'file',
    'session.cookie_expires': 3600,
    'session.data_dir': './data',
    'session.auto': True,
    'session.key': 'bpr-session'
}
app = SessionMiddleware(app(), session_opts)

policyCharacters = ["d", "u", "l", "s"]

defaultPolicy = {
	'regex': 'sdul',
	'minlength': 1
}

params, paramsJSON = Util.Params.getJSONParams("bprServer/pc.param")
bprPostURL = "/bprMessage"
bprFinalURL = "/bprDone"
tSokePostURL = "/tSokeMessage"
tSokeFinalURL = "/tSokeDone"

def buildSiteParams(params, s):
	return '{"f": ' + params + ', "postURL": "' + bprPostURL + '", "finalURL": "' + bprFinalURL + '", "regex": "' + s["regex"] + '", "minlength": "' + str(s["minlength"]) + '"}'

@route('/static/:path#.+#', name='static')
def static(path):
    return static_file(path, root='static')

############################
## admin
############################

@route('/')
def index(session=defaultPolicy, params=paramsJSON):
    # save default policy in session
    s = request.environ.get('beaker.session')
    s['regex'] = s.get('regex', defaultPolicy['regex'])
    s['minlength'] = s.get('minlength', defaultPolicy['minlength'])
    print(s['regex'])
    print(s['minlength'])
    s.save()
    policy = {'regex': s['regex'], 'minlength': s['minlength']}

    return template("index.html", session=policy)

@post('/changePolicy')
def changePolicy():
    s = request.environ.get('beaker.session')
    R = request.json.get("R", s['regex'])
    mn = request.json.get("min", s['minlength'])
    
    # check that R contains only valid policy characters
    RR = ''
    for c in R:
        if c in policyCharacters:
            RR = RR + c
    if RR != '':
        s['regex'] = RR
    
    # only allow minimum length of > 0
    if int(mn) > 0:
        s['minlength'] = mn
    
    s.save()

@post(bprPostURL)
def bprPostURL():

    # save session (name, tss)
    s = request.environ.get('beaker.session')
    
    # check if this is a COM or RES message
    if request.json["X"] == "COM":
        s['name'] = request.json["name"]
        s['COM_PoM'] = request.json["COM_PoM"]
        s['COM_PoE'] = request.json["COM_PoE"]
        s['COM_PoS'] = request.json["COM_PoS"]
        s['C'] = request.json["C"]
        s['Cp'] = request.json["Cp"]
        s['v'] = request.json["v"]
    
        #call bprServer to get challenges
        CH = bprServer.pcServer.getChallenge(len(s['C']), int(s['minlength']), params)
        s['CH'] = CH
        s.save()
    
        print("computed challenges, returning ...")
    
        return {"CH": CH}

    elif request.json["X"] == "RES":
#        s['RES_PoM'] = request.json["RES_PoM"]
#        s['RES_PoE'] = request.json["RES_PoE"]
#        s['RES_PoS'] = request.json["RES_PoS"]
        
        srvInput = request.json
        srvInput['v'] = s['v']
        srvInput['C'] = s['C']
        srvInput['Cp'] = s['Cp']
        srvInput['CH_PoM'] = s['CH']['CH_PoM']
        srvInput['CH_PoE'] = s['CH']['CH_PoE']
        srvInput['CH_PoS'] = s['CH']['CH_PoS']
        srvInput['COM_PoM'] = s['COM_PoM']
        srvInput['COM_PoE'] = s['COM_PoE']
        srvInput['COM_PoS'] = s['COM_PoS']
        
        policyString = s['regex']
    
        #call bprServer to get challenges
        verifyResult = bprServer.pcServer.verifyProofs(srvInput, policyString, params)
        s['verifyResult'] = verifyResult
        s.save()
    
        print("done with BPR, store client and return to web app ...")
        
        # store client to mysql
        cnx = mysql.connector.connect(user='root', password='root', host='127.0.0.1', database='pow')
        cursor = cnx.cursor()
        cursor.execute('insert into users (username, hash, salt) values ("'+s["name"]+'", "'+str(s["v"]["H2"])+'", "'+str(s["v"]["H1"])+','+s["v"]["sH"]+'")')
        cnx.commit()
        cnx.close()
        
        # FIXME: delete state
        
        return {"done": verifyResult, "goto": gotoURL}

############################
## client
############################

@route('/client')
def client():
    
    # save default policy in session
    s = request.environ.get('beaker.session')
    s['regex'] = s.get('regex', defaultPolicy['regex'])
    s['minlength'] = s.get('minlength', defaultPolicy['minlength'])
    print(s['regex'])
    print(s['minlength'])
    s.save()
    policy = {'regex': s['regex'], 'minlength': s['minlength']}

		# build params JSON
    siteParams = buildSiteParams(paramsJSON, s)
    return template("client.html", 
       params=siteParams, 
       uuid=ADD_ON_WEBSITE_UUID,
       message="This is the BPR client website. Go ahead and register a new user using the BPR button in the toolbar.")

@route('/client-app')
def client():
    s = request.environ.get('beaker.session')
    return template("client-app.html", params={})

@route('/'+registeredURL)
def client():
    s = request.environ.get('beaker.session')
    return template("client.html", 
      message="Congratulations "+s.get('name')+", you successfully registered.",
      uuid=ADD_ON_WEBSITE_UUID_APP,
      params={})

@post(tSokePostURL)
def tSokePostURL():

    # save session 
    s = request.environ.get('beaker.session')
    
    # check if this is a COM or RES message
    if request.json["M"] == "X":
        s['X'] = request.json["X"]
        s['name'] = request.json["name"]
        print("X: "+str(s['X']))
        print("name: "+s['name'])
    
############################
## run it
############################

run(host=domain, port=int(port), reloader=True, app=app)

