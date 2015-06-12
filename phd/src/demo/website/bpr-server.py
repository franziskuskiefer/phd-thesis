#!/usr/bin/python

from bottle import route, run, template, static_file, post, get, request, app, redirect, response
import json
import mysql.connector

from beaker.middleware import SessionMiddleware

import bprServer.Util as Util
import bprServer.bprServer as bprServer
import bprServer.tSokeServer as tSokeServer

# XXX: move this
from charm.toolbox.ecgroup import ZR

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
appURL = "/app"

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
def bprPost():

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
        saltJson = {}
        saltJson["H1"] = s["v"]["H1"]
        saltJson["sH"] = str(s["v"]["sH"])
        cnx = mysql.connector.connect(user='root', password='root', host='127.0.0.1', database='pow')
        cursor = cnx.cursor()
        cursor.execute('insert into users (username, hash, salt) values ("'+s["name"]+'", "'+str(s["v"]["H2"])+'", "'+str(saltJson)+'")')
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

@route('/'+registeredURL)
def client():
    s = request.environ.get('beaker.session')
    return template("client.html", 
      message="Congratulations "+s.get('name')+", you successfully registered.",
      uuid=ADD_ON_WEBSITE_UUID,
      params={})

@route('/client-app')
def client():
    s = request.environ.get('beaker.session')
    return template("client-app.html", 
      params='{"postURL": "'+tSokePostURL+'", "finalURL": "'+tSokeFinalURL+'"}',
      uuid=ADD_ON_WEBSITE_UUID_APP)

# retrieve user from mysql db
def retrieveUser(username):
    cnx = mysql.connector.connect(user='root', password='root', host='127.0.0.1', database='pow')
    cursor = cnx.cursor()
    cursor.execute('select * from users where username="'+username+'"')
    cnx.close()
    
    user = {}
    for (username, hash, salt) in cursor:
        user['username'] = username
        user['hash'] = hash
        user['salt'] = salt
    
    return user

@post(tSokePostURL)
def tSokePost():

    # save session 
    s = request.environ.get('beaker.session')
    
    # check if this is a COM or RES message
    if request.json["M"] == "X":
        s['X'] = request.json["X"]
        s['name'] = request.json["name"]
        
        print("getting verifier for "+s['name'])
        
        user = retrieveUser(s['name'])
        print(user)

        a1, a2, Yast = tSokeServer.tSokeServer.compute(s['X'], params, user['hash'], s['name'])
        s['a1'] = a1
        s['a2'] = a2
        
        return {'Y': Yast, 'salt': user['salt']}
        
    if request.json["M"] == "a1":
        print("got an authentication token, checking ...")
        a1c = request.json["a1"]
        if (a1c != s["a1"]):
            print("tSoke authentication failed :(")
            return {'a2': ''}
        else:
            print("tSoke authentication successful :)")
            
            # store random value to user for app authentication
            secret = str(params[1].random(ZR))
            cnx = mysql.connector.connect(user='root', password='root', host='127.0.0.1', database='pow')
            cursor = cnx.cursor()
            cursor.execute('insert into sessions (username, secret) values ("'+s["name"]+'", "'+secret+'")')
            cnx.commit()
            cnx.close()
            
            s["key"] = secret
            
            # return auth token
            return {'a2': s['a2']}


@post(tSokeFinalURL)
def tSokeDone():
                
    s = request.environ.get('beaker.session')
    print("in tSokeDone")
    print(request.json["done"])
    print(s["name"])
    print(s["key"])
    # this is the final message, a secret
    if request.json['done'] and s["name"] and s["key"]:
          response.status = 303
          response.set_header('Location', appURL)
          return ""
#        return redirect(appURL, code=302)


@route(tSokeFinalURL)
def demoApp():
        
    s = request.environ.get('beaker.session')
    return template("client-app.html",
        params = '',
        user = s.get('name', "Alice"),
        key = s.get('key', "1234567890"))
    
############################
## run it
############################

run(host=domain, port=int(port), reloader=True, app=app)

