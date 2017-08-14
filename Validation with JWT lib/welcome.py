# Copyright 2015 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import json
from flask import Flask, jsonify,redirect,request,session,render_template
import requests
from requests.auth import HTTPBasicAuth
WebAppStrategy={}
WebAppStrategy['DEFAULT_SCOPE'] = "appid_default";
WebAppStrategy['ORIGINAL_URL'] = "APPID_ORIGINAL_URL";
WebAppStrategy['AUTH_CONTEXT'] = "APPID_AUTH_CONTEXT";


execfile("modals/serviceConfig.py")
execfile("utils/token-utils.py")


app = Flask(__name__)
# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jm3]LWX/,?RT'# for session
AUTHORIZATION_PATH = "/authorization"
TOKEN_PATH = "/token"
@app.route('/')
def Welcome():
    return app.send_static_file('index.html')
def validateToken(token):
    publickey = retrievePublicKey(ServiceConfig.serverUrl)
    pem = getPublicKeyPem(publickey)
    return verifyToken(token,pem)
#when connecting to protected resource we have few steps need to be done

 #1. Checking if the user already authenticated, after successful authenticationThis code saves the token on the session on APPID_AUTH_CONTEX parameter
 #2. If the user doesn't authenticated or have invalid token, the authorization proccess need to start
 #3. if the token is valid the user can access the protected resource
@app.route('/protected')
def protected():
    tokens = session.get(WebAppStrategy['AUTH_CONTEXT'])
    if (tokens):
        publickey = retrievePublicKey(ServiceConfig.serverUrl)
        pem = getPublicKeyPem(publickey)
        idToken = tokens.get('id_token')
        accessToken = tokens.get('access_token')
        idTokenPayload = verifyToken(idToken,pem)
        accessTokenPayload =verifyToken(accessToken,pem)
        if (not idTokenPayload or not accessTokenPayload):
            session[WebAppStrategy['AUTH_CONTEXT']]=None
            return startAuthorization()
        else:
            print('idTokenPayload')
            print (idTokenPayload)
            return render_template('protected.html', name=idTokenPayload.get('name'),picture=idTokenPayload.get('picture'))
    else:
        return startAuthorization()
#To start the authorization process you need to redirect the user to appid endpoint.
#with the clientid and redirecturi as query parameters.
#when binding appid to your service the global enviorement contains appid credintials which contain the clientid and server url, I've created a class called serviceConfig that read that data, you can use this class or copy this data from the service credintials section in app id dashboard
#after reading the data, redirect the user to appid url with redirecturi to your application and clientid and the login widget will be presented to the user
@app.route('/startAuthorization')
def startAuthorization():
    serviceConfig=ServiceConfig()
    clientId = serviceConfig.clientId

    authorizationEndpoint = serviceConfig.serverUrl + AUTHORIZATION_PATH
    redirectUri = serviceConfig.redirectUri
    return redirect("{}?client_id={}&response_type=code&redirect_uri={}&scope=appid_default".format(authorizationEndpoint,clientId,redirectUri))

@app.route('/afterauth')
def afterauth():
    error = request.args.get('error')
    code = request.args.get('code')
    if error:
        return error
    elif code:
        return handleCallback(code)
    else:
        return '?'


def handleCallback(grantCode):
    tokens=retriveTokens(grantCode)
    if (type(tokens) is str):
        return tokens#it's error
    else:
        if (tokens['access_token']):
            session[WebAppStrategy['AUTH_CONTEXT']]=tokens
            return protected()
        else:
            return 'fail'

def retriveTokens(grantCode):
    serviceConfig=ServiceConfig()
    clientId = serviceConfig.clientId
    secret = serviceConfig.secret
    tokenEndpoint = serviceConfig.serverUrl + TOKEN_PATH
    redirectUri = serviceConfig.redirectUri
#    requests.post(url, data={}, auth=('user', 'pass'))
    r = requests.post(tokenEndpoint, data={"client_id": clientId,"grant_type": "authorization_code","redirect_uri": redirectUri,"code": grantCode
		}, auth=HTTPBasicAuth(clientId, secret))
    print(r.status_code, r.reason)
    if (r.status_code is not 200):
        return 'fail'
    else:
        return r.json()

port = os.getenv('PORT', '5000')
if __name__ == "__main__":
	app.run(host='0.0.0.0', port=int(port))
