# IBM appid-python-flask-example
This example is for developers that want to use [IBM App ID](https://console.ng.bluemix.net/docs/services/appid/index.html)  service to protect their python server or create an end-to-end flow of appid authentication with python.


## Choose your protected resource
A protected resource is an endpoint that you want the user to identify before connecting to it, in this example, I called that endpoint `/protected`
```python
from flask import Flask, session,render_template
WebAppStrategy['AUTH_CONTEXT'] = "APPID_AUTH_CONTEXT";
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
```
when connecting to protected resource, there are few steps need to be done, to make sure the user has a valid token:
 1. Checking if the user already authenticated. after successful authentication, this example saves the token on the session in APPID_AUTH_CONTEX parameter
 2. If the user does not authenticate or have an invalid token, the authorization process needs to start.
 3. If the token is valid the user can access the protected resource.

## Authorization proccess
The authorization process is meant to authorize the user, in the end of the process, you can know the user is who he says he is by verifying his token

```python
@app.route('/startAuthorization')
def startAuthorization():
    serviceConfig=ServiceConfig()
    clientId = serviceConfig.clientId

    authorizationEndpoint = serviceConfig.serverUrl + AUTHORIZATION_PATH
    redirectUri = serviceConfig.redirectUri
    return redirect("{}?client_id={}&response_type=code&redirect_uri={}&scope=appid_default".format(authorizationEndpoint,clientId,redirectUri))

```
To start the authorization process, you need to redirect the user to app-id endpoint.
with the client id and redirect URI as query parameters.

when binding appid to your application.
Your application global environment contains appid credentials which contain the client id, server URL and more.
I've created a class called serviceConfig that read that data, you can use this class or copy this data from the service credentials section in the app id dashboard.
after reading the data, redirect the user to appid URL with the redirect URI to your application and your client id, after the redirect the login widget will be presented to the user

## Redirect endpoint
After the user has authorized, s/he will be redirected to your redirect endpoint with either error or code that can replace to the appid id token and access token
```python
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
```
If there was an error (for instance the user decided not to grant access to your app).
 I returned it to the user (in production you probably want to redirect him back to the login screen, or let him continue unauthenticated to unprotected resources, depends on your flow)
if the response contains a code I'll switch it with appid tokens

## replace code with tokens

```python
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

```
to exchange code with an access token and an id token, you need to send a post request to the token endpoint with:
* client_id - You can find it in the service credentials section in your dashboard or just bind your app to appid and serviceConfig class will extract it.
* grunt_type - It always "authorization_code"
* redirect_uri - The redirect URI from the authorization process. this is part of the open-id spec, appid service will validate that redirect URI in the code exchange process.
* code - The code you got after the authorization process.

this endpoint is protected by your client id as the username and your secret as the password.
Both can be found in the service credentials section in appid dashboard or extracted at runtime using ServiceConfig class

If it had no error, the token endpoint return status code 200 and a JSON contains the 2 tokens.
in my code, I saved them on the session and redirected to the protected resource, which validate those tokens and if they are valid shows the page.

## validating the tokens
appid tokens are signed by appid private key to validate them you need to get appid public key and open them. under `token-utils.py' you can see the code I used to open them ,I used pyJWT which is a big library to handle jwt tokens

```python
    import jwt
    PUBLIC_KEY_PATH = "/publickey";
    publickey = retrievePublicKey(ServiceConfig.serverUrl)
    pem = getPublicKeyPem(publickey)
    token = '{{some token}}'
    verifyToken(token,pem)
    def verifyToken(token,pemVal):
        try:
            payload = jwt.decode(token, pemVal, algorithms=['RS256'], options={'verify_aud':False})
            print('verified')
            return payload
     except:
            print ('not verified')
            return False
    def retrievePublicKey(serverUrl):
        serverUrl = serverUrl + PUBLIC_KEY_PATH;
        content = urllib2.urlopen(serverUrl).read()
        publicKeyJson=content;
        return  publicKeyJson
    def getPublicKeyPem(publicKeyJson=publicKeyJson):
        #some code I found in the internet to convert RS256 to pem
```

That's it after finishing this process your website is fully protected by appid.
