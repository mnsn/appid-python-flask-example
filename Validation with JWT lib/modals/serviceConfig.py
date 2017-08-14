class ServiceConfig():
    REDIRECT_URI = "redirectUri"
    def getParamFromVcap(parsedVcap,serviceName,field):
        return parsedVcap.get(serviceName)[0]['credentials'][field]
    def getRedirectUri():
        redirectUri=os.environ.get('REDIRECT_URI')
        if not redirectUri:
            vcapApplication=os.environ.get('VCAP_APPLICATION')
            if vcapApplication:
                vcapApplication=json.loads(vcapApplication)
                redirectUri = "https://{}/afterauth".format(vcapApplication["application_uris"][0]);
            else:
                redirectUri='http://localhost:5000/afterauth'
        return redirectUri
    serverUrl='https://appid-oauth.ng.bluemix.net/oauth/v3/stub'
    VCAP_SERVICES=os.environ.get('VCAP_SERVICES')
    if VCAP_SERVICES:
        parsedVcap = json.loads(VCAP_SERVICES)
        serviceName=None
        if (parsedVcap.get('AdvancedMobileAccess')):
            serviceName='AdvancedMobileAccess'
        elif (parsedVcap.get('AppID')):
            serviceName='AppID'
        if(serviceName):
            serverUrl=getParamFromVcap(parsedVcap,serviceName,'oauthServerUrl')
            secret=getParamFromVcap(parsedVcap,serviceName,'secret')
            clientId=getParamFromVcap(parsedVcap,serviceName,'clientId')
            redirectUri=getRedirectUri()
    if (not serverUrl):
        raise 'please choose server url'


    @property
    def get_clientId(self):
        return 'clientId'

    @property
    def get_secret(self):
        return secret

    @property
    def get_serverUrl(self):
        return serverUrl

    def get_redirectUri(self):
        return redirectUri

    def __repr__(self):
        print ('{} {} {} {} '.format(clientId,secret,tokenEndpoint,redirectUri))
        return '<serviceConfig %r>' % (self.client_id)
