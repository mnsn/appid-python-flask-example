from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import struct
import base64
import six
import json
PUBLIC_KEY_PATH = "/publickey";
import urllib2
print("Initializing");
global publicKeyJson
publicKeyJson=None

import jwt

def verifyToken(token,pemVal):
    try:
        payload = jwt.decode(token, pemVal, algorithms=['RS256'],options={'verify_aud':False})
        print('verified')
        return payload
    except:
        print ('not verified')
        return False

def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)

def retrievePublicKey(serverUrl):
  serverUrl = serverUrl + PUBLIC_KEY_PATH;
  content = urllib2.urlopen(serverUrl).read()
  publicKeyJson=content;
  return  publicKeyJson

def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))


def pemFromModExp(modulus,exponent):
    exponentlong = base64_to_long(exponent)
    moduluslong = base64_to_long(modulus)
    numbers = RSAPublicNumbers(exponentlong, moduluslong)
    public_key = numbers.public_key(backend=default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem
def getPublicKeyPem(publicKeyJson=publicKeyJson):
    if(not publicKeyJson):
        publicKeyJson=retrievePublicKey('https://appid-oauth.ng.bluemix.net/oauth/v3/stub')
    parsed = json.loads(publicKeyJson)
    if (publicKeyJson):
        return pemFromModExp(parsed['n'], parsed['e'])
    else:
        print("Public key not found. All requests to protected endpoints will be rejected.")
        return ""
