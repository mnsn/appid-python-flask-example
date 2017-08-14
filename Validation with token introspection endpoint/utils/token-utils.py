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


def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)

def getTokenPayload(data):
    payLoad = base64.urlsafe_b64decode(bytes(data.split('.')[1]) + b'==')
    return payLoad

def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))



