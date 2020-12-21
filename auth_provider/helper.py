from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64


def verify_signature(base64_public_key, base64_signature, message):
    print('--------------------------------')
    print('PUBLIC KEY: ', base64_public_key)
    print('MESSAGE: ', message)
    print('SIGNATURE: ', base64_signature)
    print('--------------------------------')
    
    formatted_public_key = "-----BEGIN RSA KEY-----\n{}-----END RSA KEY-----".format(base64_public_key)
    rsa_public_key = RSA.importKey(formatted_public_key)
    signature_verifier = PKCS1_v1_5.new(rsa_public_key)
    digest = SHA256.new()
    digest.update(message.encode())

    verified = signature_verifier.verify(digest, base64.b64decode(base64_signature))
    return verified