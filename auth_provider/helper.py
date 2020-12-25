from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64
import firebase_admin
from firebase_admin import messaging
from firebase_admin import credentials

cred = credentials.Certificate("instance/donelogin-9f53f-firebase-adminsdk-sxu56-8682d3b594.json")
firebase_admin.initialize_app(cred)


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


def push_fcm_notification(token, title, body, data={}):
    notification = messaging.Notification(title = title, body = body)

    message = messaging.Message(
        notification = notification,
        data=data,
        token=token
    )

    # Send a message to the device corresponding to the provided
    # registration token.
    response = messaging.send(message)
    # Response is a message ID string.
    print('Successfully sent message:', response)