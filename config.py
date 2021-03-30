import os
from authlib.jose import JsonWebKey


FLASK_APP='app.py'
FLASK_ENV='production'
SQLALCHEMY_DATABASE_URI='sqlite:///db.sqlite'
SQLALCHEMY_TRACK_MODIFICATIONS=True
WTF_CSRF_ENABLED = True
DEBUG= False


OAUTH2_JWT_ENABLED = True
OAUTH2_JWT_ISS = 'https://donelogin.ai'
OAUTH2_JWT_KEY = 'secret-key'
OAUTH2_JWT_ALG = 'HS256'


PERMANENT_SESSION_LIFETIME = 1800



# mail settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True


# mail accounts
MAIL_DEFAULT_SENDER = ('DOneLogin', 'donelogin.ai@gmail.com')


# Google reCAPCHA v2
RECAPTCHA_USE_SSL= False
RECAPTCHA_OPTIONS = {'theme':'white'}
RECAPTCHA_DATA_ATTRS = {'bind': 'submit-btn', 'callback': 'onSubmitCallback', 'size': 'invisible'}


# SSL cert
SSL_CERT_PATH = os.path.join("instance", "ssl_cert.pem")
SSL_KEY_PATH = os.path.join("instance", "ssl_key.pem")


# JWK & OIDC JWT
RS256_JWK_PUBLIC_PATH = os.path.join("instance", "rs256_jwk.key.pub")
RS256_JWK_PRIVATE_PATH = os.path.join("instance", "rs256_jwk.key")

JWK_PUBLIC_CONFIG = {}
with open(RS256_JWK_PUBLIC_PATH, 'rb') as f:
    key_data = f.read()
    key = JsonWebKey.import_key(key_data, options= {'kty': 'RSA'})
    key_info = key.as_dict()
    key_info.update({'use': 'sig', 'alg': 'RS256', 'kid': 'the-constant-one' })
    JWK_PUBLIC_CONFIG ={
        "keys": [
            key_info
        ]
    }

OIDC_JWT_CONFIG = {}
with open(RS256_JWK_PRIVATE_PATH, 'rb') as f:
    key_data = f.read()
    key = JsonWebKey.import_key(key_data, options= {'kty': 'RSA'})
    key_info = key.as_dict()
    key_info.update({'use': 'sig', 'alg': 'RS256', 'kid': 'the-constant-one' })
    OIDC_JWT_CONFIG = {
        'key': key_info,
        'alg': 'RS256',
        'iss': 'https://donelogin.ai',
        'exp': 3600,
    }



