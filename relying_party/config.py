"""App config"""

# SSO Provider Discovery endpoint
DONELOGIN_CONFIG_URL = 'https://localhost:5000/.well-known/openid-configuration'

#
DONELOGIN_CLIENT_KWARGS= {
    'scope': 'openid email preferred_username',
    "token_endpoint_auth_method": "client_secret_post"
}

# CLIENT CREDENTIALS
DONELOGIN_CLIENT_ID = 'client_id'
DONELOGIN_CLIENT_SECRET = 'client_secret'


