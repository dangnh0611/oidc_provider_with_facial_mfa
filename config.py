FLASK_APP='app2.py'
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

# reCAPCHA v2
RECAPTCHA_USE_SSL= False
RECAPTCHA_OPTIONS = {'theme':'white'}
RECAPTCHA_DATA_ATTRS = {'bind': 'submit-btn', 'callback': 'onSubmitCallback', 'size': 'invisible'}