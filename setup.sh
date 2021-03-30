# Make instance folder to store private configurations
mkdir instance

# Fill this config file later
echo """
import os


FLASK_ENV='development'
SECRET_KEY=b'enter your secret key here. It should be random generated'
DEBUG= True

# gmail authentication
MAIL_USERNAME = 'your email username'
MAIL_PASSWORD = 'your email password'

# FCM
FCM_CREDENTIALS = os.path.join('instance', 'your_own_fcm_credentials.json')

# Google reCAPCHA v2
RECAPTCHA_PUBLIC_KEY= 'get your own from Google'
RECAPTCHA_PRIVATE_KEY='get your own from Google'
""" > instance/config.py

# generate self-signed ssl certificate
openssl req -x509 -newkey rsa:4096 -nodes -out instance/ssl_cert.pem -keyout instance/ssl_key.pem -days 365

# generate RS256 key
ssh-keygen -t rsa -b 4096 -m PEM -f instance/rs256_jwk.key
# Don't add passphrase
openssl rsa -in instance/rs256_jwk.key -pubout -outform PEM -out instance/rs256_jwk.key.pub

# Allow executable
sudo chmod +x ./run_op.sh
sudo chmod +x ./run_rp.sh