from flask import Flask, url_for, session
from flask import render_template, redirect
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)
app.secret_key = 'a-secret-key'
app.config.from_object('config')

CONF_URL = 'https://192.168.11.2:5000/.well-known/openid-configuration'
oauth = OAuth(app)
oauth.register(
    name='donelogin',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email',
        "token_endpoint_auth_method": "client_secret_post"
    }
)

@app.route('/')
def homepage():
    user = session.get('user')
    return render_template('home.html', user=user)


@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oauth.donelogin.authorize_redirect(redirect_uri)


@app.route('/auth')
def auth():
    token = oauth.donelogin.authorize_access_token()
    print('TOKEN:', token)
    user = oauth.donelogin.parse_id_token(token)
    print('USER', user)
    session['user'] = user
    return redirect('/')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4000, debug=True)