from flask import Flask, url_for, session
from flask import render_template, redirect
from authlib.integrations.flask_client import OAuth
import sys


app = Flask(__name__)
app.secret_key = 'a-secret-key'
app.config.from_object('config')



oauth = OAuth(app)
oauth.register(
    name= 'donelogin',
    server_metadata_url= app.config['DONELOGIN_CONFIG_URL'],
    client_kwargs=app.config['DONELOGIN_CLIENT_KWARGS']
)


@app.route('/')
def homepage():
    user = session.get('user')
    return render_template('home.html', user=user)


@app.route('/login')
def login():
    print(session)
    redirect_uri = url_for('auth', _external=True)
    return oauth.donelogin.authorize_redirect(redirect_uri)


@app.route('/auth')
def auth():
    print(session)
    token = oauth.donelogin.authorize_access_token()
    print('TOKEN:', token)
    id_token_content = oauth.donelogin.parse_id_token(token)
    print('ID Token', id_token_content)
    user_info = oauth.donelogin.userinfo()
    print('USERINFO', user_info)
    user= {}
    user['id_token_content'] = id_token_content
    user['user_info'] = user_info
    session['user'] = user
    return redirect('/')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


if __name__ == "__main__":
    port = int(sys.argv[1])
    app.run(host='0.0.0.0', port= port, debug=True)