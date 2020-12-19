"""Logged-in page routes."""
from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify
from flask_login import current_user, login_required, logout_user
from ..models import OAuth2Client, Registration, TokenDevice
from ..forms import CreateClientForm
from werkzeug.security import gen_salt
import time
from .. import db
import json
import pyqrcode
import io
from werkzeug.security import gen_salt


# Blueprint Configuration
main_bp = Blueprint(
    'main_bp', __name__,
    template_folder='templates',
    static_folder='static'
)

global registrations
registrations = {}


@main_bp.route('/', methods=['GET'])
@login_required
def dashboard():    
    """Logged-in User Dashboard."""
    print(current_user.id)
    return render_template(
        'dashboard.html',
        title='Dashboard',
        template='dashboard-template',
        profile={'username': current_user},
        body="You are now logged in!"
    )


@main_bp.route("/logout")
@login_required
def logout():
    """User log-out logic."""
    logout_user()
    return redirect(url_for('auth_bp.login'))

def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

@main_bp.route('/create_client', methods=['GET', 'POST'])
@login_required
def create_client():
    """
    User sign-up page.

    GET requests serve sign-up page.
    POST requests validate form & user creation.
    """
    user=current_user
    form = CreateClientForm()
    if request.method=='POST':
        if form.validate_on_submit():
            client_id = gen_salt(24)
            client = OAuth2Client(client_id=client_id, user_id=user.id)
            print('User ID', user.id)
            # Mixin doesn't set the issue_at date
            client.client_id_issued_at = int(time.time())
            if client.token_endpoint_auth_method == 'none':
                client.client_secret = ''
            else:
                client.client_secret = gen_salt(48)

            client_metadata = {
                "client_name": form.client_name.data,
                "client_uri": form.client_uri.data,
                "grant_types": form.allowed_grant_type.data,
                "redirect_uris": [form.redirect_uri.data],
                "response_types": form.allowed_response_type.data,
                "scope": ' '.join(form.allowed_scope.data),
                "token_endpoint_auth_method": form.token_endpoint_auth_method.data
            }
            print('CLIENT METADATA:', client_metadata)
            client.set_client_metadata(client_metadata)
            db.session.add(client)
            db.session.commit()
            return redirect('/clients')
    else:
        return render_template(
            'create_client.html',
            title='Create a client.',
            form=form,
            profile={'username': current_user},
            template='signup-page',
        )


@main_bp.route('/clients', methods=('GET', 'POST'))
@login_required
def clients():
    user = current_user
    if user:
        print('user:', user)
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []

    return render_template('clients.html', profile={'username': user}, clients=clients)

@main_bp.route('/devices', methods=['GET'])
@login_required
def devices():
    user = current_user
    return render_template('devices.html', profile={'username': user} )


@main_bp.route('/qrcode', methods=['GET'])
@login_required
def qrcode():
    global registrations
    msg={'name':'Nguyen Hong Dang'}
    code = gen_salt(48)
    msg['code'] = code
    session['code']=code
    session.modified = True
    new_regist = Registration(code)
    registrations[code] = new_regist
    print('NEW REGIST: ', code)

    # render QR code
    qr_content = json.dumps(msg)
    url = pyqrcode.create(qr_content)
    stream = io.BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@main_bp.route('/device_registration_status', methods=['GET'])
@login_required
def device_registration_status():
    global registrations
    if 'code' not in session:
        # an attack, log this
        return jsonify({'status': 'fail', 'msg': 'Invalid cookies! Attack detected!'})
    code = session['code']
    if code not in registrations:
        return jsonify({'status': 'fail', 'msg': 'Client send an invalid cookies or a registration timeout occur !'})
    else:
        regist = registrations[code]
        if regist.is_success():
            del registrations[code]
            del session['code']
            return jsonify({'status': 'success',  'device_model': regist.device_model, 'device_os': regist.device_os})
        else:
            return jsonify({'status': 'waiting'})



@main_bp.route('/device_registration', methods=['POST'])
def device_registration():
    global registrations
    data= request.json
    if 'code' not in data:
        return jsonify({'status': 'fail', 'msg': 'No code found !'})
    else:
        code = data['code']
        if code not in registrations:
            # may be an attack, log
            return jsonify({'status': 'fail', 'msg': 'Code is invalid !'})
        else:
            regist = registrations[code]
            if regist.is_success():
                return jsonify({'status': 'fail', 'msg': 'Registration has been success yet !'})
            if regist.is_expired():
                del registrations[code]
                return jsonify({'status': 'fail', 'msg': 'Registration session is expired!'})
            else:
                
                regist.update_metadata(data)
                regist.success= True
                return jsonify({'status': 'success'})


@main_bp.route("/test")
def test():
    """Test html template"""
    return render_template('dashboard.html', profile={'username': 'Dang Nguyen Hong'})


