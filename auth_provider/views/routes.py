"""Logged-in page routes."""
from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify, flash
from flask_login import current_user, login_required, logout_user
from ..models import OAuth2Client, Registration, TokenDevice, User
from ..forms import CreateClientForm, MFASettingForm
from ..helper import verify_signature
from werkzeug.security import gen_salt
import time
from .. import db
import json
import pyqrcode
import io
from werkzeug.security import gen_salt
from datetime import datetime

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
    user= current_user
    return render_template(
        'dashboard.html',
        title='Dashboard',
        template='dashboard-template',
        user= user,
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
            user= user,
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

    return render_template('clients.html', user = user, clients=clients)

@main_bp.route('/devices', methods=['GET'])
@login_required
def devices():
    user = current_user
    token_devices = user.token_devices
    return render_template('devices.html', user=user, token_devices = token_devices)


@main_bp.route('/qrcode', methods=['GET'])
@login_required
def qrcode():
    global registrations
    user = current_user
    code = gen_salt(48)
    msg = {
        "code": code,
        "user_id": user.get_user_id(),
        "username": user.name,
        "email": user.email,
    }
    session['code']=code
    session.modified = True
    new_regist = Registration(code, current_user.get_user_id())
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
        # check signature
        public_key = data['public_key']
        signed_code = data['code_signature']

        is_valid_signature = verify_signature(public_key, signed_code, code)
        print('VERIFY', is_valid_signature)
        if not is_valid_signature:
            return jsonify({'status': 'fail', 'msg': 'Invalid signature !'})

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
                # main flow, save info to db
                user_id = regist.get_user_id()
                token_device = TokenDevice(user_id = user_id, public_key=data['public_key'] , is_active = True,
                 device_model = data['device_model'] , device_os = data['device_os'], fcm_token = data['fcm_token'],
                  created_at = datetime.now(), updated_at = datetime.now(), last_login = datetime.now())
                db.session.add(token_device)
                db.session.commit()

                regist.update_metadata(data)
                regist.success= True
                return jsonify({'status': 'success', 'device_id': token_device.get_id()})



@main_bp.route('/mfa_setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    print(session)
    form = MFASettingForm()
    user = current_user
    # Validate login attempt
    if form.validate_on_submit():
        if form.mfa.data == user.mfa:
            flash('Nothing changed!')
        if form.mfa.data == False and user.mfa == True:
            user.mfa = False
            db.session.add(user)
            db.session.commit()
            flash('Turned off 2FA successfully !')
        if form.mfa.data ==True and user.mfa == False:
            devices = user.token_devices
            active_devices = [device for device in devices if device.is_active ]
            if len(active_devices)==0:
                flash('Error: You have no active token device. Setup a new device to enable 2FA')
            else:
                user.mfa = True
                db.session.add(user)
                db.session.commit()
                flash('Enabled MFA successfully ! You can now use your token device for 2FA.')
    
    # GET
    form.mfa.default = user.mfa
    form.process()
    return render_template(
        'mfa_setup.html',
        user = user,
        title='MFA Setting',
        form=form,
        template='signup-page',
        body="Sign up for a user account."
    )

            



@main_bp.route("/test")
def test():
    """Test html template"""
    return render_template('dashboard.html', profile={'username': 'Dang Nguyen Hong'})


