"""Logged-in page routes."""
from flask import Blueprint, render_template, redirect, url_for, request, session, jsonify, flash
from flask_login import current_user, login_required, logout_user
from ..models import OAuth2Client, RegistrationRequest, TokenDevice, User
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
import base64

# Blueprint Configuration
main_bp = Blueprint(
    'main_bp', __name__,
    template_folder='templates',
    static_folder='static'
)


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


@main_bp.route('/profile', methods=['GET'])
@login_required
def profile():    
    """Logged-in User Dashboard."""
    user= current_user
    n_clients = OAuth2Client.query.filter_by(user_id = user.id).count()
    return render_template(
        'profile.html',
        title='Profile',
        template='dashboard-template',
        user= user, n_clients = n_clients,
        body="Your personal profile"
    )

@main_bp.route('/activities/login_history', methods=['GET'])
@login_required
def login_history():    
    """Logged-in User Dashboard."""
    user= current_user
    return render_template(
        'login_history.html',
        title='Login History',
        template='dashboard-template',
        user= user,
        body="Login history"
    )


@main_bp.route("/logout")
@login_required
def logout():
    """User log-out logic."""
    logout_user()
    return redirect(url_for('auth_bp.login'))


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
                "redirect_uris": form.redirect_uri.data.split(),
                "response_types": form.allowed_response_type.data,
                "scope": ' '.join(form.allowed_scope.data),
                "token_endpoint_auth_method": form.token_endpoint_auth_method.data
            }
            print('CLIENT METADATA:', client_metadata)
            client.set_client_metadata(client_metadata)
            db.session.add(client)
            db.session.commit()
            return redirect('/clients')

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

    clients_list = []
    for client in clients:
        clients_list.append([client, {'client_info': client.client_info, 'client_metadata': client.client_metadata}])
    return render_template('clients.html', user = user, clients_list = clients_list)


@main_bp.route('/clients/<client_id>', methods = ['GET', 'DELETE'])
@login_required
def client(client_id):
    user = current_user
    target_client = OAuth2Client.query.filter_by(id = client_id, user_id = user.id).first()
    
    if target_client is None:
        flash('Invalid request!')
        return jsonify({'status': 'fail', 'msg': 'Invalid request!'})
    else:
        db.session.delete(target_client)
        db.session.commit()
        flash(f'Removed {target_client.client_name} ({target_client.client_uri}) !')
        return jsonify({'status': 'success'})


@main_bp.route('/devices', methods=['GET'])
@login_required
def devices():
    user = current_user
    token_devices = user.token_devices
    return render_template('devices.html', user=user, token_devices = token_devices)


@main_bp.route('/devices/<device_id>', methods = ['GET', 'DELETE'])
@login_required
def device(device_id):
    user = current_user
    token_device = None
    for device in user.token_devices:
        if device.id == int(device_id):
            token_device = device
    if token_device is None:
        flash('Invalid request!')
        return jsonify({'status': 'fail', 'msg': 'Invalid request!'})
    elif len(user.token_devices)<=1 and user.mfa:
        flash('You must turn of MFA first since this device is the last associated one with your account.')
        return jsonify({'status': 'fail', 'msg': 'Turn off MFA first!'})
    else:
        db.session.delete(token_device)
        db.session.commit()
        flash(f'Removed {token_device.device_model}!')
        return jsonify({'status': 'success'})


@main_bp.route('/qrcode', methods=['GET'])
@login_required
def qrcode():
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
    new_regist = RegistrationRequest(private_code= code, user_id = current_user.get_user_id(), start_at = datetime.now(), is_success = False)
    db.session.add(new_regist)
    db.session.commit()
    print('NEW REGIST: ', code)

    # render QR code
    content_json = json.dumps(msg)
    qr_content = base64.b64encode(content_json.encode('utf-8'))
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
    if 'code' not in session:
        # an attack, log this
        return jsonify({'status': 'fail', 'msg': 'Invalid cookies! Attack detected!'})
    code = session['code']
    regist = RegistrationRequest.query.filter_by(private_code = code).first()
    if regist is None:
        return jsonify({'status': 'fail', 'msg': 'Registration time-out error !'})
    else:
        if regist.is_success:
            db.session.delete(regist)
            db.session.commit()
            del session['code']
            return jsonify({'status': 'success',  'device_model': regist.metadata_device_model, 'device_os': regist.metadata_device_os})
        else:
            return jsonify({'status': 'waiting'})



@main_bp.route('/device_registration', methods=['POST'])
def device_registration():
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

        regist = RegistrationRequest.query.filter_by(private_code = code).first()
        if regist is None:
            # may be an attack, log
            return jsonify({'status': 'fail', 'msg': 'Code is invalid !'})
        else:
            if regist.is_success:
                return jsonify({'status': 'fail', 'msg': 'Registration has been success yet !'})
            if regist.check_expired():
                db.session.delete(regist)
                db.session.commit()
                return jsonify({'status': 'fail', 'msg': 'Registration session is expired!'})
            else:
                # main flow, save info to db
                user_id = regist.user_id
                token_device = TokenDevice(user_id = user_id, public_key=data['public_key'] , is_active = True,
                 device_model = data['device_model'] , device_os = data['device_os'], fcm_token = data['fcm_token'],
                  created_at = datetime.now(), updated_at = datetime.now(), last_login = datetime.now())
                db.session.add(token_device)
                db.session.commit()

                regist.update_metadata(data)
                regist.is_success= True
                db.session.add(regist)
                db.session.commit()
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
                flash('Error: You have no active token device. Setup a new device to enable 2FA.')
            else:
                user.mfa = True
                user.updated_at = datetime.now()
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


