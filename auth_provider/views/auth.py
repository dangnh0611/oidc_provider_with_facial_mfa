"""Routes for user authentication."""
from flask import redirect, render_template, flash, Blueprint, request, url_for, session, jsonify
from flask_login import current_user, login_user
from ..forms import LoginForm, SignupForm
from ..models import db, User, MFARequest, TokenDevice
from ..import login_manager
from werkzeug.security import gen_salt
from ..helper import push_fcm_notification, verify_signature
from datetime import datetime


# Blueprint Configuration
auth_bp = Blueprint(
    'auth_bp', __name__,
    template_folder='templates',
    static_folder='static'
)

global mfa_requests
mfa_requests={}

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    User sign-up page.

    GET requests serve sign-up page.
    POST requests validate form & user creation.
    """
    print('SIGNUP', session)
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user is None:
            user = User(
                name=form.name.data,
                email=form.email.data,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()  # Create new user
            login_user(user)  # Log in as newly created user
            return redirect(url_for('main_bp.dashboard'))
        flash('A user already exists with that email address.')
    return render_template(
        'signup.html',
        title='Create an Account.',
        form=form,
        template='signup-page',
        body="Sign up for a user account."
    )


# @auth_bp.route('/login', methods=['GET', 'POST'])
# def login():
#     """
#     Log-in page for registered users.

#     GET requests serve Log-in page.
#     POST requests validate and redirect user to dashboard.
#     """
#     # Bypass if user is logged in
#     print('LOGIN', session, current_user)
#     if current_user.is_authenticated:
#         return redirect(url_for('main_bp.dashboard'))

#     form = LoginForm()
#     # Validate login attempt
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()  
#         if user and user.check_password(password=form.password.data):
#             login_user(user)
#             session.permanent = True
#             next_page = request.args.get('next')
#             return redirect(next_page or url_for('main_bp.dashboard'))
#         flash('Invalid username/password combination')
#         return redirect(url_for('auth_bp.login'))
#     return render_template(
#         'login.html',
#         form=form,
#         title='Log in.',
#         template='login-page',
#         body="Log in with your User account."
#     )


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Log-in page for registered users.

    GET requests serve Log-in page.
    POST requests validate and redirect user to dashboard.
    """
    # Bypass if user is logged in
    global mfa_requests
    next_page = request.args.get('next')
    print("NEXT", next_page)
    if current_user.is_authenticated:
        return redirect(next_page or url_for('main_bp.dashboard'))

    form = LoginForm()
    # Validate login attempt
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()  
        if user and user.check_password(password=form.password.data):
            if not user.mfa:
                login_user(user)
                # session.permanent = True
                print("NEXT", next_page)
                print('REDIRECT TO ', next_page or url_for('main_bp.dashboard'))
                return redirect(next_page or url_for('main_bp.dashboard'))
            # if mfa enable
            else:    
                mfa_code = gen_salt(48)
                print('NEW MFA CODE: ', mfa_code)
                # push notification
                devices = user.token_devices
                title = "DOneLogin MFA Request"
                for device in devices:
                    token = device.fcm_token
                    body = f'Facial authentication request from {user.name}({user.email})'
                    data = { "mfa_code": mfa_code, "type": "faceid", "device_id": str(device.id),
                     "username": user.name, "email": user.email, "request_at": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")}
                    push_fcm_notification(token= token, title= title, body = body, data= data)
                print('CREATE MFAREQUEST', next_page)
                mfa_requests[mfa_code] = MFARequest(mfa_code = mfa_code, user_id = user.id, next_page = next_page)
                # update session
                session['mfa_code'] = mfa_code
                session.modified = True
                return redirect(url_for('auth_bp.mfa_face', next = next_page))
        flash('Invalid username/password combination')
        return redirect(url_for('auth_bp.login'))
    return render_template(
        'login.html',
        form=form,
        next_url = next_page,
        title='Log in.',
        template='login-page',
        body="Log in with your User account."
    )


@auth_bp.route('/login_2fa', methods=['GET', 'POST'])
def mfa_face():
    global mfa_requests
    if request.method == 'GET':
        if "mfa_code" not in session:
            return jsonify({"status": "fail", "msg": "Invalid cookies, maybe an attack detected!"})
        return render_template(
            'mfa_face.html',
            title='Log in.',
            template='login-page',
            body="Log in with your User account."
        )

    # if method is POST
    data= request.json
    print('LOGIN 2FA POST', data )
    mfa_code = data['mfa_code']
    
    device_id = data['device_id']
    device = TokenDevice.query.filter_by(id = device_id).first()
    if device is None:
        return jsonify({"status": "fail", "msg": "Invalid device id !"})
    if mfa_code not in mfa_requests:
        return jsonify({"status": "fail", "msg": "Invalid MFA code !"})
    mfa_request = mfa_requests[mfa_code]
    public_key = device.public_key
    signed_code = data['code_signature']
    is_valid_signature = verify_signature(public_key, signed_code, mfa_code)
    print('VERIFY', is_valid_signature)
    if is_valid_signature:
        if data['status']=='success':
            mfa_request.success= True
            return jsonify({'status': 'success'})
        else:
            del mfa_requests[mfa_code]
            return jsonify({'status': 'fail', 'msg': "Facial recognition failed !"})
    
    
@auth_bp.route('/login_2fa_status', methods=['GET'])
def login_2fa_status():
    global mfa_requests
    if "mfa_code" not in session:
        return jsonify({"status": "fail", "msg": "Invalid cookies, maybe an attack detected!"})
    mfa_code = session['mfa_code']
    if mfa_code not in mfa_requests:
        return jsonify({"status": "fail", "msg": "Attack detected!"})
    else:
        mfa_request = mfa_requests[mfa_code]
        if mfa_request.is_success():
            next_page = mfa_request.next_page
            print('OHHHHHH', next_page)
            user = User.query.filter_by(id = mfa_request.get_user_id()).first() 
            login_user(user)
            # session.permanent = True
            del mfa_requests[mfa_code]
            del session['mfa_code']
            return jsonify({'status': 'success', 'next_page': next_page or url_for('main_bp.dashboard')})
        else:
            return jsonify({'status': 'waiting'})


@auth_bp.route('/mfa_requests', methods=['POST'])
def get_mfa_requests():
    global mfa_requests
    data = request.json
    fcm_token = data['fcm_token']
    token_devices = TokenDevice.query.filter_by(fcm_token = fcm_token).all()
    ret=[]
    for device in token_devices:
        device_id = device.id
        user_id = device.user_id
        user = device.user
        mfa_request_list = [v for (k,v) in mfa_requests.items() if v.user_id == user_id]
        for mfa_request in mfa_request_list:
            ret.append({ "mfa_code": mfa_request.mfa_code, "device_id": device_id,
                         "request_at": mfa_request.start_at.strftime("%m/%d/%Y, %H:%M:%S") })

    return jsonify({"status": "success", "requests": ret })


@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in upon page load."""
    if user_id is not None:
        return User.query.get(user_id)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash('You must be logged in to view that page.')
    return redirect(url_for('auth_bp.login', next = request.url))
