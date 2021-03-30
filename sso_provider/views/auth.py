"""Routes for user authentication."""
from flask import redirect, render_template, flash, Blueprint, request, url_for, session, jsonify
from flask_login import current_user, login_user
from ..forms import LoginForm, SignupForm, ReSentEmailConfirmationForm, PasswordResetFirstStepForm, PasswordResetSecondStepForm
from ..models import db, User, AccessRequest, TokenDevice
from ..import login_manager
from werkzeug.security import gen_salt
from ..helper import push_fcm_notification, verify_signature, generate_security_email_token, confirm_security_email_token, send_email
from flask_login import login_required
from datetime import datetime


# Blueprint Configuration
auth_bp = Blueprint(
    'auth_bp', __name__,
    template_folder='templates',
    static_folder='static'
)


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
                email=form.email.data
            )
            user.set_password(form.password.data)
            user.created_at = datetime.now()

            # sent email
            token = generate_security_email_token(user.email, salt = 'confirm_account')
            confirm_url = url_for('auth_bp.confirm_email', token=token, _external=True)
            html = render_template('confirmation_email.html', confirm_url=confirm_url)
            subject = "[DOneLogin] Please confirm your email"
            send_email(user.email, subject, html)

            db.session.add(user)
            db.session.commit()  # Create new user
            session['unconfirmed_user_id'] = user.get_user_id()
            session.modified = True

            return redirect(url_for('auth_bp.confirm_email_warning'))
        else:
            flash('A user already exists with that email address.')
    return render_template(
        'signup.html',
        title='Create an Account.',
        form=form,
        template='signup-page',
        body="Sign up for a user account."
    )


@auth_bp.route('/confirm/<token>', methods = ['GET'])
def confirm_email(token):
    try:
        email = confirm_security_email_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_confirmed:
        flash('Account already confirmed.', 'success')
        return redirect(url_for('auth_bp.login'))
    else:
        user.is_confirmed = True
        user.last_login = datetime.now()
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('main_bp.dashboard'))


@auth_bp.route('/confirm/', methods = ['GET', 'POST'])
def confirm_email_warning():
    if 'unconfirmed_user_id' not in session:
        flash('You must be logged in to view that page.')
        return redirect(url_for('auth_bp.login'))
    
    user = User.query.filter_by(id = session['unconfirmed_user_id']).first_or_404()
    form = ReSentEmailConfirmationForm()
    # if method is POST
    if form.validate_on_submit():
        try:
            # re-sent email confirmation link
            token = generate_security_email_token(user.email, salt = 'confirm_account')
            confirm_url = url_for('auth_bp.confirm_email', token=token, _external=True)
            html = render_template('confirmation_email.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)
            flash("Email re-sent successfully!")
        except:
            flash("An unexpected error occur!")
        return redirect(url_for('auth_bp.confirm_email_warning'))
    # if method is GET
    else:
        if current_user.is_authenticated:
            print('HELLO')
            return redirect(url_for('main_bp.dashboard'))
        else:
            print("GO HERE")
            return render_template(
            'unconfirmed.html',
            title='Confirm your email address.',
            form=form,
            template='signup-page',
            body="Confirm your email address.",
            email = user.email
        )


@auth_bp.route('/reset/<token>', methods = ['GET', 'POST'])
def password_reset(token):
    if current_user.is_authenticated:
        return redirect(url_for('main_bp.dashboard'))
    try:
        email = confirm_security_email_token(token, salt = 'reset_password')
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('auth_bp.password_reset_promt'))
    user = User.query.filter_by(email=email).first_or_404()
    form = PasswordResetSecondStepForm()
    # POST
    if form.validate_on_submit():
        user.set_password(form.password.data)
        # if user choose to reset MFA credentials too
        if form.reset_mfa:
            user.mfa = False
            TokenDevice.query.filter_by(user_id = user.id).delete()
        db.session.add(user)
        db.session.commit()
        flash('Password reset successfully! You can now login with your new password.')
        return redirect(url_for('auth_bp.login'))
    # GET
    else:
        return render_template(
            'password_reset_promt2.html',
            form=form,
            title='Reset password.',
            template='login-page',
            body="Reset your account password."
        )


@auth_bp.route('/password_reset_promt/', methods = ['GET', 'POST'])
def password_reset_promt():
    if current_user.is_authenticated:
        return redirect(url_for('main_bp.dashboard'))
    form = PasswordResetFirstStepForm()
    # if method is POST
    if form.validate_on_submit():
        try:
            email = form.email.data
            user = User.query.filter_by(email = email).first()
            if user is None:
                flash("No account associated with this email!")
            else:
                # re-sent email confirmation link
                token = generate_security_email_token(email = email, salt = 'reset_password')
                password_reset_url = url_for('auth_bp.password_reset', token=token, _external=True)
                html = render_template('password_reset_email.html', confirm_url=password_reset_url)
                subject = "Reset your account password"
                send_email(user.email, subject, html)
                return render_template(
                    'password_reset_warning.html',
                    title='Reset password.',
                    template='signup-page',
                    body="Reset your account password.",
                    email = user.email
                )
        except:
            flash("An unexpected error occur! Please try again.")
        return redirect(url_for('auth_bp.password_reset_promt'))
    # if method is GET
    else:
        return render_template(
        'password_reset_promt1.html',
        title='Reset your password.',
        form=form,
        template='signup-page',
        body="Confirm your email address.",
    )


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Log-in page for registered users.

    GET requests serve Log-in page.
    POST requests validate and redirect user to dashboard.
    """
    # Bypass if user is logged in
    next_page = request.args.get('next')
    print("NEXT", next_page)
    if current_user.is_authenticated:
        return redirect(next_page or url_for('main_bp.dashboard'))

    form = LoginForm()

    if request.method == 'POST':
        # Validate login attempt
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()  
            if user and user.check_password(password=form.password.data):
                if not user.is_confirmed:
                    session['user_id']= user.get_user_id()
                    session.modified = True
                    return redirect(url_for('auth_bp.confirm_email_warning'))

                if not user.mfa:
                    # login user
                    user.last_login = datetime.now()
                    db.session.add(user)
                    db.session.commit()
                    login_user(user)
                    # session.permanent = True
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
                        "request_at": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                        "ip": request.remote_addr, "location": "UNKNOWN"}
                        push_fcm_notification(token= token, title= title, body = body, data= data)
                    print('CREATE MFAREQUEST', next_page)
                    new_access_request = AccessRequest(user_id = user.id, mfa_code = mfa_code, start_at = datetime.now(),
                     is_success= False, ip = request.remote_addr, location = "UNKNOWN")
                    db.session.add(new_access_request)
                    db.session.commit()
                    # update session
                    session['mfa_code'] = mfa_code
                    session.modified = True
                    return redirect(url_for('auth_bp.mfa_face', next = next_page))
            else:
                flash('Invalid username/password combination')
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
    if request.method == 'GET':
        if "mfa_code" not in session:
            return jsonify({"status": "fail", "msg": "Attack detected!"})
        else:
            access_request = AccessRequest.query.filter_by(mfa_code = session['mfa_code']).first()
            if access_request is None:
                next_page = request.args.get('next')
                return redirect(url_for("auth_bp.login", next = next_page ))
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
    access_request = AccessRequest.query.filter_by(mfa_code = mfa_code).first()
    if access_request is None:
        return jsonify({"status": "fail", "msg": "Invalid MFA code !"})
    if access_request.check_expired():
        db.session.delete(access_request)
        db.session.commit()
        return jsonify({"status": "fail", "msg": "Time-out error !"})
    public_key = device.public_key
    signed_code = data['code_signature']
    is_valid_signature = verify_signature(public_key, signed_code, mfa_code)
    print('VERIFY', is_valid_signature)
    if is_valid_signature:
        if data['status']=='success':
            access_request.is_success= True
            device.last_login = datetime.now()
            db.session.add(access_request)
            db.session.add(device)
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            db.session.delete(access_request)
            db.session.commit()
            if 'msg' in data:
                msg = data['msg']
            else:
                msg = "Unexpected Error !"
            return jsonify({'status': 'fail', 'msg': msg})
    else:
        return jsonify({'status': 'fail', 'msg': 'Invalid signature, attack detected !'})
    
    
@auth_bp.route('/login_2fa_status', methods=['GET'])
def login_2fa_status():
    if "mfa_code" not in session:
        return jsonify({"status": "fail", "msg": "Invalid cookies, attack detected!"})
    mfa_code = session['mfa_code']
    access_request = AccessRequest.query.filter_by(mfa_code = mfa_code).first()
    if access_request is None:
        return jsonify({"status": "fail", "msg": "Access request denied !"})
    if access_request.check_expired():
        db.session.delete(access_request)
        db.session.commit()
        return jsonify({"status": "fail", "msg": "Time-out error !"})
    else:
        if access_request.is_success:
            user = access_request.user
            # login user
            user.last_login = datetime.now()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            # session.permanent = True
            del session['mfa_code']
            db.session.delete(access_request)
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'waiting'})


@auth_bp.route('/mfa_requests', methods=['POST'])
def get_mfa_requests():
    data = request.json
    fcm_token = data['fcm_token']
    token_devices = TokenDevice.query.filter_by(fcm_token = fcm_token).all()
    ret=[]
    for device in token_devices:
        device_id = device.id
        user_id = device.user_id
        access_requests = AccessRequest.query.filter_by(user_id = user_id).all()
        for access_request in access_requests:
            ret.append({ "mfa_code": access_request.mfa_code, "device_id": device_id,
                         "request_at": access_request.start_at.strftime("%m/%d/%Y, %H:%M:%S"),
                         "ip": access_request.ip, "location": access_request.location })

    return jsonify({"status": "success", "requests": ret })


@login_manager.user_loader
def load_user(user_id):
    """Check if user is logged-in upon page load."""
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash('You must be logged in to view that page.')
    return redirect(url_for('auth_bp.login', next = request.url))
