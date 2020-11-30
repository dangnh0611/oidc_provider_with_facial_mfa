"""Logged-in page routes."""
from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import current_user, login_required, logout_user
from ..models import OAuth2Client
from ..forms import CreateClientForm
from werkzeug.security import gen_salt
import time
from .. import db


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


@main_bp.route("/test")
def test():
    """Test html template"""
    return render_template('dashboard.html', profile={'username': 'Dang Nguyen Hong'})


