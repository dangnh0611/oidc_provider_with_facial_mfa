"""Routes for user authentication."""
from flask import redirect, render_template, flash, Blueprint, request, url_for, session
from ..models import db, User
from ..import login_manager
from flask_login import current_user, login_required, logout_user
from flask import render_template, redirect, jsonify
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from ..oidc import authorization, require_oauth
from ..forms import AuthorizationForm


# Blueprint Configuration
oidc_bp = Blueprint(
    'oidc_bp', __name__,
    template_folder='templates',
    static_folder='static'
)


@oidc_bp.route('/oauth2/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    user = current_user
    print('USER', user)
    form= AuthorizationForm()
    
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))
        return render_template('authorization.html',
        form=form,
        template='login-page', user=user,
        grant=grant, scopes=grant.request.scope.split())
    
    if form.validate_on_submit():
        if form.confirm.data:
            print('GOOOOOOOO')
            return authorization.create_authorization_response(grant_user=user)
        else:
            return '<h1>Access rejected! </h1>'

@oidc_bp.route('/oauth2/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@oidc_bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)
