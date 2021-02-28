"""Routes for user authentication."""
from flask import redirect, render_template, flash, Blueprint, request, url_for, session, current_app
from ..models import db, User, AuthorizedClientUser
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


SCOPE2DESCRIPTIONS = {
    'openid': 'Open ID Connect',
    'sub': 'Your user identifier',
    'preferred_username': 'Your user name',
    'email': 'Your email',
    'phone_number': 'Your phone number',
    'address': 'Your address'
}

@oidc_bp.route('/oauth2/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    user = current_user
    form= AuthorizationForm()
    
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))
        client_id = grant.client.id
        authorized_or_not = AuthorizedClientUser.query.filter_by(user_id = user.id, client_id = client_id).first()
        if authorized_or_not is None:
            session['client_id'] = client_id
            session.modified = True
            scopes=grant.request.scope.split()
            scopes = {scope: SCOPE2DESCRIPTIONS[scope] for scope in scopes}
            return render_template('authorization.html',
            form=form,
            template='login-page', user=user,
            grant=grant, scopes = scopes)
        else:
            return authorization.create_authorization_response(grant_user=user)
    
    if form.validate_on_submit():
        if form.confirm.data:
            if 'client_id' in session:
                new_authorized = AuthorizedClientUser(user_id = user.id, client_id = session['client_id'])
                db.session.add(new_authorized)
                db.session.commit()
                del session['client_id']
                return authorization.create_authorization_response(grant_user=user)
        return '<h1>Access rejected! </h1>'


@oidc_bp.route('/oauth2/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()



@oidc_bp.route('/userinfo')
@require_oauth('openid')
def user_info():
    user = current_token.user
    scopes = current_token.scope.split()
    ret= { "sub": user.id}
    if 'preferred_username' in scopes:
        ret['preferred_username'] = user.name
    if 'email' in scopes:
        ret['email'] = user.email
    return jsonify(ret)


# implement later
@oidc_bp.route('/revoke')
def revoke_token():
    return jsonify("No implementation.")


# implement later
@oidc_bp.route('/certs')
def jwk_certs():
    return jsonify(current_app.config['JWK_PUBLIC_CONFIG'])


# Well-known OpenID configuration
# Similar as https://accounts.google.com/.well-known/openid-configuration 
@oidc_bp.route('/.well-known/openid-configuration')
def wellknown_configuration():
    WELL_KNOWN_CONFIG = {
        "issuer": "https://donelogin.ai",
        "authorization_endpoint": url_for('oidc_bp.authorize', _external = True),
        "token_endpoint": url_for('oidc_bp.issue_token', _external= True),
        "userinfo_endpoint": url_for('oidc_bp.user_info', _external = True),
        "revocation_endpoint": url_for('oidc_bp.revoke_token', _external = True) ,
        "jwks_uri": url_for('oidc_bp.jwk_certs', _external = True),
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
        ],
        "id_token_signing_alg_values_supported": [
            "RS256"
        ],
        "scopes_supported": [
            "openid",
            "email",
            "profile"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic"
        ],
        "code_challenge_methods_supported": [
            "plain",
            "S256"
        ],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token"
        ]
    }
    return jsonify(WELL_KNOWN_CONFIG)