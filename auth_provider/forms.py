"""Sign-up & log-in forms."""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional


class SignupForm(FlaskForm):
    """User Sign-up Form."""
    name = StringField(
        'Name',
        validators=[DataRequired()]
    )
    email = StringField(
        'Email',
        validators=[
            Length(min=6),
            Email(message='Enter a valid email.'),
            DataRequired()
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=6, message='Select a stronger password.')
        ]
    )
    confirm = PasswordField(
        'Confirm Your Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.')
        ]
    )

    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """User Log-in Form."""
    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(message='Enter a valid email.')
        ]
    )
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class AuthorizationForm(FlaskForm):
    """Authorization confirmation"""
    confirm= BooleanField(
        label='Allow access',
        description='Allow access' 
    )
    submit=SubmitField('Submit')


class CreateClientForm(FlaskForm):
    """Create Client Form."""
    client_name= StringField(
        'Client Name', 
        validators=[DataRequired()]
        )
    client_uri= StringField(
        'Client URI', 
        validators=[DataRequired()]
        )
    allowed_scope= SelectMultipleField (
        'Allowed Scope', 
        validators=[DataRequired()], choices=[('openid', 'Open ID Connect (openid)'), ('profile', 'Profile (profile)'), ('email', 'Email (email)'), ('phone', 'Phone number (phone)'), ('address', 'Address (address)')]
        )
    redirect_uri=StringField(
        'Redirect URI', 
        validators=[DataRequired()]
        )
    allowed_grant_type=SelectMultipleField(
        'Allowed Grant Type', 
        validators=[DataRequired()],
        choices=[('authorization_code', 'Authorization Code Grant'), ('refresh_token', 'Refresh Token')]
        )
    # Change later
    allowed_response_type=SelectMultipleField(
        'Allowed Response Type',
        validators=[DataRequired()],
        choices=[('code', 'code'),  ('id_token', 'id_token'), ('id_token token', 'id_token token'),
         ('code id_token', 'code id_token'), ('code token', 'code token'), ('code id_token token', 'code id_token token')]
    )
    token_endpoint_auth_method=SelectField(
        'Token Endpoint Authentication Method',
        validators=[DataRequired()], 
        choices=[('none', 'none'), ('client_secret_post', 'client_secret_post'), ('client_secret_basic', 'client_secret_basic')]
    )
    submit = SubmitField('Submit')



class MFASettingForm(FlaskForm):

    mfa = BooleanField(
        'Enable 2FA',
        validators=[],
        default= False
    )
    submit = SubmitField('Submit')