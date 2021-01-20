"""Sign-up & log-in forms."""
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, SelectField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, ValidationError

def safe_password_check(min_len = 8):

    def _safe_password_check(form, field):
        password = field.data
        if len(password) < min_len:
            raise ValidationError(f"Password must contain at least {min_len} characters.")
        alpha = False
        digit = False
        other = False
        for c in password:
            if c.isalpha():
                alpha = True
            elif c.isdigit():
                digit = True
            else:
                other = True
        if alpha and digit and other:
            pass
        else:
            raise ValidationError(f"Password must contain both 3 types: alphabet letters (a-z, A-Z), digits (0-9) and special characters. For example: done_login@123")
    
    return _safe_password_check


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
            safe_password_check(min_len=8)
        ]
    )
    confirm = PasswordField(
        'Confirm Your Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.'),
        ]
    )

    recaptcha = RecaptchaField()

    # use variable name except "submit" to intergrate hidden reCAPTCHA
    signup_submit = SubmitField('Register')


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
    recaptcha = RecaptchaField()
    
    # use variable name except "submit" to intergrate hidden reCAPTCHA
    login_submit = SubmitField('Log In')    


class ReSentEmailConfirmationForm(FlaskForm):
    """User Log-in Form."""
    submit = SubmitField(label = 'Re-sent confirmation email', description='Re-sent email confirmation link')


class PasswordResetFirstStepForm(FlaskForm):
    """User Log-in Form."""
    recaptcha = RecaptchaField()

    email = StringField(
        'Email',
        validators=[
            DataRequired(),
            Email(message='Enter a valid email.')
        ]
    )

    password_reset_submit = SubmitField(label = 'Reset password', description='Sent me an email for password reset')


class PasswordResetSecondStepForm(FlaskForm):
    """User Log-in Form."""
    password = PasswordField(
        'New password',
        validators=[
            DataRequired(),
            safe_password_check(min_len=8)
        ]
    )
    confirm = PasswordField(
        'Confirm your new password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.'),
        ]
    )
    reset_mfa = BooleanField(
        'Also reset my MFA setting',
        validators=[],
        default= False
    )
    recaptcha = RecaptchaField()
    password_reset_submit = SubmitField(label = 'Reset password', description='Reset password')


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
    redirect_uri= TextAreaField(
        'Redirect URIs', 
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