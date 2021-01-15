"""Database models."""
from . import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin
)
import json
from datetime import datetime

class User(UserMixin, db.Model):
	"""User account model."""

	__tablename__ = 'user'
	id = db.Column(
		db.Integer,
		primary_key=True
	)
	name = db.Column(
		db.String(100),
		nullable=False,
		unique=False
	)
	email = db.Column(
		db.String(40),
		unique=True,
		nullable=False
	)
	password = db.Column(
		db.String(200),
		primary_key=False,
		unique=False,
		nullable=False
	)
	created_at = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=True
	)
	updated_at = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=True
	)
	last_login = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=True
	)
	mfa = db.Column(
		db.Boolean,
		index = False,
		unique = False,
		nullable = False,
		default = False
	)
	is_confirmed = db.Column(
		db.Boolean,
		index = False,
		unique = False,
		nullable = False,
		default = False
	)

	token_devices = db.relationship('TokenDevice', lazy='select',
        backref=db.backref('user', lazy='select'))

	def set_password(self, password):
		"""Create hashed password."""
		self.password = generate_password_hash(password, method='pbkdf2:sha256:100000', salt_length= 16)

	def check_password(self, password):
		"""Check hashed password."""
		return check_password_hash(self.password, password)

	def get_user_id(self):
		return self.id

	def __repr__(self):
		return self.name
	
	def __str__(self):
		return self.name


class TokenDevice(db.Model):
	__tablename__= "tokendevice"
	id = db.Column(
		db.Integer,
		primary_key=True
	)

	user_id = db.Column(
		db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))

	public_key = db.Column(
		db.String(512),
		primary_key=False,
		unique=False,
		nullable=False
	)
	device_model = db.Column(
		db.String(100),
		nullable=True,
		unique=False
	)

	device_os = db.Column(
		db.String(100),
		nullable=True,
		unique=False
	)
	fcm_token = db.Column(
		db.String(200),
		nullable=False,
		unique=False
	)
	is_active = db.Column(
		db.Boolean,
		index = False,
		unique = False,
		nullable = False,
		default = True
	)
	created_at = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=False
	)
	updated_at = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=True
	)
	last_login = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=False
	)


	def __str__(self):
		return self.name

	def get_id(self):
		return self.id



class OAuth2Client(db.Model, OAuth2ClientMixin):
	__tablename__ = 'oauth2_client'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(
		db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
	user = db.relationship('User')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
	__tablename__ = 'oauth2_code'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(
		db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
	user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
	__tablename__ = 'oauth2_token'

	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(
		db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
	user = db.relationship('User')


class RegistrationRequest(db.Model):
	# invalid after 30 minutes
	EXPIRE = 30
	
	id = db.Column(db.Integer, primary_key=True)

	user_id = db.Column(
		db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))

	private_code = db.Column(
		db.String(48),
		unique=True,
		nullable=False,
		index = True
	)
	
	start_at = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=True
	)

	is_success = db.Column(
		db.Boolean,
		unique = False,
		nullable = False,
		default = True
	)

	metadata_device_model = db.Column(
		db.String(100),
		unique=False,
		nullable= True,
		index = False
	)
	
	metadata_device_os = db.Column(
		db.String(100),
		unique=False,
		nullable= True,
		index = False
	)

	user = db.relationship('User')

	def update_metadata(self, metadata):
		self.metadata_device_model = metadata['device_model']
		self.metadata_device_os = metadata['device_os']

	def check_expired(self):
		now= datetime.now()
		delta = now - self.start_at
		return delta.seconds > self.EXPIRE


class AccessRequest(db.Model):
	# invalid after 5 minutes
	EXPIRE = 30

	id = db.Column(db.Integer, primary_key=True)

	user_id = db.Column(
		db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))

	mfa_code = db.Column(
		db.String(48),
		unique=True,
		nullable=False,
		index = True
	)
	
	start_at = db.Column(
		db.DateTime,
		index=False,
		unique=False,
		nullable=True
	)

	is_success = db.Column(
		db.Boolean,
		unique = False,
		nullable = False,
		default = True
	)

	user = db.relationship('User')

	def check_expired(self):
		now= datetime.now()
		delta = now - self.start_at
		return delta.seconds > self.EXPIRE
	
