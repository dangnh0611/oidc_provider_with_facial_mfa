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

	token_devices = db.relationship('TokenDevice', lazy='select',
        backref=db.backref('user', lazy='select'))

	def set_password(self, password):
		"""Create hashed password."""
		self.password = generate_password_hash(password, method='sha256')

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


class Registration:
	# invalid after 30 minutes
	EXPIRE = 1800

	def __init__(self, code, user_id):
		self.user_id = user_id
		self.code = code
		self.start_at = datetime.now()
		self.success = False

	def get_user_id(self):
		return self.user_id

	def update_metadata(self, metadata):
		self.device_model = metadata['device_model']
		self.device_os = metadata['device_os']

	def is_expired(self):
		now= datetime.now()
		delta = now - self.start_at
		return delta.seconds > self.EXPIRE

	def is_success(self):
		return self.success



class MFARequest:
	# invalid after 30 minutes
	EXPIRE = 1800

	def __init__(self, mfa_code, user_id, next_page):
		self.user_id = user_id
		self.mfa_code = mfa_code
		self.start_at = datetime.now()
		self.success = False
		self.next_page = next_page

	def get_user_id(self):
		return self.user_id

	def is_expired(self):
		now= datetime.now()
		delta = now - self.start_at
		return delta.seconds > self.EXPIRE

	def is_success(self):
		return self.success
	
