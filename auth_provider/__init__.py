"""Initialize app."""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_session import Session
from flask_mail import Mail
import json
from datetime import datetime


db = SQLAlchemy()
login_manager = LoginManager()
sess = Session()
mail = Mail()

def create_app():
    """Construct the core app object."""
    app = Flask(__name__, instance_relative_config=True)
    app.config['SESSION_TYPE']= 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    # Configurations 
    app.config.from_object('config')
    app.config.from_pyfile('config.py')

    # Initialize Plugins
    db.app = app
    db.init_app(app)
    login_manager.init_app(app)
    sess.init_app(app)
    mail.init_app(app)

    with app.app_context():
        from .views import auth, routes, oidc_endpoint
        from .oidc import config_oauth
        from . import cronjob
        # Register Blueprints
        app.register_blueprint(auth.auth_bp)
        app.register_blueprint(routes.main_bp)
        app.register_blueprint(oidc_endpoint.oidc_bp)
        # Config oauth app
        config_oauth(app)

        # Create Database Models
        db.create_all()

        def to_pretty_json(value):
            return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))
        
        def timestamp_to_str(value):
            return datetime.fromtimestamp(value).strftime("%m/%d/%Y, %H:%M:%S")

        app.jinja_env.filters['tojson_pretty'] = to_pretty_json
        app.jinja_env.filters['timestamp_to_str'] = timestamp_to_str 
        return app