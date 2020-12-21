"""Initialize app."""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager



db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    """Construct the core app object."""
    app = Flask(__name__, instance_relative_config=True)
    
    # Configurations 
    app.config.from_object('config')
    app.config.from_pyfile('config.py')

    # Initialize Plugins
    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from .views import auth, routes, oidc_endpoint
        from .oidc import config_oauth
        # Register Blueprints
        app.register_blueprint(auth.auth_bp)
        app.register_blueprint(routes.main_bp)
        app.register_blueprint(oidc_endpoint.oidc_bp)

        # Config oauth app
        config_oauth(app)

        # Create Database Models
        db.create_all()

        return app