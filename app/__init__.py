import os
from flask import Flask
from flask_login import LoginManager
from authlib.integrations.flask_client import OAuth
from pillow_heif import register_heif_opener

from app.config import Config
from app.models import db, User
from app.permissions import register_permissions

# Register HEIC/AVIF opener for Pillow
register_heif_opener()


def create_app():
    """Application factory pattern"""
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config.from_object(Config)

    # Make APPLICATION_NAME available globally in Jinja2 templates
    app.jinja_env.globals['app_name'] = app.config['APPLICATION_NAME']

    # Ensure upload directory exists
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    register_permissions(app)

    # Setup Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, user_id)

    # Setup OAuth
    oauth = OAuth(app)

    # Register blueprints
    from app.blueprints.main import main
    from app.blueprints.auth import auth, init_oauth
    from app.blueprints.teams import teams, teams_public
    from app.blueprints.admin import admin
    from app.blueprints.user import user

    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(teams)
    app.register_blueprint(teams_public)  # Public routes without prefix
    app.register_blueprint(admin)
    app.register_blueprint(user)

    # Initialize OAuth providers
    init_oauth(oauth)

    # Initialize database
    with app.app_context():
        db.create_all()
        print("Database initialized")

    return app