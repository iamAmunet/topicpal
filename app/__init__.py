from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from datetime import timedelta
import os

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "your-secure-secret-key-1234567890")
    app.permanent_session_lifetime = timedelta(days=1)
    # Use cockroachdb:// dialect
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'cockroachdb://anthony:up5VK3wUEz4fiA2O_mIcUA@aware-owl-16338.j77.aws-ap-southeast-1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {
            'application_name': 'topicpal',
            'sslmode': 'verify-full',
            'sslrootcert': r'C:\Users\musonda sichilongo\AppData\Roaming\postgresql\root.crt'
        }
    }

    # Flask-Mail config for Gmail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # Initialize extensions
    mail.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    migrate.init_app(app, db)

    # Register blueprints
    from .routes import main
    if 'main' not in app.blueprints:
        app.register_blueprint(main)
        print("Registered main blueprint")

    from .models import User, Project, Note, Research, Blog

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app