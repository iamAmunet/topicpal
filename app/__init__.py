import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from datetime import timedelta

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "your-secure-secret-key-1234567890")
    app.permanent_session_lifetime = timedelta(days=1)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///topicpal.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    from .routes import main
    app.register_blueprint(main)

    from .models import User, Project, Note, Research, Blog # Include all models

    with app.app_context():
        
        db.create_all()  # Create new tables

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app