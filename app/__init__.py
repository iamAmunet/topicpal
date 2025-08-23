from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secrekey_is_here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///topicpal.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    # Import routes AFTER db + login_manager are initialized
    from .routes import main
    app.register_blueprint(main)

    # Import User AFTER db.init_app(app) to avoid circular import
    from .models import User

    with app.app_context():
        db.create_all()

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
