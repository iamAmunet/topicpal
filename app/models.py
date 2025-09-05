from . import db
from flask_login import UserMixin
from datetime import datetime, timedelta

class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(100))
    trial_start = db.Column(db.DateTime, default=datetime.utcnow)
    trial_end = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=14))
    tier = db.Column(db.String(10), default='free') 
    projects = db.relationship('Project', backref='user', lazy=True)

    def get_id(self):
        return str(self.user_id)

class Research(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    topic = db.Column(db.String(200))
    subtopic = db.Column(db.String(200))
    search_terms = db.Column(db.JSON)
    scraper_results = db.Column(db.JSON)
    chat_history = db.Column(db.JSON, default=[])  # Store chat as JSON array
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    topic = db.Column(db.String(200))
    subtopic = db.Column(db.String(200))
    search_terms = db.Column(db.JSON)
    scraper_results = db.Column(db.JSON)
    chat_history = db.Column(db.JSON, default=[])  # Copy from Research
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text)
    research_id = db.Column(db.Integer, db.ForeignKey('research.id'), nullable=True)  # Nullable for standalone
    source_tab = db.Column(db.String(50))  # e.g., 'overview', 'keypoints'
    standalone = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)