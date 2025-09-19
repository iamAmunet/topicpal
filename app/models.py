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
    __tablename__ = 'research'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    topic = db.Column(db.String(255), nullable=False, default='')
    subtopic = db.Column(db.String(255), nullable=False, default='')
    search_terms = db.Column(db.JSON, nullable=False, default=[])
    scraper_results = db.Column(db.JSON, nullable=False, default={})
    chat_history = db.Column(db.JSON, nullable=False, default=[])
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    session_id = db.Column(db.String(128))
    user = db.relationship('User', backref='research')
    __table_args__ = (
        db.Index('idx_research_user_session_active', 'user_id', 'session_id', 'active'),
    )

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    topic = db.Column(db.String(200), nullable=False, default='')
    subtopic = db.Column(db.String(200), nullable=False, default='')
    search_terms = db.Column(db.JSON, nullable=False, default=[])
    scraper_results = db.Column(db.JSON, nullable=False, default={})
    chat_history = db.Column(db.JSON, nullable=False, default=[])
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index('idx_project_user_id', 'user_id'),
    )

class Note(db.Model):
    __tablename__ = 'note'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(500))
    research_id = db.Column(db.Integer, db.ForeignKey('research.id'))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Blog(db.Model):
    __tablename__ = "blog"
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text)