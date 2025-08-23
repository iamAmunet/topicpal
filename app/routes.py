from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Project
from . import db
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import login_required, current_user
import re

main = Blueprint('main', __name__)

# --- Home Page ---
@main.route('/')
def home():
    # If user is logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('base.html')


# --- Dashboard ---
@main.route('/dashboard')
@login_required
def dashboard():
    projects = Project.query.filter_by(user_id=current_user.user_id).all()
    return render_template("dashboard.html", user=current_user, projects=projects)


# --- Login ---
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('main.login'))

    return render_template('login.html')


# --- Signup ---
@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for('main.signup'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, username=username, password_hash=hashed_pw)

        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for('main.login'))

    return render_template('signup.html')


# --- Logout ---
@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You’ve been logged out.", "info")
    return redirect(url_for('main.home'))

# --- Utilities (temporary "AI" stub for Step 1) ---
def naive_subtopics(topic: str) -> list[str]:
    """
    Very lightweight subtopic generator so Step 1 works without an AI key.
    We'll replace this with a real Grok/OpenAI call in Step 2.
    """
    t = topic.strip()
    if not t:
        return []

    # Seed a few generic angles
    seeds = [
        "Overview & Definitions",
        "History & Background",
        "Key Challenges",
        "Opportunities/Use Cases",
        "Tools & Frameworks",
        "Trends & Future Outlook",
        "Ethics & Risks",
        "Case Studies",
        "Getting Started / How-To"
    ]

    # Try to extract keywords from the topic for a couple of custom items
    words = re.findall(r"[A-Za-z]{3,}", t.lower())
    uniq = list(dict.fromkeys(words))[:3]  # first 3 unique words
    if uniq:
        seeds.insert(0, f"{uniq[0].title()} – Basics")
    if len(uniq) >= 2:
        seeds.insert(1, f"{uniq[0].title()} vs {uniq[1].title()}")
    if len(uniq) >= 3:
        seeds.insert(2, f"Advanced {uniq[2].title()} Topics")

    # Return top 6–7 to keep UI tidy
    return seeds[:7]


# =========================
# STEP 1: Topic -> Subtopics
# =========================
@main.route('/get_subtopics', methods=['POST'])
@login_required
def get_subtopics():
    data = request.get_json(silent=True) or {}
    topic = (data.get('topic') or '').strip()

    if not topic:
        return jsonify({"error": "No topic provided."}), 400

    # (Later) call Grok/OpenAI here. For now, use stub:
    subs = naive_subtopics(topic)

    # Persist topic for this session so later steps can use it
    session['current_topic'] = topic
    session['current_subtopics'] = subs

    return jsonify({"subtopics": subs}), 200

# --------------------------------------------
# Placeholder so your JS `showTab()` doesn't 404
# We'll replace with real content in Step 2/3.
# --------------------------------------------
@main.route('/tab_content/<tab_name>', methods=['GET'])
@login_required
def tab_content(tab_name):
    topic = session.get('current_topic', '(no topic)')
    subtopic = session.get('chosen_subtopic', '(no subtopic)')
    # Temporary placeholder content
    content = (
        f"[Placeholder] Tab: {tab_name}. "
        f"Topic: {topic}. Subtopic: {subtopic or 'not chosen yet'}.\n"
        f"(Real content will appear after we implement Step 2: subtopic selection -> research generation.)"
    )
    return jsonify({"content": content}), 200