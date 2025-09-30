from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Project, Research, Note, Blog, Settings
from . import db
import re
from dotenv import load_dotenv
import os
import json
import requests
from .scrapper import free_scraper
from .scrapper2 import tavily_enhanced_scraper
from .config import GROQ_API_KEY, GROQ_ENDPOINT
from .ai_utils import generate_keypoints, generate_deep_dive, generate_sources, generate_summary
from datetime import timedelta, datetime
from flask_login import login_user, current_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from . import db, mail
import uuid


load_dotenv()

main = Blueprint('main', __name__)
s = URLSafeTimedSerializer(os.getenv('FLASK_SECRET_KEY', 'your-secure-secret-key-1234567890'))

@main.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('base.html')

@main.route('/pricing')
def pricing():
    return render_template('pricing.html')

@main.route('/blog')
def blog():
    contents = Blog.query.all()
    print(f"Contents: {[c.id for c in contents]}")
    return render_template('blog.html', contents=contents)

@main.route('/load_contents/<int:content_id>', methods=['GET'])
def load_contents(content_id):
    try:
        content = Blog.query.get(content_id)
        if not content:
            return jsonify({'error': 'Content not found'}), 404
        return jsonify({
            'title': content.title,
            'content': content.content
        })
    except Exception as e:
        print(f"Error loading content {content_id}: {e}")
        return jsonify({'error': 'Server error'}), 500

@main.route('/about')
def about():
    return render_template('about.html')

@main.route('/setting')
def setting():
    return render_template('setting.html')

@main.route('/get_settings', methods=['GET'])
@login_required
def get_settings():
    try:
        settings = Settings.query.filter_by(user_id=current_user.user_id).first()
        if not settings:
            # Return default settings if none exist
            return jsonify({
                'theme_color': 'light',
                'notifications': False,
                'default_view': 'chat'
            }), 200
        return jsonify({
            'theme_color': settings.theme_color,
            'notifications': settings.notifications,
            'default_view': settings.default_view
        }), 200
    except Exception as e:
        print(f"Error fetching settings for user {current_user.user_id}: {str(e)}")
        return jsonify({'error': f"Failed to fetch settings: {str(e)}"}), 500

@main.route('/save_settings', methods=['POST'])
@login_required
def save_settings():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        theme_color = data.get('theme_color', 'light')
        notifications = data.get('notifications', False)
        default_view = data.get('default_view', 'chat')

        # Validate inputs
        valid_themes = ['light', 'dark', 'blue']
        valid_views = ['chat', 'form']
        if theme_color not in valid_themes or default_view not in valid_views:
            return jsonify({'error': 'Invalid theme or view'}), 400

        # Check if settings exist
        settings = Settings.query.filter_by(user_id=current_user.user_id).first()
        if settings:
            # Update existing settings
            settings.theme_color = theme_color
            settings.notifications = notifications
            settings.default_view = default_view
        else:
            # Create new settings
            settings = Settings(
                user_id=current_user.user_id,
                theme_color=theme_color,
                notifications=notifications,
                default_view=default_view
            )
            db.session.add(settings)

        db.session.commit()
        print(f"Saved settings for user {current_user.user_id}: {theme_color}, {notifications}, {default_view}")
        return jsonify({'message': 'Settings saved successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error saving settings for user {current_user.user_id}: {str(e)}")
        return jsonify({'error': f"Failed to save settings: {str(e)}"}), 500



@main.route('/profile')
@login_required
def profile():
    settings = Settings.query.filter_by(user_id=current_user.user_id).first()
    theme_color = settings.theme_color if settings else 'light'
    return render_template('profile.html', user=current_user, theme_color=theme_color)

@main.route('/new_research')
@login_required
def new_research():
    try:
        # Generate a new session_id
        session_id = os.urandom(16).hex()
        session['session_id'] = session_id
        session['current_topic'] = ''
        session['chosen_subtopic'] = {'research_id': None, 'subtopic': ''}
        session['scraping'] = False
        session.permanent = True
        session.modified = True

        # Deactivate all existing active research sessions for the user
        Research.query.filter_by(user_id=current_user.user_id, active=True).update({'active': False})
        db.session.commit()

        return render_template("dashboard.html", user=current_user)

    except Exception as e:
        db.session.rollback()
        print(f"Error starting new research: {str(e)}")
        return jsonify({'error': f"Failed to start new research: {str(e)}"}), 500
        

@main.route('/dashboard')
@login_required
def dashboard():
    # Check for stale session (older than 1 hour)
    session_timestamp = session.get('last_active')
    if session_timestamp:
        last_active = datetime.fromisoformat(session_timestamp)
        if datetime.utcnow() - last_active > timedelta(hours=1):
            print("Stale session detected, clearing.")
            session.pop('chosen_subtopic', None)
            session.pop('current_topic', None)
            session.pop('scraping', None)
            session.pop('last_active', None)
            session.pop('session_id', None)  # Clear session_id
            session.modified = True

    # Set session_id if not present
    if not session.get('session_id'):
        session['session_id'] = os.urandom(16).hex()  # Generate unique session_id
        session.permanent = True
        session.modified = True

    # Update session timestamp
    session['last_active'] = datetime.utcnow().isoformat()

    # Clear invalid session data
    if session.get('chosen_subtopic', {}).get('research_id'):
        research = Research.query.get(session['chosen_subtopic']['research_id'])
        if not research or research.user_id != current_user.user_id or not research.active or research.session_id != session['session_id']:
            print(f"Invalid or inactive research_id {session['chosen_subtopic']['research_id']} for user {current_user.user_id} or session {session['session_id']}, clearing.")
            session.pop('chosen_subtopic', None)
            session.pop('current_topic', None)
            session.modified = True

    # Load latest active research for the current session
    latest_research = Research.query.filter_by(user_id=current_user.user_id, session_id=session['session_id'], active=True).order_by(Research.created_at.desc()).first()
    if latest_research and not session.get('chosen_subtopic'):
        session['chosen_subtopic'] = {
            'subtopic': latest_research.subtopic or '',
            'research_id': latest_research.id
        }
        session['current_topic'] = latest_research.topic or ''
        session['scraping'] = False
        session.permanent = True
        session.modified = True
        print(f"Loaded Research ID {latest_research.id}, Topic: {latest_research.topic}, Subtopic: {latest_research.subtopic}, Scraper Results: {bool(latest_research.scraper_results)}")

    projects = Project.query.filter_by(user_id=current_user.user_id).order_by(Project.created_at.desc()).all()
    print(f"Current user: {current_user.user_id}, Session: {dict(session)}, Projects: {[p.id for p in projects]}")
    settings = Settings.query.filter_by(user_id=current_user.user_id).first()
    theme_color = settings.theme_color if settings else 'light'
    default_view = settings.default_view if settings else 'chat'
    return render_template("dashboard.html", user=current_user, projects=projects, theme_color=theme_color, default_view=default_view)

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


@main.route('/forgot_password', methods=['POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()
    
    if user:
        token = s.dumps(email, salt='password-reset-salt')
        reset_url = url_for('main.reset_password', token=token, _external=True)
        msg = Message(
            subject='Topicpal Password Reset',
            recipients=[email],
            body=f'Click this link to reset your password: {reset_url}\nThis link expires in 1 hour.'
        )
        try:
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'success')
        except Exception as e:
            flash('Error sending email. Please try again later.', 'danger')
            print(f"Mail error: {e}")
    else:
        flash('No account found with that email.', 'danger')
    
    return redirect(url_for('main.login'))


@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1-hour expiry
    except SignatureExpired:
        flash('The reset link has expired.', 'danger')
        return redirect(url_for('main.login'))
    except:
        flash('Invalid reset link.', 'danger')
        return redirect(url_for('main.login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_password.html')
        
        user = User.query.filter_by(email=email).first()
        if user:
            user.password_hash = generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated! Please log in.', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('main.login'))
    
    return render_template('reset_password.html')


@main.route('/google-login', methods=['POST'])
def google_login():
    if current_user.is_authenticated:
        return jsonify({'success': False, 'error': 'Already logged in'})
    
    token = request.json.get('token')
    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            '238751018517-0b4hj9qn3j5k9q74180f7siq8b295ing.apps.googleusercontent.com'  # Replace with your Client ID
        )
        email = idinfo['email']
        name = idinfo.get('name', '')
        
        user = User.query.filter_by(email=email).first()
        if not user:
            random_password = str(uuid.uuid4())
            user = User(
                email=email,
                username=name or email.split('@')[0],
                password_hash=generate_password_hash(random_password),
                trial_start=datetime.utcnow(),
                trial_end=datetime.utcnow() + timedelta(days=14),
                tier='free',
                scraper_contraints=10,
                bookmark_contraints=40
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash('Logged in with Google successfully!', 'success')
        return jsonify({'success': True, 'redirect': url_for('main.dashboard')})
    
    except ValueError as e:
        return jsonify({'success': False, 'error': 'Invalid Google token'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


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
        new_user = User(email=email, username=username, password_hash=hashed_pw, tier='free')
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for('main.login'))
    return render_template('signup.html')

@main.route('/logout')
@login_required
def logout():
    # Mark all active research records as inactive
    Research.query.filter_by(user_id=current_user.user_id, active=True).update({'active': False})
    db.session.commit()
    # Clear session and log out
    session.clear()
    logout_user()
    flash("You’ve been logged out.", "info")
    return redirect(url_for('main.home'))

from sqlalchemy import inspect
from sqlalchemy.orm import attributes

@main.route('/get_subtopics', methods=['POST'])
@login_required
def get_subtopics():
    data = request.get_json()
    topic = data.get('topic', '').strip()
    if not topic:
        print("Error: No topic provided.")
        return jsonify({"error": "No topic provided."}), 400

    print(f"Received topic: {topic}")

    # Ensure session_id is set
    if not session.get('session_id'):
        session['session_id'] = os.urandom(16).hex()
        session.permanent = True
        session.modified = True

    # Check for existing active research with the same topic and session_id
    research = Research.query.filter_by(
        user_id=current_user.user_id,
        topic=topic,
        session_id=session['session_id'],
        active=True
    ).order_by(Research.created_at.desc()).first()

    if not research:
        # Deactivate old active research records in this session
        Research.query.filter_by(user_id=current_user.user_id, session_id=session['session_id'], active=True).update({'active': False})
        db.session.commit()
        # Create new research record
        research = Research(
            user_id=current_user.user_id,
            topic=topic,
            chat_history=[{"role": "user", "content": topic, "timestamp": datetime.utcnow().isoformat()}],
            active=True,
            session_id=session['session_id']
        )
        db.session.add(research)
    else:
        # Append user message to existing research
        research.chat_history = research.chat_history or []
        research.chat_history.append({"role": "user", "content": topic, "timestamp": datetime.utcnow().isoformat()})
        attributes.flag_modified(research, "chat_history")
        db.session.add(research)

    try:
        db.session.flush()
        db.session.commit()
        research = Research.query.get(research.id)
        print(f"Saved user topic to Research ID {research.id}: {json.dumps(research.chat_history, indent=2)}")
    except Exception as e:
        db.session.rollback()
        print(f"Error saving user topic: {str(e)}")
        return jsonify({"error": f"Failed to save topic: {str(e)}"}), 500

    prompt = f"""
    Generate exactly 3-5 specific subtopics for research on the topic '{topic}'.
    For each subtopic, generate 3-4 relevant search terms (keywords for web scraping).
    Respond ONLY in this exact format, with one line per subtopic:
    - Subtopic Name: search_term1, search_term2, search_term3, search_term4
    Example:
    - History of Coca-Cola: coca-cola history, coca-cola invention, coca-cola timeline
    - Marketing Strategies: coca-cola marketing, coca-cola advertising, coca-cola campaigns
    Do not add extra text or explanations.
    """

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 400,
        "temperature": 0.3
    }

    try:
        print(f"Sending request to Groq with prompt: {prompt[:200]}...")
        response = requests.post(GROQ_ENDPOINT, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        ai_response = response.json()
        print(f"Full API response: {json.dumps(ai_response, indent=2)}")

        if 'choices' not in ai_response or not ai_response['choices']:
            print("Error: No choices in API response.")
            raise ValueError("No choices in response")

        ai_output = ai_response["choices"][0]["message"]["content"].strip()
        print(f"AI output content: {ai_output}")

        subtopics = []
        search_terms = {}
        lines = ai_output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('- '):
                parts = line[2:].split(': ', 1)
                if len(parts) == 2:
                    subtopic = parts[0].strip()
                    terms_str = parts[1].strip()
                    terms = [t.strip() for t in terms_str.split(',') if t.strip()]
                    if subtopic and terms:
                        subtopics.append(subtopic)
                        search_terms[subtopic] = terms
            elif line.startswith('1.') or line.startswith('2.') or line.startswith('3.'):
                parts = line.split(': ', 1)
                if len(parts) == 2:
                    subtopic = parts[0].strip()
                    terms_str = parts[1].strip()
                    terms = [t.strip() for t in terms_str.split(',') if t.strip()]
                    if subtopic and terms:
                        subtopics.append(subtopic)
                        search_terms[subtopic] = terms
            elif ':' in line and 'search' in line.lower():
                parts = line.split(': ', 1)
                if len(parts) == 2:
                    subtopic = parts[0].strip()
                    terms_str = parts[1].strip()
                    terms = [t.strip() for t in terms_str.split(',') if t.strip()]
                    if subtopic and terms:
                        subtopics.append(subtopic)
                        search_terms[subtopic] = terms

        if not subtopics:
            print("Parsing failed, using fallback naive subtopics.")
            result = naive_subtopics(topic)
        else:
            result = {"subtopics": subtopics, "search_terms": search_terms}

        # Add bot response with subtopics to chat history
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        attributes.flag_modified(research, "chat_history")
        db.session.add(research)
        print(f"Before commit, chat_history: {json.dumps(research.chat_history, indent=2)}")
        try:
            db.session.flush()
            db.session.commit()
            research = Research.query.get(research.id)
            print(f"After commit, Research ID {research.id} chat_history: {json.dumps(research.chat_history, indent=2)}")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing bot subtopics: {str(e)}")
            return jsonify({"error": f"Failed to save subtopics: {str(e)}"}), 500

        session['current_topic'] = topic
        session['chosen_subtopic'] = {'subtopic': '', 'research_id': research.id}
        session.permanent = True
        session.modified = True
        print(f"Final subtopics: {subtopics}")
        return jsonify({
            "subtopics": result["subtopics"],
            "search_terms": result["search_terms"],
            "research_id": str(research.id)
        })

    except requests.exceptions.Timeout:
        print("Timeout error: Groq API timed out.")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        attributes.flag_modified(research, "chat_history")
        db.session.add(research)
        print(f"Before commit (fallback), chat_history: {json.dumps(research.chat_history, indent=2)}")
        try:
            db.session.flush()
            db.session.commit()
            research = Research.query.get(research.id)
            print(f"After commit (fallback), Research ID {research.id} chat_history: {json.dumps(research.chat_history, indent=2)}")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing fallback bot subtopics: {str(e)}")
            return jsonify({"error": f"Failed to save subtopics: {str(e)}"}), 500
        return jsonify({
            "subtopics": result["subtopics"],
            "search_terms": result["search_terms"],
            "research_id": str(research.id)
        }), 500
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e.response.status_code} - {e.response.text}")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        attributes.flag_modified(research, "chat_history")
        db.session.add(research)
        print(f"Before commit (fallback), chat_history: {json.dumps(research.chat_history, indent=2)}")
        try:
            db.session.flush()
            db.session.commit()
            research = Research.query.get(research.id)
            print(f"After commit (fallback), Research ID {research.id} chat_history: {json.dumps(research.chat_history, indent=2)}")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing fallback bot subtopics: {str(e)}")
            return jsonify({"error": f"Failed to save subtopics: {str(e)}"}), 500
        return jsonify({
            "subtopics": result["subtopics"],
            "search_terms": result["search_terms"],
            "research_id": str(research.id)
        }), 500
    except KeyError as e:
        print(f"Key error in response: {e}")
        print(f"Response keys: {ai_response.keys() if 'ai_response' in locals() else 'No response'}")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        attributes.flag_modified(research, "chat_history")
        db.session.add(research)
        print(f"Before commit (fallback), chat_history: {json.dumps(research.chat_history, indent=2)}")
        try:
            db.session.flush()
            db.session.commit()
            research = Research.query.get(research.id)
            print(f"After commit (fallback), Research ID {research.id} chat_history: {json.dumps(research.chat_history, indent=2)}")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing fallback bot subtopics: {str(e)}")
            return jsonify({"error": f"Failed to save subtopics: {str(e)}"}), 500
        return jsonify({
            "subtopics": result["subtopics"],
            "search_terms": result["search_terms"],
            "research_id": str(research.id)
        }), 500
    except Exception as e:
        print(f"Grok API error: {e}")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        attributes.flag_modified(research, "chat_history")
        db.session.add(research)
        print(f"Before commit (fallback), chat_history: {json.dumps(research.chat_history, indent=2)}")
        try:
            db.session.flush()
            db.session.commit()
            research = Research.query.get(research.id)
            print(f"After commit (fallback), Research ID {research.id} chat_history: {json.dumps(research.chat_history, indent=2)}")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing fallback bot subtopics: {str(e)}")
            return jsonify({"error": f"Failed to save subtopics: {str(e)}"}), 500
        return jsonify({
            "subtopics": result["subtopics"],
            "search_terms": result["search_terms"],
            "research_id": str(research.id)
        }), 500

def naive_subtopics(topic: str) -> dict:
    """Fallback subtopic generator without AI."""
    words = topic.lower().split()
    base_subtopics = [
        f"{words[0].title()} History and Background",
        f"Key Developments in {words[0].title()}",
        f"Current Trends in {words[0].title()}",
        f"Future Outlook for {words[0].title()}"
    ]
    search_terms = {}
    for sub in base_subtopics[:4]:
        terms = [sub.lower(), f"{sub.lower()} guide", f"{sub.lower()} timeline"]
        search_terms[sub] = terms
    return {"subtopics": base_subtopics, "search_terms": search_terms}

@main.route('/remember_subtopic', methods=['POST'])
@login_required
def remember_subtopic():
    data = request.get_json()
    subtopic = data.get('subtopic', '')
    search_terms = data.get('search_terms', [])
    if not subtopic or not search_terms:
        return jsonify({"error": "Missing subtopic or search terms."}), 400

    try:
        research = Research.query.filter_by(user_id=current_user.user_id, active=True).order_by(Research.created_at.desc()).first()
        if not research:
            research = Research(
                user_id=current_user.user_id,
                topic=session.get('current_topic', ''),
                subtopic=subtopic,
                search_terms=search_terms,
                chat_history=[{"role": "bot", "content": f"Selected subtopic: {subtopic}", "timestamp": datetime.utcnow().isoformat()}],
                active=True
            )
            db.session.add(research)
        else:
            research.subtopic = subtopic
            research.search_terms = search_terms
            research.chat_history = research.chat_history or []
            research.chat_history.append({"role": "bot", "content": f"Selected subtopic: {subtopic}", "timestamp": datetime.utcnow().isoformat()})
        db.session.commit()

        session['chosen_subtopic'] = {'subtopic': subtopic, 'research_id': research.id}
        session.modified = True
        print(f"Updated Research ID {research.id} with subtopic '{subtopic}'")
        return jsonify({"message": "Subtopic saved", "research_id": str(research.id)})
    except Exception as e:
        print(f"Error saving subtopic: {e}")
        return jsonify({"error": str(e)}), 500


@main.route('/run_scraper', methods=['POST'])
@login_required
def run_scraper():
    data = request.get_json()
    search_terms = data.get('search_terms', [])
    subtopic = data.get('subtopic', '')
    print(f"run_scraper received: subtopic={subtopic}, search_terms={search_terms}")

    if not search_terms:
        print("Error: No search terms provided.")
        return jsonify({"error": "No search terms provided."}), 400

    session['scraping'] = True
    session.permanent = True
    session.modified = True

    try:
        if current_user.tier == "basic" or current_user.tier == "unlimited":
            print("running paid scraper.....")
            scraped_results = tavily_enhanced_scraper(search_terms)

        else:
            if current_user.scraper_contraints > 0:
                print("running free scraper.....")
                scraped_results = free_scraper(tuple(search_terms))
                current_user.scraper_contraints = current_user.scraper_contraints - 1
                db.session.commit()
            else:
                print("limit reached upgrade to scrape more data")
                return jsonify({"message": "limit reached upgrade!", "Status": "limit reached, upgrade"})
        
        print(f"Scraper raw results: {json.dumps(scraped_results, indent=2)}")

        if not scraped_results or not any(scraped_results.values()):
            print("Scraper returned empty results, trying fallback terms")
            fallback_terms = [f"{subtopic.lower()} overview", f"{subtopic.lower()} guide", f"{subtopic.lower()} history"]
            scraped_results = free_scraper(tuple(fallback_terms))
            print(f"Fallback scraper results: {json.dumps(scraped_results, indent=2)}")

        flat_results = [
            {**item, 'source': source}
            for query_results in scraped_results.values()
            for source, source_results in query_results.items()
            for item in source_results
        ]

        research = Research.query.filter_by(user_id=current_user.user_id, subtopic=subtopic, active=True).order_by(Research.created_at.desc()).first()
        if not research:
            print("Creating new Research record")
            research = Research(
                user_id=current_user.user_id,
                topic=session.get('current_topic', ''),
                subtopic=subtopic,
                search_terms=search_terms,
                chat_history=[{"role": "bot", "content": f"Data scraped for \"{subtopic}\". View scraped data", "timestamp": datetime.utcnow().isoformat()}],
                active=True
            )
            db.session.add(research)
        else:
            research.scraper_results = scraped_results
            research.chat_history = research.chat_history or []
            research.chat_history.append({"role": "bot", "content": f"Data scraped for \"{subtopic}\". View scraped data", "timestamp": datetime.utcnow().isoformat()})
        research.scraper_results = scraped_results
        db.session.commit()

        session['chosen_subtopic'] = {'subtopic': subtopic, 'research_id': research.id}
        session['scraping'] = False
        session.permanent = True
        session.modified = True
        print(f"Session updated: chosen_subtopic={session.get('chosen_subtopic')}, scraper_results_exists={bool(flat_results)}")

        if not flat_results:
            print("Warning: No scraper results after fallback.")
            return jsonify({"error": "No results found after scraping. Try different search terms."}), 404

        return jsonify({"message": "Scraping completed", "results": scraped_results})
    except Exception as e:
        session['scraping'] = False
        session.permanent = True
        session.modified = True
        print(f"Scraper error: {e}")
        return jsonify({"error": f"Scraper failed: {str(e)}"}), 500

@main.route('/save_chat_history', methods=['POST'])
@login_required
def save_chat_history():
    data = request.get_json()
    chat_history = data.get('chat_history', [])
    if not chat_history:
        return jsonify({"error": "No chat history provided."}), 400

    try:
        research = Research.query.filter_by(user_id=current_user.user_id, active=True).order_by(Research.created_at.desc()).first()
        if not research:
            return jsonify({"error": "No active research found."}), 404

        research.chat_history = chat_history
        db.session.commit()
        print(f"Saved chat history to Research ID {research.id}")
        return jsonify({"message": "Chat history saved"})
    except Exception as e:
        print(f"Error saving chat history: {e}")
        return jsonify({"error": str(e)}), 500

@main.route('/get_session_data')
@login_required
def get_session_data():
    data = {
        'current_topic': session.get('current_topic', ''),
        'chosen_subtopic': session.get('chosen_subtopic', {})
    }
    print(f"Returning session data: {json.dumps(data, indent=2)}")
    return jsonify(data)


@main.route('/get_research/<int:research_id>')
@login_required
def get_research(research_id):
    try:
        research = Research.query.filter_by(id=research_id, user_id=current_user.user_id).first()
        if not research:
            print(f"Research ID {research_id} not found for user {current_user.user_id}")
            return jsonify({"error": "Research not found."}), 404

        session_id = research.session_id
        if not session_id:
            # Legacy records without session_id, return single record
            data = {
                'topic': str(research.topic),
                'subtopic': research.subtopic,
                'scraper_results': research.scraper_results if research.scraper_results else None,
                'chat_history': research.chat_history if research.chat_history else []
            }
            print(f"Returning single research data for ID {research_id}: {json.dumps(data, indent=2)}")
            return jsonify(data)

        # Fetch all research records in the same session
        researches = Research.query.filter_by(
            user_id=current_user.user_id,
            session_id=session_id
        ).order_by(Research.created_at.asc()).all()

        # Aggregate chat_history
        aggregated_chat_history = []
        for r in researches:
            if r.chat_history:
                aggregated_chat_history.extend(r.chat_history)

        # Sort chat_history by timestamp
        aggregated_chat_history.sort(key=lambda x: x['timestamp'])

        data = {
            'topic': research.topic,
            'subtopic': research.subtopic,
            'scraper_results': research.scraper_results if research.scraper_results else None,
            'chat_history': aggregated_chat_history
        }
        print(f"Returning aggregated research data for ID {research_id} in session {session_id}: {json.dumps(data, indent=2)}")
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching research {research_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500


@main.route('/get_latest_research', methods=['GET'])
@login_required
def get_latest_research():
    try:
        session_id = session.get('session_id')
        if not session_id:
            print(f"No session_id for user {current_user.user_id}")
            return jsonify({}), 200

        # Fetch all research records in the current session
        researches = Research.query.filter_by(
            user_id=current_user.user_id,
            session_id=session_id
        ).order_by(Research.created_at.asc()).all()

        if not researches:
            print(f"No research records for user {current_user.user_id} in session {session_id}")
            return jsonify({}), 200

        # Aggregate chat_history from all records
        aggregated_chat_history = []
        latest_research = researches[-1]  # Latest record for metadata
        for research in researches:
            if research.chat_history:
                aggregated_chat_history.extend(research.chat_history)

        # Sort chat_history by timestamp
        aggregated_chat_history.sort(key=lambda x: x['timestamp'])

        data = {
            "id": str(latest_research.id),
            "topic": latest_research.topic,
            "subtopic": latest_research.subtopic,
            "scraper_results": latest_research.scraper_results,
            "chat_history": aggregated_chat_history
        }
        print(f"Returning aggregated research data for session {session_id}: {json.dumps(data, indent=2)}")
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching latest research: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/start_research', methods=['POST'])
@login_required
def start_research():
    try:
        data = request.get_json()
        topic = data.get('topic', '').strip()
        if not topic:
            print(f"No topic provided by user {current_user.user_id}")
            return jsonify({'error': 'No topic provided.'}), 400
        # Redirect to /get_subtopics
        return redirect(url_for('main.get_subtopics'), code=307)  # Preserve POST data
    except Exception as e:
        print(f"Error starting research: {str(e)}")
        return jsonify({'error': f"Failed to start research: {str(e)}"}), 500


@main.route('/save_research', methods=['POST'])
@login_required
def save_research():
    try:
        research = Research.query.filter_by(user_id=current_user.user_id, active=True).order_by(Research.created_at.desc()).first()
        if not research:
            print(f"No active research for user {current_user.user_id}")
            return jsonify({"error": "No active research to save."}), 404

        # Enforce free user limit (3 projects)
        user_tier = current_user.tier or 'free'
        if user_tier == 'free':
            project_count = Project.query.filter_by(user_id=current_user.user_id).count()
            if project_count >= 3:
                oldest = Project.query.filter_by(user_id=current_user.user_id).order_by(Project.created_at.asc()).first()
                db.session.delete(oldest)
                print(f"Deleted oldest Project ID {oldest.id} for free user {current_user.user_id}")

        project = Project(
            user_id=current_user.user_id,
            topic=research.topic,
            subtopic=research.subtopic,
            search_terms=research.search_terms,
            scraper_results=research.scraper_results,
            chat_history=research.chat_history or []
        )
        db.session.add(project)
        research.active = False  # Deactivate after saving
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Database commit failed: {str(e)}")
            return jsonify({"error": f"Failed to save project: {str(e)}"}), 500

        print(f"Saved Project ID {project.id} for user {current_user.user_id}")
        return jsonify({"message": "Research saved as project", "project_id": str(project.id)})
    except Exception as e:
        print(f"Error saving project: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/load_project/<int:project_id>', methods=['GET'])
@login_required
def load_project(project_id):
    try:
        project = Project.query.filter_by(id=project_id, user_id=current_user.user_id).first()
        if not project:
            print(f"Project ID {project_id} not found for user {current_user.user_id}")
            return jsonify({'error': 'Project not found.'}), 404

        session_id = session.get('session_id')
        if not session_id:
            print(f"No session_id for user {current_user.user_id}, generating new one")
            session_id = os.urandom(16).hex()
            session['session_id'] = session_id
            session.permanent = True
            session.modified = True

        Research.query.filter_by(user_id=current_user.user_id, session_id=session_id, active=True).update({'active': False})
        db.session.commit()

        research = Research(
            user_id=current_user.user_id,
            topic=project.topic,
            subtopic=project.subtopic,
            search_terms=project.search_terms,
            scraper_results=project.scraper_results,
            chat_history=project.chat_history or [{"role": "user", "content": project.topic, "timestamp": datetime.utcnow().isoformat()}],
            active=True,
            session_id=session_id
        )
        db.session.add(research)
        db.session.commit()

        print(f"Created Research ID {research.id} from Project ID {project_id} for user {current_user.user_id}")

        session['chosen_subtopic'] = {'research_id': research.id, 'subtopic': project.subtopic or ''}
        session['current_topic'] = project.topic
        session.permanent = True
        session.modified = True

        return jsonify({
            'message': 'Project loaded',
            'research_id': str(research.id),
            'topic': project.topic,
            'subtopic': project.subtopic,
            'scraper_results': project.scraper_results,
            'chat_history': project.chat_history
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error loading project: {str(e)}")
        return jsonify({'error': f"Failed to load project: {str(e)}"}), 500

@main.route('/load_content/<int:content_id>', methods=['GET'])
def load_content(content_id):
    try:
        content = Blog.query._filter_by(id=content_id).first()
        if not content:
            print(f"Project ID {content_id}")
            return jsonify({'error': 'Project not found.'}), 404
        
        return jsonify({
            'message' : 'Content loaded',
            'content_id' : content.id,
            'title' : content.title,
            'contents' : content.content
        })
    except Exception as e:
        print(f"Error loading content: {str(e)}")
        return jsonify({'error': f"Failed to load project: {str(e)}"}), 500




@main.route('/bookmark', methods=['GET'])
@login_required
def bookmark_page():
    settings = Settings.query.filter_by(user_id=current_user.user_id).first()
    theme_color = settings.theme_color if settings else 'light'
    return render_template("bookmarkwork.html", theme_color=theme_color)

@main.route('/bookmark', methods=['POST'])
@login_required
def bookmark():
    data = request.get_json()
    print(f"Received /bookmark payload for user {current_user.user_id}: {json.dumps(data, indent=2)}")
    content = data.get('text', '').strip()
    source = data.get('source', '').strip()
    if not content:
        print(f"No content provided for bookmark by user {current_user.user_id}")
        return jsonify({'error': 'No content to bookmark.'}), 400

    session_id = session.get('session_id')
    if not session_id:
        print(f"No session_id found for user {current_user.user_id}, generating new one")
        session_id = os.urandom(16).hex()
        session['session_id'] = session_id
        session.permanent = True
        session.modified = True

    research_id = data.get('research_id')
    if research_id:
        research = Research.query.filter_by(
            id=research_id,
            user_id=current_user.user_id,
            active=True
        ).first()
        if not research:
            print(f"Invalid research_id {str(research_id)} for user {current_user.user_id}")
            return jsonify({'error': 'Invalid research ID.'}), 400
    else:
        research = Research.query.filter_by(
            user_id=current_user.user_id,
            session_id=session_id,
            active=True
        ).order_by(Research.created_at.desc()).first()

    if not research:
        print(f"No active research found for user {current_user.user_id} in session {session_id}, creating fallback")
        Research.query.filter_by(user_id=current_user.user_id, session_id=session_id, active=True).update({'active': False})
        db.session.commit()
        research = Research(
            user_id=current_user.user_id,
            topic="Bookmarked Content",
            chat_history=[],
            active=True,
            session_id=session_id,
            created_at=datetime.utcnow()
        )
        db.session.add(research)
        try:
            db.session.commit()
            print(f"Created fallback Research ID {research.id} for user {current_user.user_id} in session {session_id}")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating fallback Research: {str(e)}")
            return jsonify({'error': f"Failed to create research record: {str(e)}"}), 500
    note = Note(
        user_id=current_user.user_id,
        research_id=research.id,
        content=content,
        source=source,
        created_at=datetime.utcnow()
    )
    db.session.add(note)
    try:
        db.session.commit()
        print(f"Saved Note ID {note.id} for user {current_user.user_id}, attached to Research ID {research.id}")
        return jsonify({'message': 'Text bookmarked!'})
    except Exception as e:
        db.session.rollback()
        print(f"Error saving bookmark: {str(e)}")
        return jsonify({'error': f"Failed to save bookmark: {str(e)}"}), 500

@main.route('/make_standalone/<int:note_id>', methods=['POST'])
@login_required
def make_standalone(note_id):
    note = Note.query.get(note_id)
    if not note or note.user_id != current_user.user_id:
        print(f"Note ID {note_id} not found or unauthorized for user {current_user.user_id}")
        return jsonify({"error": "Note not found or unauthorized."}), 404
    try:
        note.standalone = True
        note.research_id = None
        db.session.commit()
        print(f"Note ID {note_id} set as standalone")
        return jsonify({"message": "Note set as standalone"})
    except Exception as e:
        print(f"Error making note standalone: {e}")
        return jsonify({"error": str(e)}), 500

@main.route('/tab_content/<tab_name>')
@login_required
def tab_content(tab_name):
    if session.get('scraping', False):
        return jsonify({"content": "Scraping in progress, please wait..."})

    research_id = request.args.get('research_id', session.get('chosen_subtopic', {}).get('research_id'))
    if not research_id:
        print("No research_id in session or query parameters.")
        return jsonify({"content": "No research data available."}), 404

    research = Research.query.get(research_id)
    if not research or not research.scraper_results:
        print(f"No results for research_id: {research_id}")
        return jsonify({"content": "No research data available."}), 404

    results = research.scraper_results
    flat_results = [
        {**item, 'source': source}
        for query_results in results.values()
        for source, source_results in query_results.items()
        for item in source_results
    ]

    try:
        if tab_name == 'overview':
            content = "<ul>" + "".join([
                f"<li><a href='{r['link']}' target='_blank'>{r['title']}</a> ({r['source']}): {r.get('snippet', '')[:200]}</li>"
                for r in flat_results
            ]) + "</ul>" or "No overview available."
        elif tab_name == 'keypoints':
            content = "<br>".join(generate_keypoints(results))
        elif tab_name == 'deepdive':
            content = generate_deep_dive(results)
        elif tab_name == 'sources':
            content = generate_sources(results)
        elif tab_name == 'summary':
            content = generate_summary(results)
        else:
            content = "Invalid tab"
        return jsonify({"content": content})
    except Exception as e:
        print(f"Error loading tab {tab_name}: {e}")
        return jsonify({"content": f"Error loading {tab_name}"}), 500


def call_grok(prompt, model="llama-3.1-8b-instant"):
    """Call Grok API for content generation."""
    if not GROQ_API_KEY:
        print("Error: GROQ_API_KEY not set.")
        return "Error: API key not configured."
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500,
        "temperature": 0.5
    }
    try:
        print(f"Sending Grok request with prompt: {prompt[:200]}...")
        response = requests.post(GROQ_ENDPOINT, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        ai_response = response.json()
        print(f"Grok API response: {json.dumps(ai_response, indent=2)}")
        if 'choices' not in ai_response or not ai_response['choices']:
            print("Error: No choices in Grok response.")
            return "Error: Invalid API response."
        return ai_response["choices"][0]["message"]["content"].strip()
    except requests.exceptions.Timeout:
        print("Grok API timeout.")
        return "Error: API request timed out."
    except requests.exceptions.HTTPError as e:
        print(f"Grok API HTTP error: {e.response.status_code} - {e.response.text}")
        return f"Error: API returned {e.response.status_code}."
    except Exception as e:
        print(f"Grok API error: {e}")
        return f"Error generating content: {str(e)}"

@main.route('/get_bookmarks', methods=['GET'])
@login_required
def get_bookmarks():
    try:
        # Get the current session_id and research_id
        session_id = session.get('session_id')
        chosen_subtopic = session.get('chosen_subtopic', {})
        research_id = chosen_subtopic.get('research_id') if chosen_subtopic else None

        # Fetch current bookmarks (from active Research session)
        current_bookmarks = []
        if session_id and research_id:
            active_research = Research.query.filter_by(
                user_id=current_user.user_id,
                id=research_id,
                active=True
            ).first()
            if active_research:
                current_bookmarks = [
                    {
                        'id': str(note.id),
                        'content': note.content,
                        'source': note.source or 'No source',
                        'created_at': note.created_at.isoformat(),
                        'research_id': str(note.research_id) if note.research_id else None,
                        'project_id': str(note.project_id) if note.project_id else None
                    }
                    for note in Note.query.filter_by(
                        user_id=current_user.user_id,
                        research_id=research_id
                    ).order_by(Note.created_at.desc()).all()
                ]

        # Fetch all bookmarks for the user
        all_bookmarks = [
            {
                'id': str(note.id),
                'content': note.content,
                'source': note.source or 'No source',
                'created_at': note.created_at.isoformat(),
                'research_id': str(note.research_id) if note.research_id else None,
                'project_id': str(note.project_id) if note.project_id else None,
                'topic': (
                    Research.query.get(note.research_id).topic if note.research_id else
                    Project.query.get(note.project_id).topic if note.project_id else 'Unknown'
                ),
                'subtopic': (
                    Research.query.get(note.research_id).subtopic if note.research_id else
                    Project.query.get(note.project_id).subtopic if note.project_id else ''
                )
            }
            for note in Note.query.filter_by(user_id=current_user.user_id).order_by(Note.created_at.desc()).all()
        ]

        # Past bookmarks are all bookmarks excluding current research_id
        past_bookmarks = [b for b in all_bookmarks if b['research_id'] != research_id]

        return jsonify({
            'current_bookmarks': current_bookmarks,
            'past_bookmarks': past_bookmarks
        }), 200
    except Exception as e:
        print(f"Error fetching bookmarks: {str(e)}")
        return jsonify({'error': f"Failed to fetch bookmarks: {str(e)}"}), 500

@main.route('/reactivate_research/<int:research_id>', methods=['POST'])
@login_required
def reactivate_research(research_id):
    try:
        research = Research.query.filter_by(id=research_id, user_id=current_user.user_id).first()
        if not research:
            print(f"Research ID {research_id} not found for user {current_user.user_id}")
            return jsonify({'error': 'Research not found.'}), 404

        # Generate a new session_id
        session_id = os.urandom(16).hex()
        session['session_id'] = session_id
        session['current_topic'] = research.topic or ''
        session['chosen_subtopic'] = {'research_id': research.id, 'subtopic': research.subtopic or ''}
        session['scraping'] = False
        session.permanent = True
        session.modified = True

        # Deactivate other active research sessions
        Research.query.filter_by(user_id=current_user.user_id, active=True).update({'active': False})
        research.active = True
        db.session.commit()

        return jsonify({
            'message': 'Research session reactivated.',
            'research_id': str(research.id),
            'topic': research.topic or '',
            'subtopic': research.subtopic or ''
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error reactivating research: {str(e)}")
        return jsonify({'error': f"Failed to reactivate research: {str(e)}"}), 500


@main.route('/refine_bookmarks', methods=['POST'])
@login_required
def refine_bookmarks():
    data = request.get_json()
    output_type = data.get('output_type', 'report')
    scope = data.get('scope', 'current')  # Only refine current bookmarks
    bookmarks = data.get('bookmarks', [])  # List of bookmarks sent from frontend (current page)

    try:
        if not bookmarks:
            print(f"No bookmarks provided for refinement by user {current_user.user_id}")
            return jsonify({'error': 'No bookmarks to refine.'}), 400

        # Validate session for consistency
        chosen_subtopic = session.get('chosen_subtopic', {})
        research_id = chosen_subtopic.get('research_id')
        if not research_id and scope == 'current':
            print(f"No active research session for user {current_user.user_id} (no research_id in chosen_subtopic)")
            return jsonify({'error': 'No active research session. Start a new topic to bookmark.'}), 404

        # Package bookmarks with detailed structure
        page_text_parts = []
        total_words = 0
        for i, bookmark in enumerate(bookmarks, 1):
            content = bookmark.get('content', '').strip()
            source = bookmark.get('source', 'N/A').strip()
            if not content:
                print(f"Empty content for bookmark {i} by user {current_user.user_id}")
                continue
            word_count = len(content.split())
            total_words += word_count
            page_text_parts.append(f"Bookmark {i}:\nContent: {content}\nSource: {source}\nWord Count: {word_count}\n")
        page_text = "\n".join(page_text_parts)
        
        if not page_text.strip():
            print(f"No valid bookmark content for user {current_user.user_id}")
            return jsonify({'error': 'No valid bookmark content to refine.'}), 400

        print(f"Refining {len(bookmarks)} bookmarks for user {current_user.user_id}, total words: {total_words}")
        print(f"Input to Groq API: {page_text[:500]}..." if len(page_text) > 500 else f"Input to Groq API: {page_text}")

        # Enhanced prompt for comprehensive output
        prompt = f"""
        You are an expert content curator tasked with creating a polished {output_type} (e.g., report or script) from the following bookmark content related to a specific research topic. Your goal is to produce a detailed, well-structured output of 500-800 words, fully synthesizing all provided bookmarks. Include key points, insights, and source references where relevant. Organize the content logically with an introduction, main sections with descriptive headings, and a conclusion (for reports) or a clear narrative flow (for scripts). Ensure the output is engaging, informative, and avoids redundancy. Do not summarize excessively; incorporate all relevant details from the bookmarks. Provide only the refined content without additional explanations.

        Bookmarks:
        {page_text}

        Instructions:
        - Synthesize all bookmarks into a unified {output_type}, using all provided content.
        - Use clear section headings (e.g., Introduction, Key Findings, Conclusion for reports).
        - Reference sources explicitly (e.g., "According to [source]...") when appropriate.
        - Ensure the output is 500-800 words, fully utilizing the provided bookmark content.
        - Integrate multiple bookmarks seamlessly, avoiding repetition and ensuring coherence.
        - If content is extensive, prioritize key insights while maintaining detail.
        """
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2000,  # Increased to ensure full output
            "temperature": 0.5
        }
        try:
            response = requests.post(GROQ_ENDPOINT, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            ai_response = response.json()
            if 'choices' not in ai_response or not ai_response['choices']:
                print(f"No choices in API response for refinement by user {current_user.user_id}")
                return jsonify({'error': 'No valid response from refinement service'}), 500
            refined_content = ai_response["choices"][0]["message"]["content"].strip()
            if not refined_content:
                print(f"Empty response from Groq API for user {current_user.user_id}")
                return jsonify({'error': 'Refinement service returned empty content'}), 500
            refined_word_count = len(refined_content.split())
            print(f"Refined content ({output_type}, {refined_word_count} words): {refined_content[:200]}...")
            return jsonify({'refined': refined_content})
        except Exception as e:
            print(f"Error refining bookmarks for user {current_user.user_id}: {str(e)}")
            return jsonify({'error': f"Failed to refine bookmarks: {str(e)}"}), 500

    except Exception as e:
        print(f"Error processing refinement request for user {current_user.user_id}: {str(e)}")
        return jsonify({'error': f"Failed to process refinement request: {str(e)}"}), 500

@main.route('/download_bookmarks_pdf', methods=['POST'])
@login_required
def download_bookmarks_pdf():
    try:
        user = User.query.get(current_user.user_id)
        if user.tier == 'free':
            print(f"Free tier user {current_user.user_id} attempted to download PDF")
            return jsonify({'error': 'PDF download is available for premium users only.'}), 403

        data = request.get_json()
        content = data.get('content', '')
        scope = data.get('scope', 'current')  # 'current' or 'refined'

        if not content:
            # Fallback: Fetch content from current session bookmarks
            chosen_subtopic = session.get('chosen_subtopic', {})
            research_id = chosen_subtopic.get('research_id')
            if not research_id:
                print(f"No active research session for user {current_user.user_id} (no research_id in chosen_subtopic)")
                return jsonify({'error': 'No content available. Start a research session to bookmark.'}), 400

            notes = Note.query.filter_by(user_id=current_user.user_id, research_id=research_id).order_by(Note.created_at.asc()).all()
            if not notes:
                print(f"No bookmarks found for user {current_user.user_id} in current session (research_id: {research_id})")
                return jsonify({'error': 'No bookmarks to download.'}), 400

            content = '\n\n'.join([f"Bookmark {i+1}:\n{note.content}\nSource: {note.source or 'N/A'}" for i, note in enumerate(notes)])

        if not content.strip():
            print(f"No content provided for PDF download for user {current_user.user_id}")
            return jsonify({'error': 'No content to download.'}), 400

        print(f"Generating PDF for user {current_user.user_id} with content: {content[:100]}...")
        return jsonify({'content': content})
    except Exception as e:
        print(f"Error generating PDF for user {current_user.user_id}: {str(e)}")
        return jsonify({'error': f"Failed to generate PDF: {str(e)}"}), 500

@main.route('/get_profile', methods=['GET'])
@login_required
def get_profile():
    try:
        user = User.query.get(current_user.user_id)
        if not user:
            print(f"User ID {current_user.user_id} not found")
            return jsonify({'error': 'User not found.'}), 404

        return jsonify({
            'name': user.username or 'N/A',
            'email': user.email or 'N/A',
            'subscription': user.tier or "N/A" 
        }), 200
    except Exception as e:
        print(f"Error fetching profile: {str(e)}")
        return jsonify({'error': f"Failed to fetch profile: {str(e)}"}), 500

@main.route('/update_password', methods=['POST'])
@login_required
def update_password():
    try:
        data = request.get_json()
        password = data.get('password')
        if not password:
            return jsonify({'error': 'Password is required.'}), 400
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters.'}), 400

        user = User.query.get(current_user.user_id)
        if not user:
            print(f"User ID {current_user.user_id} not found")
            return jsonify({'error': 'User not found.'}), 404

        # Hash the new password using werkzeug.security
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()

        print(f"Password updated for user {current_user.user_id}")
        return jsonify({'message': 'Password updated successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error updating password: {str(e)}")
        return jsonify({'error': f"Failed to update password: {str(e)}"}), 500

@main.route('/upgrade_subscription', methods=['POST'])
@login_required
def upgrade_subscription():
    try:
        user = User.query.get(current_user.user_id)
        if not user:
            print(f"User ID {current_user.user_id} not found")
            return jsonify({'error': 'User not found.'}), 404

        # Check if user already has a premium subscription
        current_subscription = getattr(user, 'subscription', 'Free')
        if current_subscription == 'SuperGrok':
            return jsonify({'error': 'Already on SuperGrok plan.'}), 400

        # Redirect to xAI's subscription page (per xAI guidelines)
        redirect_url = 'https://x.ai/grok'  # Replace with actual payment portal if needed
        return jsonify({'redirect_url': redirect_url}), 200

        # Optional: If managing subscriptions internally, uncomment below
        # user.subscription = 'SuperGrok'
        # db.session.commit()
        # print(f"Subscription upgraded to SuperGrok for user {current_user.user_id}")
        # return jsonify({'message': 'Subscription upgraded successfully.'}), 200
    except Exception as e:
        print(f"Error upgrading subscription: {str(e)}")
        return jsonify({'error': f"Failed to upgrade subscription: {str(e)}"}), 50