from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Project, Research, Note
from . import db
import re
from dotenv import load_dotenv
import os
import json
import requests
from .scrapper import free_scraper
from .config import GROQ_API_KEY, GROQ_ENDPOINT
from .ai_utils import generate_keypoints, generate_deep_dive, generate_sources, generate_summary
from datetime import timedelta, datetime

load_dotenv()

main = Blueprint('main', __name__)

@main.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('base.html')

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
            session.modified = True

    # Update session timestamp
    session['last_active'] = datetime.utcnow().isoformat()

    # Clear invalid session data
    if session.get('chosen_subtopic', {}).get('research_id'):
        research = Research.query.get(session['chosen_subtopic']['research_id'])
        if not research or research.user_id != current_user.user_id or not research.active:
            print(f"Invalid or inactive research_id {session['chosen_subtopic']['research_id']} for user {current_user.user_id}, clearing.")
            session.pop('chosen_subtopic', None)
            session.pop('current_topic', None)
            session.modified = True

    # Load latest active research
    latest_research = Research.query.filter_by(user_id=current_user.user_id, active=True).order_by(Research.created_at.desc()).first()
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
    return render_template("dashboard.html", user=current_user, projects=projects)

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

@main.route('/get_subtopics', methods=['POST'])
@login_required
def get_subtopics():
    data = request.get_json()
    topic = data.get('topic', '').strip()
    if not topic:
        print("Error: No topic provided.")
        return jsonify({"error": "No topic provided."}), 400

    print(f"Received topic: {topic}")

    # Save topic as first chat message
    research = Research.query.filter_by(user_id=current_user.user_id, active=True).order_by(Research.created_at.desc()).first()
    if not research:
        research = Research(
            user_id=current_user.user_id,
            topic=topic,
            chat_history=[{"role": "user", "content": topic, "timestamp": datetime.utcnow().isoformat()}]
        )
        db.session.add(research)
    else:
        research.chat_history = research.chat_history or []
        research.chat_history.append({"role": "user", "content": topic, "timestamp": datetime.utcnow().isoformat()})
        research.topic = topic
    db.session.commit()

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

        if not subtopics:
            print("Parsing failed, using fallback naive subtopics.")
            result = naive_subtopics(topic)
        else:
            result = {"subtopics": subtopics, "search_terms": search_terms}

        # Add bot response with subtopics to chat history
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        db.session.commit()

        session['current_topic'] = topic
        session.permanent = True
        session.modified = True
        print(f"Saved topic '{topic}' and subtopics to Research ID {research.id}")
        return jsonify(result)

    except requests.exceptions.Timeout:
        print("Timeout error: Groq API timed out.")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        db.session.commit()
        return jsonify(result), 500
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e.response.status_code} - {e.response.text}")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        db.session.commit()
        return jsonify(result), 500
    except Exception as e:
        print(f"Grok API error: {e}")
        result = naive_subtopics(topic)
        bot_message = {"role": "bot", "content": f"Here are some subtopics: {', '.join(result['subtopics'])}", "timestamp": datetime.utcnow().isoformat()}
        research.chat_history.append(bot_message)
        db.session.commit()
        return jsonify(result), 500

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
        return jsonify({"message": "Subtopic saved", "research_id": research.id})
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
        # Run scraper
        scraped_results = free_scraper(tuple(search_terms))
        print(f"Scraper raw results: {json.dumps(scraped_results, indent=2)}")

        # If empty, try fallback terms
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

        # Ensure a Research record exists
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
    research = Research.query.get(research_id)
    if not research:
        print(f"Research ID {research_id} not found in database.")
        return jsonify({"error": "Research not found."}), 404
    if research.user_id != current_user.user_id:
        print(f"Research ID {research_id} unauthorized for user {current_user.user_id}.")
        return jsonify({"error": "Unauthorized access to research."}), 403
    if not research.active:
        print(f"Research ID {research_id} is inactive.")
        return jsonify({"error": "Research is inactive."}), 404
    data = {
        'topic': research.topic,
        'subtopic': research.subtopic,
        'scraper_results': research.scraper_results if research.scraper_results else None,
        'chat_history': research.chat_history if research.chat_history else []
    }
    print(f"Returning research data for ID {research_id}: {json.dumps(data, indent=2)}")
    return jsonify(data)

@main.route('/new_research', methods=['POST'])
@login_required
def new_research():
    try:
        Research.query.filter_by(user_id=current_user.user_id, active=True).update({'active': False})
        db.session.commit()
        session.pop('chosen_subtopic', None)
        session.pop('current_topic', None)
        session.pop('scraping', None)
        session.pop('bookmarks', None)
        session['last_active'] = datetime.utcnow().isoformat()
        session.permanent = True
        session.modified = True
        print(f"Cleared active research for user {current_user.user_id}")
        return jsonify({"message": "New research started"})
    except Exception as e:
        print(f"Error starting new research: {e}")
        return jsonify({"error": str(e)}), 500

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
            title=research.topic or 'Untitled',
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
        return jsonify({"message": "Research saved as project", "project_id": project.id})
    except Exception as e:
        print(f"Error saving project: {str(e)}")
        return jsonify({"error": str(e)}), 500

@main.route('/load_project/<int:project_id>')
@login_required
def load_project(project_id):
    project = Project.query.get(project_id)
    if not project or project.user_id != current_user.user_id:
        print(f"Project ID {project_id} not found or unauthorized for user {current_user.user_id}")
        return jsonify({"error": "Project not found or unauthorized."}), 404

    try:
        # Deactivate current research
        Research.query.filter_by(user_id=current_user.user_id, active=True).update({'active': False})
        # Create new Research from Project
        research = Research(
            user_id=current_user.user_id,
            topic=project.topic,
            subtopic=project.subtopic,
            search_terms=project.search_terms,
            scraper_results=project.scraper_results,
            chat_history=project.chat_history,
            active=True
        )
        db.session.add(research)
        db.session.commit()

        session['chosen_subtopic'] = {'subtopic': project.subtopic or '', 'research_id': research.id}
        session['current_topic'] = project.topic or ''
        session.modified = True
        print(f"Loaded Project ID {project_id} into Research ID {research.id}")
        return jsonify({
            "topic": project.topic,
            "subtopic": project.subtopic,
            "scraper_results": project.scraper_results,
            "chat_history": project.chat_history
        })
    except Exception as e:
        print(f"Error loading project: {e}")
        return jsonify({"error": str(e)}), 500

@main.route('/bookmark', methods=['GET'])
@login_required
def bookmark_page():
    return render_template("bookmarkwork.html")

@main.route('/bookmark', methods=['POST'])
@login_required
def bookmark():
    data = request.get_json()
    text = data.get('text', '').strip()
    if not text:
        return jsonify({"error": "No text provided."}), 400

    try:
        research = Research.query.filter_by(user_id=current_user.user_id, active=True).order_by(Research.created_at.desc()).first()
        note = Note(
            user_id=current_user.user_id,
            content=text,
            research_id=research.id if research else None,
            source_tab=session.get('activeTab', 'overview'),
            standalone=False
        )
        db.session.add(note)
        db.session.commit()
        print(f"Saved Note ID {note.id} for user {current_user.user_id}, attached to Research ID {research.id if research else 'None'}")
        return jsonify({"message": "Bookmark saved", "note_id": note.id})
    except Exception as e:
        print(f"Error saving bookmark: {e}")
        return jsonify({"error": str(e)}), 500

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

    research_id = session.get('chosen_subtopic', {}).get('research_id')
    if not research_id:
        print("No research_id in session.")
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