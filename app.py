import os
import hashlib
import hmac
import time
import datetime
import secrets
import json
import logging
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from flask import Flask, request, redirect, render_template, send_from_directory, jsonify, abort, session, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from pillow_heif import register_heif_opener
from werkzeug.utils import secure_filename
from models import db, User, Team, TeamMembership
from permissions import (
    admin_required, team_access_required, team_captain_required,
    team_captain_or_member_required, user_self_or_admin_required,
    team_upload_allowed, register_permissions
)

# Register HEIC/AVIF opener for Pillow
register_heif_opener()

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_PHOTOS_PER_TEAM = 23
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.tiff'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_secret(secret_name):
    # Check environment variable
    secret = os.getenv(secret_name.upper())
    if secret:
        return secret

    # Check Docker Secrets path
    try:
        with open(f"/run/secrets/{secret_name}") as secret_file:
            return secret_file.read().strip()
    except FileNotFoundError:
        pass

    # Fallback to local file
    try:
        with open(f"./config/{secret_name}.txt") as secret_file:
            return secret_file.read().strip()
    except FileNotFoundError:
        pass

    raise RuntimeError(f"Secret '{secret_name}' not found in any source")


# Configuration
app.config['SECRET_KEY'] = get_secret('URL_KEY')

# Database configuration - use data directory for persistence
db_path = os.path.join(os.getcwd(), 'data', 'relay_photos.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = get_secret('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = get_secret('GOOGLE_CLIENT_SECRET')
app.config['GITHUB_CLIENT_ID'] = get_secret('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = get_secret('GITHUB_CLIENT_SECRET')
app.config['META_CLIENT_ID'] = get_secret('META_CLIENT_ID')
app.config['META_CLIENT_SECRET'] = get_secret('META_CLIENT_SECRET')

# Admin configuration
ADMIN_EMAIL = get_secret('ADMIN_EMAIL')

# Initialize extensions
db.init_app(app)
register_permissions(app)

# Make utility functions available in templates
@app.template_global()
def get_team_hash(team_name):
    hmac_value = hmac.new(SECRET_KEY.encode('utf-8'), team_name.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac_value


# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

# Setup OAuth
oauth = OAuth(app)

# Configure OAuth providers
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

github = oauth.register(
    name='github',
    client_id=app.config['GITHUB_CLIENT_ID'],
    client_secret=app.config['GITHUB_CLIENT_SECRET'],
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

meta = oauth.register(
    name='meta',
    client_id=app.config['META_CLIENT_ID'],
    client_secret=app.config['META_CLIENT_SECRET'],
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

# Provider configuration for template
oauth_providers = [
    {'name': 'google', 'display_name': 'Google'},
    {'name': 'github', 'display_name': 'GitHub'},
    {'name': 'meta', 'display_name': 'Meta'}
]

SECRET_KEY = get_secret('URL_KEY')


def get_team_hash(team_name):
    hmac_value = hmac.new(SECRET_KEY.encode('utf-8'), team_name.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac_value




def load_station_names():
    """Load station names from lrr_1_line.geojson file"""
    try:
        with open('data/lrr_1_line.geojson', 'r') as f:
            data = json.load(f)
        sorted_features = sorted(data["features"], key=lambda item: item['properties']['id'], reverse=True)
        station_names = [feature['properties']['name'] for feature in sorted_features]
        return station_names
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        print(f"Error loading station names: {e}")
        return []


# Extract capture time and GPS coordinates from image EXIF metadata
def get_exif_data(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image.getexif()
        if not exif_data:
            return None, None

        capture_time = None
        gps_info = None

        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag, tag)
            if tag_name == 'DateTimeOriginal':
                capture_time = value
            if tag_name == 'DateTime' and not capture_time:
                capture_time = value
            elif tag_name == 'GPSInfo':
                gps_info = {GPSTAGS.get(t, t): v for t, v in exif_data.get_ifd(0x8825).items()}

        # Extract GPS coordinates if available
        if gps_info:
            gps_coordinates = get_gps_data(gps_info)
        else:
            gps_coordinates = None

        return capture_time, gps_coordinates
    except Exception as e:
        print(f"Error extracting EXIF data: {e}")
        return None, None


def get_gps_data(exif_data):
    if 'GPSLatitude' not in exif_data or 'GPSLongitude' not in exif_data:
        return None

    def convert_to_degrees(value):
        d, m, s = value
        return d + (m / 60.0) + (s / 3600.0)

    lat = convert_to_degrees(exif_data['GPSLatitude'])
    lon = convert_to_degrees(exif_data['GPSLongitude'])

    # Adjust for hemisphere
    if exif_data.get('GPSLatitudeRef') == 'S':
        lat = -lat
    if exif_data.get('GPSLongitudeRef') == 'W':
        lon = -lon

    return lat, lon


# OAuth routes
@app.route('/login/<provider>')
def oauth_login(provider):
    if provider not in [p['name'] for p in oauth_providers]:
        return abort(404)

    client = oauth.create_client(provider)

    # Store the 'next' parameter in the session
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url
    logging.warning(f"DEBUG: Storing next_url in session: {session.get('next_url')}")

    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)


@app.route('/account/auth/<provider>')
def oauth_callback(provider):
    if provider not in [p['name'] for p in oauth_providers]:
        return abort(404)

    client = oauth.create_client(provider)
    try:
        token = client.authorize_access_token()

        if provider == 'google':
            user_info = token.get('userinfo')
            if user_info:
                email = user_info.get('email')
                name = user_info.get('name')
                avatar_url = user_info.get('picture')
                provider_id = str(user_info.get('sub'))
        elif provider == 'github':
            # Get user info from GitHub API
            resp = client.get('user', token=token)
            user_info = resp.json()

            # Get primary email from GitHub API
            email_resp = client.get('user/emails', token=token)
            emails = email_resp.json()
            primary_email = next((e['email'] for e in emails if e['primary']), None)

            email = primary_email or user_info.get('email')
            name = user_info.get('name') or user_info.get('login')
            avatar_url = user_info.get('avatar_url')
            provider_id = str(user_info.get('id'))
        elif provider == 'meta':
            # Get user info from Facebook Graph API
            resp = client.get('me?fields=id,email,name,picture', token=token)
            user_info = resp.json()

            email = user_info.get('email')
            name = user_info.get('name')
            avatar_url = user_info.get('picture', {}).get('data', {}).get('url')
            provider_id = str(user_info.get('id'))
        else:
            return redirect(url_for('login', error='auth_failed'))

        if not email or not provider_id:
            return redirect(url_for('login', error='missing_data'))

        # Find or create user
        user = User.query.filter_by(provider=provider, provider_id=provider_id).first()

        if user:
            # Update existing user
            user.email = email
            user.name = name
            user.avatar_url = avatar_url
            user.last_login = datetime.datetime.now(datetime.UTC)
        else:
            # Check if email exists with different provider
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return redirect(url_for('login', error='email_exists'))

            # Create new user
            user = User(
                email=email,
                name=name,
                avatar_url=avatar_url,
                provider=provider,
                provider_id=provider_id,
                is_admin=(email == ADMIN_EMAIL)  # Set admin based on configured email
            )
            db.session.add(user)

        db.session.commit()
        login_user(user)

        # Redirect to the original page from session or to index
        next_page = session.pop('next_url', None)
        logging.warning(f"DEBUG: Retrieved next_url from session: {next_page}")

        if not next_page or not next_page.startswith('/'):
            if not next_page:
                logging.warning("DEBUG: next_page is None, redirecting to index.")
            else:
                logging.warning(f"DEBUG: next_page '{next_page}' is not a valid relative path, redirecting to index.")
            next_page = url_for('index')

        logging.warning(f"DEBUG: Redirecting to: {next_page}")
        return redirect(next_page)

    except Exception as e:
        print(f"OAuth error: {e}")
        return redirect(url_for('login', error='auth_failed'))

@app.route('/')
def index():
    return render_template('index.html')


def find_team_by_hash(team_hash):
    """Find team in database by hash"""
    all_teams = Team.query.all()
    for team in all_teams:
        if get_team_hash(team.name) == team_hash:
            return team
    return None


def find_team_by_id(team_id):
    """Find team in database by id"""
    return Team.query.filter_by(id=team_id).first()


def find_team_by_gallery_hash(gallery_hash):
    """Find team in database by gallery_hash"""
    return Team.query.filter_by(gallery_hash=gallery_hash).first()


@app.route('/team/<team_id>/gallery')
@team_access_required()
def team_page(team_id, team):

    team_path = os.path.join(UPLOAD_FOLDER, team.id)

    # Check if team folder exists and get images
    images = []
    if os.path.exists(team_path) and os.path.isdir(team_path):
        images = [f for f in os.listdir(team_path)
                 if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)]

    from datetime import datetime

    # Helper function to parse capture time
    def parse_capture_time(time_str):
        return datetime.strptime(time_str, "%Y:%m:%d %H:%M:%S") if time_str else None

    image_data = []
    for image in images:
        image_path = os.path.join(team_path, image)
        capture_time, gps_coordinates = get_exif_data(image_path)
        image_data.append((image, capture_time, gps_coordinates))

    # Sort by capture_time, defaulting to datetime.min for missing values
    image_data = sorted(image_data, key=lambda x: parse_capture_time(x[1]) or datetime.min)
    return render_template('gallery.html', team=team, images=image_data, team_id=team_id)


# Public gallery route (view-only)
@app.route('/gallery/<gallery_hash>')
def public_gallery(gallery_hash):
    # Find team in database by gallery_hash
    team = find_team_by_gallery_hash(gallery_hash)

    if not team:
        return "Invalid gallery URL.", 404

    team_path = os.path.join(UPLOAD_FOLDER, team.id)

    # Check if team folder exists and get images
    images = []
    if os.path.exists(team_path) and os.path.isdir(team_path):
        images = [f for f in os.listdir(team_path)
                 if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)]

    from datetime import datetime

    # Helper function to parse capture time
    def parse_capture_time(time_str):
        return datetime.strptime(time_str, "%Y:%m:%d %H:%M:%S") if time_str else None

    image_data = []
    for image in images:
        image_path = os.path.join(team_path, image)
        capture_time, gps_coordinates = get_exif_data(image_path)
        image_data.append((image, capture_time, gps_coordinates))

    # Sort by capture_time, defaulting to datetime.min for missing values
    image_data = sorted(image_data, key=lambda x: parse_capture_time(x[1]) or datetime.min)
    return render_template('gallery.html', team=team, images=image_data, gallery_hash=gallery_hash)


@app.route('/team/<team_id>/members')
@team_access_required()
def team_members(team_id, team):

    # Get all team memberships with user data
    all_memberships = TeamMembership.query.filter_by(team_id=team.id).all()

    # Filter memberships by status
    active_members = [m for m in all_memberships if m.status == 'active']
    withdrawn_members = [m for m in all_memberships if m.status == 'withdrawn']
    removed_members = [m for m in all_memberships if m.status == 'removed']

    # Calculate statistics from active members only
    willing_leaders_count = sum(1 for membership in active_members if membership.willing_to_lead)
    preferred_miles_list = [membership.preferred_miles for membership in active_members if membership.preferred_miles]
    avg_preferred_miles = round(sum(preferred_miles_list) / len(preferred_miles_list)) if preferred_miles_list else None

    return render_template('team_members.html',
                         team=team,
                         active_members=active_members,
                         withdrawn_members=withdrawn_members,
                         removed_members=removed_members,
                         team_id=team_id,
                         willing_leaders_count=willing_leaders_count,
                         avg_preferred_miles=avg_preferred_miles)


@app.route('/team/<team_id>/gallery/delete', methods=['DELETE'])
@team_upload_allowed()
def delete_image(team_id, team):

    filename = secure_filename(request.args.get('filename'))
    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, team.id, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "File not found"}), 404



@app.route('/team/<team_id>/upload', methods=['POST'])
@team_upload_allowed()
def upload_file(team_id, team):
    # team is automatically provided by the decorator

    team_path = os.path.join(UPLOAD_FOLDER, team.id)
    existing_images_count = 0
    if os.path.exists(team_path) and os.path.isdir(team_path):
        existing_images_count = len([f for f in os.listdir(team_path)
                                   if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)])
    files = request.files.getlist('files')
    if not files:
        return "No files uploaded", 400

    if existing_images_count + len(files) > MAX_PHOTOS_PER_TEAM:
        return "Team photo limit exceeded.", 400

    save_path = os.path.join(UPLOAD_FOLDER, team.id)
    os.makedirs(save_path, exist_ok=True)

    for file in files:
        if len(file.read()) > MAX_FILE_SIZE:
            return "File size exceeds 10MB limit.", 400
        if not is_allowed_image(file.filename):
            continue

        file.seek(0)  # Reset file pointer after size check

        # Compute hash of the file to check for duplicates
        file_hash = hashlib.md5(file.read()).hexdigest()
        file.seek(0)  # Reset file pointer after hash calculation

        # Check for duplicate files in the existing uploads
        is_duplicate = False
        for existing_file in os.listdir(save_path):
            existing_file_path = os.path.join(save_path, existing_file)
            existing_file_hash = hashlib.md5(open(existing_file_path, 'rb').read()).hexdigest()
            if file_hash == existing_file_hash:
                is_duplicate = True
                break

        if is_duplicate:
            continue  # Skip saving this file as it is a duplicate

        # Save the file with a timestamped filename
        file_path = os.path.join(save_path, f"{int(time.time())}_{secure_filename(file.filename)}")
        file.save(file_path)

    return redirect(url_for('team_page', team_id=team.id))


def is_allowed_image(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<team_id>/<filename>')
def serve_image(team_id, filename):
    if not is_allowed_image(filename):
        return abort(404, description="Invalid file type.")

    # Find team in database by team_id
    team = find_team_by_id(team_id)
    if not team:
        return abort(404, description="Invalid team URL.")

    return send_from_directory(os.path.join(UPLOAD_FOLDER, team.id), secure_filename(filename))


@app.route('/login')
def login():
    # If user is already logged in, redirect to next page or index
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('index'))

    error = request.args.get('error')
    error_messages = {
        'missing_data': 'Unable to retrieve user information from OAuth provider.',
        'email_exists': 'An account with this email already exists with a different provider.',
        'auth_failed': 'Authentication failed. Please try again.'
    }
    error_message = error_messages.get(error) if error else None

    # Preserve the next URL for the OAuth links
    next_url = request.args.get('next')

    return render_template('login.html', providers=oauth_providers, error=error_message, next_url=next_url)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create-team', methods=['GET', 'POST'])
@login_required
def create_team():
    # Check if user is already associated with any team (as captain or member)
    existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
    existing_membership = TeamMembership.query.filter_by(user_id=current_user.id, status='active').first()

    if existing_captained_team and existing_captained_team.status not in ['withdrawn', 'cancelled']:
        return jsonify({'error': f'You have already created team "{existing_captained_team.name}"'}), 400

    if existing_membership and existing_membership.team.status not in ['withdrawn', 'cancelled']:
        return jsonify({'error': f'You are already a member of team "{existing_membership.team.name}"'}), 400

    if request.method == 'GET':
        return render_template('create_team.html', user=current_user)

    # Handle POST request
    try:
        team_name = request.form.get('team_name', '').strip()
        format_type = request.form.get('format', '').strip()
        estimated_duration = request.form.get('estimated_duration', '').strip()
        comments = request.form.get('comments', '').strip()
        password = request.form.get('password', '').strip()
        has_baton = request.form.get('has_baton') == 'on'
        email_opt_in = request.form.get('email_opt_in') == 'true'

        # Validation
        if not team_name:
            return jsonify({'error': 'Team name is required'}), 400

        if format_type not in ['Solo', 'Team']:
            return jsonify({'error': 'Format must be Solo or Team'}), 400

        if not estimated_duration:
            return jsonify({'error': 'Estimated duration is required'}), 400

        # Validate duration format (HH:MM)
        import re
        if not re.match(r'^\d{1,2}:\d{2}$', estimated_duration):
            return jsonify({'error': 'Duration must be in HH:MM format'}), 400

        # Check if team name already exists
        existing_name = Team.query.filter_by(name=team_name).first()
        if existing_name:
            return jsonify({'error': 'Team name already exists'}), 400

        # Create new team (status defaults to 'pending')
        new_team = Team(
            name=team_name,
            format=format_type,
            estimated_duration=estimated_duration,
            comments=comments if comments else None,
            password=password if password else None,
            has_baton=has_baton,
            status='pending',
            captain_id=current_user.id
        )

        db.session.add(new_team)
        db.session.flush()  # Flush to get the team ID before creating membership

        # Always create TeamMembership for captain with standard defaults
        captain_membership = None
        if format_type == 'Solo':
            # Solo teams get reasonable defaults that can be edited later
            captain_membership = TeamMembership(
                user_id=current_user.id,
                team_id=new_team.id,
                willing_to_lead=True,
                preferred_miles=36,    # Full distance default
                planned_pace='8:00',   # Common pace
                preferred_station=None,
                comments=None
            )
            db.session.add(captain_membership)
            redirect_url = url_for('team_members', team_id=new_team.id)
            message = 'Solo entry created successfully! You can edit your preferences anytime.'
        else:
            # Team format captains still need to set their preferences
            # No membership created here - they'll create it via join form
            redirect_url = url_for('join_team')
            message = 'Team created successfully! Now enter your preferences.'

        # Update email opt-in status for all team types
        current_user.email_opt_in = email_opt_in

        db.session.commit()

        team_folder_path = os.path.join(UPLOAD_FOLDER, new_team.id)
        os.makedirs(team_folder_path, exist_ok=True)

        return jsonify({
            'success': True,
            'message': message,
            'team_id': new_team.id,
            'team_name': new_team.name,
            'redirect_url': redirect_url
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create team: {str(e)}'}), 500

@app.route('/join-team', methods=['GET', 'POST'])
@login_required
def join_team():
    stations = load_station_names()[1:]
    if request.method == 'GET':
        # Check if user is already associated with any team (as captain or member)
        existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
        existing_membership = TeamMembership.query.filter_by(user_id=current_user.id, status='active').first()
        pending_captain_team = None

        # Handle invite token if present in URL
        invite_token = request.args.get('invite_token')
        invited_team = None
        error_message = None

        if invite_token:
            invited_team = Team.query.filter_by(invite_token=invite_token).first()
            if not invited_team:
                error_message = "The invitation link is invalid or has expired. Please select a team from the list below."
            elif invited_team.status != 'complete':
                error_message = f"The team '{invited_team.name}' is not currently accepting new members."
                invited_team = None  # Don't pre-fill if team is not open

        # Handle case where a captain just created a team and needs to join
        if not invited_team and existing_captained_team and existing_captained_team.status == 'pending' and not existing_membership:
            pending_captain_team = existing_captained_team


        # Get all teams with "Team" format and "complete" status (open for joining)
        # Exclude closed teams as they're not accepting new members
        open_teams = Team.query.filter_by(format='Team', status='complete').all()

        # Determine mode and setup template data
        if pending_captain_team:
            mode = 'join'
            existing_team = None
        elif existing_membership or existing_captained_team:
            mode = 'switch'  # User can switch teams or edit current preferences
            existing_team = existing_membership.team if existing_membership else existing_captained_team
        else:
            mode = 'join'  # Fresh user joining for first time
            existing_team = None

        return render_template('participant_registration.html',
                             teams=open_teams,
                             stations=stations,
                             user=current_user,
                             mode=mode,
                             existing_team=existing_team,
                             existing_membership=existing_membership,
                             pending_captain_team=pending_captain_team,
                             invited_team=invited_team,
                             error_message=error_message)

    # Handle POST - delegate to shared handler
    return handle_team_registration_post(stations, mode='join')

@app.route('/my-registration', methods=['GET', 'POST'])
@login_required
def my_registration():
    """Handle editing existing team registration/preferences"""
    stations = load_station_names()[1:]

    # Check if user has existing membership or captained team
    existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
    existing_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()

    if not existing_membership and not existing_captained_team:
        # No existing registration, redirect to join team
        return redirect(url_for('join_team'))

    if request.method == 'GET':
        if existing_membership:
            # User has membership - show edit form
            team = existing_membership.team
            return render_template('participant_registration.html',
                                 teams=[],
                                 stations=stations,
                                 user=current_user,
                                 mode='edit',
                                 existing_team=team,
                                 existing_membership=existing_membership)
        elif existing_captained_team and existing_captained_team.format == 'Solo':
            # Solo captain - redirect to team members page
            return redirect(url_for('team_members', team_id=existing_captained_team.id))
        else:
            # Team captain without membership - show edit form for their own team
            return render_template('participant_registration.html',
                                 teams=[existing_captained_team],
                                 stations=stations,
                                 user=current_user,
                                 mode='edit',
                                 existing_team=existing_captained_team,
                                 existing_membership=None)

    # Handle POST - delegate to shared handler
    return handle_team_registration_post(stations, mode='edit')

def handle_team_registration_post(stations, mode='join'):
    """Shared handler for team registration POST requests"""
    try:
        team_id = request.form.get('team_id')
        willing_to_lead = request.form.get('willing_to_lead') == 'yes'
        preferred_miles = request.form.get('preferred_miles')
        planned_pace = request.form.get('planned_pace')
        preferred_station = request.form.get('preferred_station')
        comments = request.form.get('comments', '').strip()
        waiver_agreed = request.form.get('waiver_agreed') == 'on'
        team_password = request.form.get('team_password', '').strip()
        invite_token = request.form.get('invite_token')
        email_opt_in = request.form.get('email_opt_in') == 'true'

        # Check if user is already associated with any team (as captain or member)
        existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
        existing_membership = TeamMembership.query.filter_by(user_id=current_user.id, status='active').first()

        # Validation
        if not team_id:
            if not invite_token:
                return jsonify({'error': 'Please select a team'}), 400

        team = None
        # Authorize joining the team
        if invite_token:
            team = Team.query.filter_by(invite_token=invite_token).first()
            if not team:
                return jsonify({'error': 'The invitation link is invalid or has expired.'}), 400
            if team_id and int(team_id) != team.id:
                return jsonify({'error': 'Invitation and selected team do not match.'}), 400
        else:
            if not team_id:
                 return jsonify({'error': 'Please select a team'}), 400
            team = db.session.get(Team, team_id)

        # Authorization logic: Check if user can join this specific team
        if team.status == 'complete':
            # For complete teams, check password if required
            if team.password and not invite_token: # Invite token bypasses password
                if not team_password:
                    return jsonify({'error': 'This team requires a password'}), 400
                if team_password != team.password:
                    return jsonify({'error': 'Incorrect team password'}), 400
        elif team.status == 'pending':
            # For pending teams, only the captain can register
            if team.captain_id != current_user.id:
                return jsonify({'error': 'This team is pending approval and not yet open for joining.'}), 403
        else: # 'withdrawn' or other statuses
            return jsonify({'error': f"Team '{team.name}' is not currently accepting new members."}), 403

        if team.format == 'Solo':
            return jsonify({'error': 'Solo teams cannot be joined.'}), 400

        # Handle team switching (user joining different team)
        is_switching_teams = existing_membership and existing_membership.team_id != team.id

        if not preferred_miles or not preferred_miles.isdigit():
            return jsonify({'error': 'Preferred miles must be a valid number'}), 400

        # Validate pace format (mm:ss)
        import re
        if not planned_pace or not re.match(r'^\d{1,2}:\d{2}$', planned_pace):
            return jsonify({'error': 'Planned pace must be in MM:SS format'}), 400

        if not waiver_agreed:
            return jsonify({'error': 'You must agree to the waiver terms'}), 400

        # Handle different scenarios
        if is_switching_teams:
            # User is switching to a different team - remove old membership and create new one
            db.session.delete(existing_membership)
            membership = TeamMembership(
                user_id=current_user.id,
                team_id=team.id,
                willing_to_lead=willing_to_lead,
                preferred_miles=int(preferred_miles),
                planned_pace=planned_pace,
                preferred_station=preferred_station if preferred_station else None,
                comments=comments if comments else None
            )
            db.session.add(membership)
            message = f'Successfully switched to {team.name}'
        elif existing_membership:
            # Update existing membership
            existing_membership.willing_to_lead = willing_to_lead
            existing_membership.preferred_miles = int(preferred_miles)
            existing_membership.planned_pace = planned_pace
            existing_membership.preferred_station = preferred_station if preferred_station else None
            existing_membership.comments = comments if comments else None
            message = f'Successfully updated preferences for {team.name}'
        elif existing_captained_team:
            # Create membership for captain (captains don't automatically have memberships)
            membership = TeamMembership(
                user_id=current_user.id,
                team_id=team.id,
                willing_to_lead=willing_to_lead,
                preferred_miles=int(preferred_miles),
                planned_pace=planned_pace,
                preferred_station=preferred_station if preferred_station else None,
                comments=comments if comments else None
            )
            db.session.add(membership)
            message = f'Successfully added preferences for {team.name}'
        else:
            # Create new team membership
            membership = TeamMembership(
                user_id=current_user.id,
                team_id=team.id,
                willing_to_lead=willing_to_lead,
                preferred_miles=int(preferred_miles),
                planned_pace=planned_pace,
                preferred_station=preferred_station if preferred_station else None,
                comments=comments if comments else None
            )
            db.session.add(membership)
            message = f'Successfully joined {team.name}'

        # Update email opt-in status
        current_user.email_opt_in = email_opt_in

        db.session.commit()

        return jsonify({
            'success': True,
            'message': message,
            'team_name': team.name,
            'redirect_url': url_for('team_members', team_id=team.id)
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to process registration: {str(e)}'}), 500

@app.route('/admin')
@admin_required
def admin():
    # Get all teams from database
    db_teams = Team.query.all()

    teams = []
    for team in db_teams:
        team_path = os.path.join(UPLOAD_FOLDER, team.id)

        # Count images in team folder (if it exists)
        image_count = 0
        if os.path.exists(team_path) and os.path.isdir(team_path):
            image_count = len([f for f in os.listdir(team_path)
                              if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)])

        teams.append({
            'name': team.name,
            'id': team.id,
            'url': url_for('team_page', team_id=team.id),
            'image_count': image_count,
            'format': team.format,
            'estimated_duration': team.estimated_duration,
            'captain': team.captain,
            'created_at': team.created_at,
            'member_count': len([m for m in team.memberships if m.status == 'active']),
            'status': team.status,
            'comments': team.comments
        })

    # Get all users from database
    db_users = User.query.all()

    users = []
    for user in db_users:
        # Get active memberships for this user
        active_memberships = [m for m in user.memberships if m.status == 'active']

        users.append({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'avatar_url': user.avatar_url,
            'is_admin': user.is_admin,
            'created_at': user.created_at,
            'active_memberships': active_memberships
        })

    return render_template('admin.html', teams=teams, users=users, user=current_user)


@app.route('/team/<team_id>/delete', methods=['DELETE'])
@admin_required
def delete_team(team_id):

    try:
        # Find team in database by team_id
        team = find_team_by_id(team_id)

        if not team:
            return jsonify({'error': 'Team not found'}), 404

        # Delete team memberships first (due to foreign key constraints)
        if team:
            TeamMembership.query.filter_by(team_id=team.id).delete()
            db.session.delete(team)
            db.session.commit()

        # Remove the team folder and all its contents
        import shutil
        team_path = os.path.join(UPLOAD_FOLDER, team.id)
        if os.path.exists(team_path):
            shutil.rmtree(team_path)

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete team: {str(e)}'}), 500

@app.route('/user/<user_id>/delete', methods=['DELETE'])
@admin_required
def delete_user(user_id):

    try:
        # Find user in database
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check if user is a captain of any teams
        captained_teams = Team.query.filter_by(captain_id=user.id).all()

        for team in captained_teams:
            # Count active team members (excluding captain)
            active_members = TeamMembership.query.filter_by(
                team_id=team.id,
                status='active'
            ).filter(TeamMembership.user_id != user.id).count()

            # If team has other active members, cannot delete captain
            if active_members > 0:
                return jsonify({
                    'error': f'Cannot delete user. They are the captain of team "{team.name}" which has other active members. Please transfer captaincy first.'
                }), 400

        # Delete user's team memberships
        TeamMembership.query.filter_by(user_id=user.id).delete()

        # Delete any teams where user was the only captain
        for team in captained_teams:
            # Delete team folder if it exists
            team_folder = os.path.join(UPLOAD_FOLDER, team.id)
            if os.path.exists(team_folder):
                import shutil
                shutil.rmtree(team_folder)

            # Delete team from database
            db.session.delete(team)

        # Store user email for response message
        user_email = user.email
        user_name = user.name

        # Delete the user account
        db.session.delete(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'User "{user_name}" ({user_email}) deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete user: {str(e)}'}), 500

@app.route('/team/<team_id>/approve', methods=['POST'])
@admin_required
def approve_team(team_id):

    try:
        # Find team in database by team_id
        team = find_team_by_id(team_id)

        if not team:
            return jsonify({'error': 'Team not found'}), 404

        if team.status != 'pending':
            return jsonify({'error': 'Only pending teams can be approved'}), 400

        # Update team status to complete
        team.status = 'complete'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" approved successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to approve team: {str(e)}'}), 500

@app.route('/team/<team_id>/withdraw', methods=['POST'])
@team_captain_required()
def withdraw_team(team_id, team):

    if team.status == 'withdrawn':
        return jsonify({'error': 'Team is already withdrawn'}), 400

    if team.status != 'complete':
        return jsonify({'error': 'Only complete teams can be withdrawn'}), 400

    try:
        # Update team status to withdrawn
        team.status = 'withdrawn'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" withdrawn successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to withdraw team: {str(e)}'}), 500

@app.route('/team/<team_id>/unwithdraw', methods=['POST'])
@team_captain_required()
def unwithdraw_team(team_id, team):

    if team.status != 'withdrawn':
        return jsonify({'error': 'Team is not withdrawn'}), 400

    try:
        # Update team status back to complete
        team.status = 'complete'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" un-withdrawn successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to un-withdraw team: {str(e)}'}), 500

@app.route('/team/<team_id>/cancel', methods=['POST'])
@team_captain_required()
def cancel_team(team_id, team):

    if team.status != 'pending':
        return jsonify({'error': 'Only pending teams can be cancelled'}), 400

    if team.status == 'cancelled':
        return jsonify({'error': 'Team is already cancelled'}), 400

    try:
        # Update team status to cancelled
        team.status = 'cancelled'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" cancelled successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to cancel team: {str(e)}'}), 500

@app.route('/team/<team_id>/close', methods=['POST'])
@team_captain_required()
def close_team(team_id, team):

    if team.status != 'complete':
        return jsonify({'error': 'Only complete teams can be closed'}), 400

    if team.status == 'closed':
        return jsonify({'error': 'Team is already closed'}), 400

    try:
        # Update team status to closed
        team.status = 'closed'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" closed to new registrations'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to close team: {str(e)}'}), 500

@app.route('/team/<team_id>/reopen', methods=['POST'])
@team_captain_required()
def reopen_team(team_id, team):

    if team.status != 'closed':
        return jsonify({'error': 'Team is not closed'}), 400

    try:
        # Update team status back to complete
        team.status = 'complete'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" reopened for new registrations'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to reopen team: {str(e)}'}), 500

@app.route('/team/<team_id>/member/<membership_id>/withdraw', methods=['POST'])
@team_captain_or_member_required()
def withdraw_membership(team_id, membership_id, team, membership):
    try:

        if membership.status == 'withdrawn':
            return jsonify({'error': 'Membership is already withdrawn'}), 400

        # Update membership status to withdrawn
        membership.status = 'withdrawn'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully withdrawn from team "{membership.team.name}"'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to withdraw membership: {str(e)}'}), 500

@app.route('/team/<team_id>/member/<membership_id>/unwithdraw', methods=['POST'])
@team_captain_or_member_required()
def unwithdraw_membership(team_id, membership_id, team, membership):
    try:

        if membership.status != 'withdrawn':
            return jsonify({'error': 'Membership is not withdrawn'}), 400

        # Update membership status to active
        membership.status = 'active'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully re-joined team "{membership.team.name}"'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to re-join team: {str(e)}'}), 500

@app.route('/team/<team_id>/member/<membership_id>/remove', methods=['POST'])
@team_captain_required()
def remove_member(team_id, membership_id, team):
    try:
        # Find membership in database
        membership = db.session.get(TeamMembership, membership_id)
        if not membership:
            return jsonify({'error': 'Membership not found'}), 404

        # Can't remove the captain
        if membership.user_id == team.captain_id:
            return jsonify({'error': 'Cannot remove team captain'}), 400

        # Update membership status to removed
        membership.status = 'removed'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully removed {membership.user.name} from team "{team.name}"'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to remove member: {str(e)}'}), 500

@app.route('/account/delete', methods=['DELETE'])
@login_required
def delete_account():
    try:
        # Check if user is a captain of any teams
        captained_teams = Team.query.filter_by(captain_id=current_user.id).all()

        for team in captained_teams:
            # Count active team members (excluding withdrawn)
            active_members = TeamMembership.query.filter_by(
                team_id=team.id,
                status='active'
            ).count()

            # If team has more than just the captain, cannot delete
            if active_members > 1:
                return jsonify({
                    'error': f'Cannot delete account. You are the captain of team "{team.name}" which has other active members. Please transfer captaincy or have other members leave first.'
                }), 400

        # Delete user's team memberships
        TeamMembership.query.filter_by(user_id=current_user.id).delete()

        # Delete any teams where user was the only captain
        for team in captained_teams:
            # Delete team folder if it exists
            team_folder = os.path.join(UPLOAD_FOLDER, team.id)
            if os.path.exists(team_folder):
                import shutil
                shutil.rmtree(team_folder)

            # Delete team from database
            db.session.delete(team)

        # Delete the user account
        user_email = current_user.email
        db.session.delete(current_user)
        db.session.commit()

        # Log out the user
        logout_user()

        return jsonify({
            'success': True,
            'message': f'Account for {user_email} has been permanently deleted'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete account: {str(e)}'}), 500

@app.route('/team/<team_id>/promote/<new_captain_id>', methods=['POST'])
@team_captain_required()
def transfer_captain(team_id, new_captain_id, team):
    try:

        # Check if new captain is a member of the team
        new_captain = User.query.get(new_captain_id)
        if not new_captain:
            return jsonify({'error': 'New captain not found'}), 404

        # Verify new captain is an active member of this team
        membership = TeamMembership.query.filter_by(
            team_id=team.id,
            user_id=new_captain_id,
            status='active'
        ).first()

        if not membership:
            return jsonify({'error': 'New captain must be an active member of the team'}), 400

        # Transfer captaincy
        team.captain_id = new_captain_id
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully transferred captaincy to {new_captain.name}'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to transfer captaincy: {str(e)}'}), 500


@app.route('/team/<team_id>/details', methods=['POST'])
@team_captain_required()
def update_team_details(team_id, team):
    """
    Allows the team captain to update team details like estimated duration.
    """
    try:

        if team.status in ['withdrawn', 'cancelled']:
            return jsonify({'error': f'Cannot update details for a {team.status} team.'}), 403

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request data is required'}), 400

        estimated_duration = data.get('estimated_duration', '').strip()
        comments = data.get('comments', '').strip()
        has_baton = data.get('has_baton') == True

        # Validation
        if not estimated_duration:
            return jsonify({'error': 'Estimated duration is required'}), 400

        import re
        if not re.match(r'^\d{1,2}:\d{2}$', estimated_duration):
            return jsonify({'error': 'Duration must be in HH:MM format (e.g., 05:30 or 12:00)'}), 400

        team.estimated_duration = estimated_duration
        team.comments = comments if comments else None
        if team.status == 'pending':
            team.has_baton = has_baton
        db.session.commit()

        return jsonify({'success': True, 'message': 'Team details updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update team details: {str(e)}'}), 500


@app.route('/team/<team_id>/password', methods=['POST'])
@team_captain_required()
def manage_team_password(team_id, team):
    try:

        # Get password from request
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request data is required'}), 400

        password = data.get('password', '').strip() if data.get('password') else None

        if password:
            # Update team password
            team.password = password
            message = 'Team password updated successfully'
        else:
            # Remove team password
            team.password = None
            message = 'Team password removed successfully'

        db.session.commit()

        return jsonify({
            'success': True,
            'message': message
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to manage team password: {str(e)}'}), 500

@app.route('/team/<team_id>/invite-link', methods=['POST'])
@team_captain_required()
def generate_invite_link(team_id, team):
    try:

        # Generate a new secure, URL-safe token (22 characters)
        invite_token = secrets.token_urlsafe(16)
        team.invite_token = invite_token
        db.session.commit()

        # Construct the full invite URL
        invite_url = url_for('join_team', invite_token=invite_token, _external=True)

        return jsonify({
            'success': True,
            'invite_link': invite_url,
            'message': 'Invite link generated successfully. Share it with your team members.'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to generate invite link: {str(e)}'}), 500

@app.route('/privacy')
def privacy_policy():
    """Renders the privacy policy page."""
    return render_template('privacy.html')

# Initialize database
with app.app_context():
    db.create_all()
    print("Database initialized")

    for team in os.listdir(UPLOAD_FOLDER):
        team_path = os.path.join(UPLOAD_FOLDER, team)
        # Skip non-directories (like .DS_Store files)
        if not os.path.isdir(team_path):
            continue
        print(f"Team URL for {team}: /team/{get_team_hash(team)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)