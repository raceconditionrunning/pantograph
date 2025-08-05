import os
import hashlib
import hmac
import time
import datetime
import json
import random
import string
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from flask import Flask, request, redirect, render_template, send_from_directory, jsonify, abort, session, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from pillow_heif import register_heif_opener
from werkzeug.utils import secure_filename
from models import db, User, Team, TeamMembership

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
    return db.session.get(User, int(user_id))

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


def generate_short_id(length=8):
    """Generate short random ID like 'k3x9p2m7'"""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    while True:
        short_id = ''.join(random.choice(chars) for _ in range(length))
        if not Team.query.filter_by(short_id=short_id).first():
            return short_id


def generate_gallery_hash(length=8):
    """Generate separate public gallery hash"""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    while True:
        gallery_hash = ''.join(random.choice(chars) for _ in range(length))
        if not Team.query.filter_by(gallery_hash=gallery_hash).first():
            return gallery_hash


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
    # Pass the next parameter through the OAuth flow
    next_page = request.args.get('next')
    redirect_uri = url_for('oauth_callback', provider=provider, next=next_page, _external=True)
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

        # Redirect to the original page or index if no next parameter
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
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


def find_team_by_short_id(short_id):
    """Find team in database by short_id"""
    return Team.query.filter_by(short_id=short_id).first()


def find_team_by_gallery_hash(gallery_hash):
    """Find team in database by gallery_hash"""
    return Team.query.filter_by(gallery_hash=gallery_hash).first()


# New team management route using short_id
@app.route('/team/<short_id>/gallery')
def team_page(short_id):
    # Find team in database by short_id
    team = find_team_by_short_id(short_id)

    if not team:
        return "Invalid team URL.", 404

    # Check access permissions
    if not check_team_access(team):
        abort(403)

    team_path = os.path.join(UPLOAD_FOLDER, team.short_id)

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
    return render_template('gallery.html', team=team, images=image_data, short_id=short_id)


# Public gallery route (view-only)
@app.route('/gallery/<gallery_hash>')
def public_gallery(gallery_hash):
    # Find team in database by gallery_hash
    team = find_team_by_gallery_hash(gallery_hash)

    if not team:
        return "Invalid gallery URL.", 404

    team_path = os.path.join(UPLOAD_FOLDER, team.short_id)

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


def check_team_access(team):
    """Check if current user has access to team (member, captain, or admin)"""
    if not current_user.is_authenticated:
        return False

    # Admin has access to all teams
    if current_user.is_admin:
        return True

    # Captain has access to their own team
    if team.captain_id == current_user.id:
        return True

    # Team members have access
    membership = TeamMembership.query.filter_by(user_id=current_user.id, team_id=team.id).first()
    return membership is not None


@app.route('/team/<short_id>/members')
@login_required
def team_members(short_id):
    # Find team in database by short_id
    team = find_team_by_short_id(short_id)

    if not team:
        return "Invalid team URL.", 404

    # Check access permissions
    if not check_team_access(team):
        abort(403)

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
                         short_id=short_id,
                         willing_leaders_count=willing_leaders_count,
                         avg_preferred_miles=avg_preferred_miles)


@app.route('/team/<short_id>/delete', methods=['DELETE'])
def delete_image(short_id):
    # Find team in database by short_id
    team = find_team_by_short_id(short_id)

    if not team:
        return jsonify({"error": "Invalid team URL"}), 404

    filename = secure_filename(request.args.get('filename'))
    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, team.short_id, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "File not found"}), 404



@app.route('/team/<short_id>/upload', methods=['POST'])
@login_required
def upload_file(short_id):
    # Find team in database by short_id
    team = find_team_by_short_id(short_id)

    if not team:
        return "Invalid team URL.", 404

    # Check if team is in pending status
    if team.status == 'pending':
        return "Photo uploads are not allowed for pending teams. Please wait for admin approval.", 403

    # Check if team has been withdrawn
    if team.status == 'withdrawn':
        return "Photo uploads are not allowed for withdrawn teams.", 403

    # Check if current user has access to this team
    if not check_team_access(team):
        return "You do not have permission to upload photos for this team.", 403

    # Check if current user is removed from this team
    if current_user.id != team.captain_id:  # Captain is never "removed"
        membership = TeamMembership.query.filter_by(user_id=current_user.id, team_id=team.id).first()
        if not membership or membership.status in ['removed', 'withdrawn']:
            return "You cannot upload photos because you have been removed from this team or have withdrawn.", 403

    team_path = os.path.join(UPLOAD_FOLDER, team.short_id)
    existing_images_count = 0
    if os.path.exists(team_path) and os.path.isdir(team_path):
        existing_images_count = len([f for f in os.listdir(team_path)
                                   if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)])
    files = request.files.getlist('files')
    if not files:
        return "No files uploaded", 400

    if existing_images_count + len(files) > MAX_PHOTOS_PER_TEAM:
        return "Team photo limit exceeded.", 400

    save_path = os.path.join(UPLOAD_FOLDER, team.short_id)
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

    return redirect(url_for('team_page', short_id=team.short_id))


def is_allowed_image(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<short_id>/<filename>')
def serve_image(short_id, filename):
    if not is_allowed_image(filename):
        return abort(404, description="Invalid file type.")

    # Find team in database by short_id
    team = find_team_by_short_id(short_id)
    if not team:
        return abort(404, description="Invalid team URL.")

    return send_from_directory(os.path.join(UPLOAD_FOLDER, team.short_id), secure_filename(filename))


@app.route('/login')
def login():
    # If user is already logged in, redirect to index
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    error = request.args.get('error')
    error_messages = {
        'missing_data': 'Unable to retrieve user information from OAuth provider.',
        'email_exists': 'An account with this email already exists with a different provider.',
        'auth_failed': 'Authentication failed. Please try again.'
    }
    error_message = error_messages.get(error) if error else None

    return render_template('login.html', providers=oauth_providers, error=error_message)

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
    existing_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()

    if existing_captained_team:
        return jsonify({'error': f'You have already created team "{existing_captained_team.name}"'}), 400

    if existing_membership:
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
            short_id=generate_short_id(),
            gallery_hash=generate_gallery_hash(),
            format=format_type,
            estimated_duration=estimated_duration,
            comments=comments if comments else None,
            password=password if password else None,
            status='pending',
            captain_id=current_user.id
        )

        db.session.add(new_team)
        db.session.commit()

        # Create the team folder using short_id
        team_folder_path = os.path.join(UPLOAD_FOLDER, new_team.short_id)
        os.makedirs(team_folder_path, exist_ok=True)

        # For solo teams, redirect directly to team members page since no preferences needed
        if format_type == 'Solo':
            redirect_url = url_for('team_members', short_id=new_team.short_id)
            message = 'Solo team created successfully!'
        else:
            redirect_url = url_for('join_team')
            message = 'Team created successfully! Now enter your preferences.'

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
        existing_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()

        # Get all teams with "Team" format and "complete" status (open for joining)
        open_teams = Team.query.filter_by(format='Team', status='complete').all()

        # Determine mode and setup template data
        if existing_membership or existing_captained_team:
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
                             existing_membership=existing_membership)

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
            return redirect(url_for('team_members', short_id=existing_captained_team.short_id))
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

        # Check if user is already associated with any team (as captain or member)
        existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
        existing_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()

        # Validation
        if not team_id:
            return jsonify({'error': 'Please select a team'}), 400

        team = db.session.get(Team, team_id)
        if not team:
            return jsonify({'error': 'Selected team not found'}), 400

        # Handle team switching (user joining different team)
        is_switching_teams = existing_membership and existing_membership.team_id != int(team_id)

        if mode == 'edit':
            # For edit mode, verify they're editing the correct team
            if existing_captained_team and existing_captained_team.id != team.id:
                return jsonify({'error': 'You can only edit preferences for your own team'}), 400
            if existing_membership and not is_switching_teams and existing_membership.team_id != team.id:
                return jsonify({'error': 'You can only edit preferences for your current team'}), 400
        elif mode == 'join':
            # For joining, check format requirements
            if team.format != 'Team':
                return jsonify({'error': 'This team is not open for joining'}), 400

            # Check team password if required
            if team.password:
                if not team_password:
                    return jsonify({'error': 'This team requires a password'}), 400
                if team_password != team.password:
                    return jsonify({'error': 'Incorrect team password'}), 400

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

        db.session.commit()

        return jsonify({
            'success': True,
            'message': message,
            'team_name': team.name,
            'redirect_url': url_for('team_members', short_id=team.short_id)
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to process registration: {str(e)}'}), 500

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)

    # Get all teams from database
    db_teams = Team.query.all()

    teams = []
    for team in db_teams:
        team_path = os.path.join(UPLOAD_FOLDER, team.short_id)

        # Count images in team folder (if it exists)
        image_count = 0
        if os.path.exists(team_path) and os.path.isdir(team_path):
            image_count = len([f for f in os.listdir(team_path)
                              if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)])

        teams.append({
            'name': team.name,
            'short_id': team.short_id,
            'url': url_for('team_page', short_id=team.short_id),
            'image_count': image_count,
            'format': team.format,
            'estimated_duration': team.estimated_duration,
            'captain': team.captain,
            'created_at': team.created_at,
            'member_count': len([m for m in team.memberships if m.status == 'active']),
            'status': team.status
        })

    return render_template('admin.html', teams=teams, user=current_user)


@app.route('/team/<short_id>/delete', methods=['DELETE'])
@login_required
def delete_team(short_id):
    if not current_user.is_admin:
        abort(403)

    try:
        # Find team in database by short_id
        team = find_team_by_short_id(short_id)

        if not team:
            return jsonify({'error': 'Team not found'}), 404

        # Delete team memberships first (due to foreign key constraints)
        if team:
            TeamMembership.query.filter_by(team_id=team.id).delete()
            db.session.delete(team)
            db.session.commit()

        # Remove the team folder and all its contents
        import shutil
        team_path = os.path.join(UPLOAD_FOLDER, team.short_id)
        if os.path.exists(team_path):
            shutil.rmtree(team_path)

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete team: {str(e)}'}), 500

@app.route('/team/<short_id>/approve', methods=['POST'])
@login_required
def approve_team(short_id):
    if not current_user.is_admin:
        abort(403)

    try:
        # Find team in database by short_id
        team = find_team_by_short_id(short_id)

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

@app.route('/team/<short_id>/withdraw', methods=['POST'])
@login_required
def withdraw_team(short_id):
    # Find team in database by short_id
    team = find_team_by_short_id(short_id)

    if not team:
        return jsonify({'error': 'Team not found'}), 404

    # Check if user is admin or team captain
    if not (current_user.is_admin or team.captain_id == current_user.id):
        abort(403)

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

@app.route('/team/<short_id>/unwithdraw', methods=['POST'])
@login_required
def unwithdraw_team(short_id):
    # Find team in database by short_id
    team = find_team_by_short_id(short_id)

    if not team:
        return jsonify({'error': 'Team not found'}), 404

    # Check if user is admin or team captain
    if not (current_user.is_admin or team.captain_id == current_user.id):
        abort(403)

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

@app.route('/team/<short_id>/member/<int:membership_id>/withdraw', methods=['POST'])
@login_required
def withdraw_membership(short_id, membership_id):
    try:
        # Find membership in database
        membership = db.session.get(TeamMembership, membership_id)

        if not membership:
            return jsonify({'error': 'Membership not found'}), 404

        # Check if user is the member or admin
        if not (current_user.id == membership.user_id or current_user.is_admin):
            abort(403)

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

@app.route('/team/<short_id>/member/<int:membership_id>/unwithdraw', methods=['POST'])
@login_required
def unwithdraw_membership(short_id, membership_id):
    try:
        # Find membership in database
        membership = db.session.get(TeamMembership, membership_id)

        if not membership:
            return jsonify({'error': 'Membership not found'}), 404

        # Check if user is the member or admin
        if not (current_user.id == membership.user_id or current_user.is_admin):
            abort(403)

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

@app.route('/team/<short_id>/member/<int:membership_id>/remove', methods=['POST'])
@login_required
def remove_member(short_id, membership_id):
    try:
        # Find membership in database
        membership = db.session.get(TeamMembership, membership_id)
        if not membership:
            return jsonify({'error': 'Membership not found'}), 404

        # Find the team
        team = db.session.get(Team, membership.team_id)
        if not team:
            return jsonify({'error': 'Team not found'}), 404

        # Check if user is the team captain
        if current_user.id != team.captain_id:
            return jsonify({'error': 'Only team captains can remove members'}), 403

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
            team_folder = os.path.join(UPLOAD_FOLDER, team.short_id)
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

@app.route('/team/<short_id>/promote/<int:new_captain_id>', methods=['POST'])
@login_required
def transfer_captain(short_id, new_captain_id):
    try:
        # Find team by short_id
        team = find_team_by_short_id(short_id)
        if not team:
            return jsonify({'error': 'Team not found'}), 404

        # Check if current user is the captain
        if team.captain_id != current_user.id:
            return jsonify({'error': 'Only the current captain can transfer captaincy'}), 403

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

@app.route('/team/<short_id>/password', methods=['POST'])
@login_required
def manage_team_password(short_id):
    try:
        # Find team by short_id
        team = find_team_by_short_id(short_id)
        if not team:
            return jsonify({'error': 'Team not found'}), 404

        # Check if current user is the captain or admin
        if not (current_user.is_admin or team.captain_id == current_user.id):
            return jsonify({'error': 'Only team captains or admins can manage team passwords'}), 403

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