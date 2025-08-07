import datetime
import logging
from flask import Blueprint, request, redirect, render_template, abort, session, url_for
from flask_login import login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from app.models import db, User
from app.config import Config, OAUTH_PROVIDERS

auth = Blueprint('auth', __name__)


def init_oauth(oauth_instance):
    """Initialize OAuth providers with the OAuth instance from the main app"""
    # Configure OAuth providers
    google = oauth_instance.register(
        name='google',
        client_id=Config.GOOGLE_CLIENT_ID,
        client_secret=Config.GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

    github = oauth_instance.register(
        name='github',
        client_id=Config.GITHUB_CLIENT_ID,
        client_secret=Config.GITHUB_CLIENT_SECRET,
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )

    meta = oauth_instance.register(
        name='meta',
        client_id=Config.META_CLIENT_ID,
        client_secret=Config.META_CLIENT_SECRET,
        access_token_url='https://graph.facebook.com/oauth/access_token',
        authorize_url='https://www.facebook.com/dialog/oauth',
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'},
    )

    return google, github, meta


@auth.route('/login/<provider>')
def oauth_login(provider):
    if provider not in [p['name'] for p in OAUTH_PROVIDERS]:
        return abort(404)

    from flask import current_app
    oauth_instance = current_app.extensions.get('authlib.integrations.flask_client')
    client = oauth_instance.create_client(provider)

    # Store the 'next' parameter in the session
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url
    logging.warning(f"DEBUG: Storing next_url in session: {session.get('next_url')}")

    redirect_uri = url_for('auth.oauth_callback', provider=provider, _external=True)
    return client.authorize_redirect(redirect_uri)


@auth.route('/account/auth/<provider>')
def oauth_callback(provider):
    if provider not in [p['name'] for p in OAUTH_PROVIDERS]:
        return abort(404)

    from flask import current_app
    oauth_instance = current_app.extensions.get('authlib.integrations.flask_client')
    client = oauth_instance.create_client(provider)
    
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
            return redirect(url_for('auth.login', error='auth_failed'))

        if not email or not provider_id:
            return redirect(url_for('auth.login', error='missing_data'))

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
                return redirect(url_for('auth.login', error='email_exists'))

            # Create new user
            user = User(
                email=email,
                name=name,
                avatar_url=avatar_url,
                provider=provider,
                provider_id=provider_id,
                is_admin=(email == Config.ADMIN_EMAIL)  # Set admin based on configured email
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
            next_page = url_for('main.index')

        logging.warning(f"DEBUG: Redirecting to: {next_page}")
        return redirect(next_page)

    except Exception as e:
        print(f"OAuth error: {e}")
        return redirect(url_for('auth.login', error='auth_failed'))


@auth.route('/login')
def login():
    # If user is already logged in, redirect to next page or index
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('main.index'))

    error = request.args.get('error')
    error_messages = {
        'missing_data': 'Unable to retrieve user information from OAuth provider.',
        'email_exists': 'An account with this email already exists with a different provider.',
        'auth_failed': 'Authentication failed. Please try again.'
    }
    error_message = error_messages.get(error) if error else None

    # Preserve the next URL for the OAuth links
    next_url = request.args.get('next')

    return render_template('login.html', providers=OAUTH_PROVIDERS, error=error_message, next_url=next_url)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))