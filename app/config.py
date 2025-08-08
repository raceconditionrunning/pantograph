import os


def get_secret(secret_name):
    """Get secrets from environment, Docker secrets, or local files"""
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


class Config:
    # Application Name
    APPLICATION_NAME = "Pantograph"

    # Core Flask configuration
    SECRET_KEY = get_secret('URL_KEY')

    # Database configuration - use data directory for persistence
    db_path = os.path.join(os.getcwd(), 'data', 'snappy.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # OAuth configuration
    GOOGLE_CLIENT_ID = get_secret('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = get_secret('GOOGLE_CLIENT_SECRET')
    GITHUB_CLIENT_ID = get_secret('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = get_secret('GITHUB_CLIENT_SECRET')
    MICROSOFT_CLIENT_ID = get_secret('MICROSOFT_CLIENT_ID')
    MICROSOFT_CLIENT_SECRET = get_secret('MICROSOFT_CLIENT_SECRET')

    # Admin configuration
    ADMIN_EMAIL = get_secret('ADMIN_EMAIL')
    CONTACT_EMAIL = get_secret('CONTACT_EMAIL')

    # Upload configuration
    UPLOAD_FOLDER = './uploads'
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_PHOTOS_PER_TEAM = 23
    ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.heic', '.tiff'}


# OAuth providers configuration for templates
OAUTH_PROVIDERS = [
    {'name': 'google', 'display_name': 'Google'},
    {'name': 'github', 'display_name': 'GitHub'},
    {'name': 'microsoft', 'display_name': 'Microsoft'}
]