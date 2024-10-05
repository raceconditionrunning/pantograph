import os
import hashlib
import hmac
import time
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from flask import Flask, request, redirect, render_template, send_from_directory, jsonify, abort
from pillow_heif import register_heif_opener
from werkzeug.utils import secure_filename

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


SECRET_KEY = get_secret('url_key')


def get_team_hash(team_name):
    hmac_value = hmac.new(SECRET_KEY.encode('utf-8'), team_name.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac_value


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


@app.route('/')
def index():
    return abort(404)


@app.route('/team/<team_hash>')
def team_page(team_hash):
    team_folder = None
    for team in os.listdir(UPLOAD_FOLDER):
        if get_team_hash(team) == team_hash:
            team_folder = team
            break

    if not team_folder:
        return "Invalid team URL.", 404

    images = os.listdir(os.path.join(UPLOAD_FOLDER, team_folder))

    from datetime import datetime

    # Helper function to parse capture time
    def parse_capture_time(time_str):
        return datetime.strptime(time_str, "%Y:%m:%d %H:%M:%S") if time_str else None

    image_data = []
    for image in images:
        image_path = os.path.join(UPLOAD_FOLDER, team_folder, image)
        capture_time, gps_coordinates = get_exif_data(image_path)
        image_data.append((image, capture_time, gps_coordinates))

    # Sort by capture_time, defaulting to datetime.min for missing values
    image_data = sorted(image_data, key=lambda x: parse_capture_time(x[1]) or datetime.min)
    return render_template('team_page.html', team=team_folder, images=image_data, team_hash=team_hash)


@app.route('/team/<team_hash>/delete', methods=['DELETE'])
def delete_image(team_hash):
    team_folder = None
    for team in os.listdir(UPLOAD_FOLDER):
        if get_team_hash(team) == team_hash:
            team_folder = team
            break

    if not team_folder:
        return jsonify({"error": "Invalid team URL"}), 404

    filename = secure_filename(request.args.get('filename'))
    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, team_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "File not found"}), 404



@app.route('/team/<team_hash>/upload', methods=['POST'])
def upload_file(team_hash):
    team_folder = None
    for team in os.listdir(UPLOAD_FOLDER):
        if get_team_hash(team) == team_hash:
            team_folder = team
            break

    if not team_folder:
        return "Invalid team URL.", 404

    existing_images_count = len(os.listdir(os.path.join(UPLOAD_FOLDER, team_folder)))
    files = request.files.getlist('files')
    if not files:
        return "No files uploaded", 400

    if existing_images_count + len(files) > MAX_PHOTOS_PER_TEAM:
        return "Team photo limit exceeded.", 400

    save_path = os.path.join(UPLOAD_FOLDER, team_folder)
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

    return redirect(f'/team/{team_hash}')


def is_allowed_image(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/uploads/<team_hash>/<filename>')
def serve_image(team_hash, filename):
    if not is_allowed_image(filename):
        return abort(404, description="Invalid file type.")

    team_folder = next((team for team in os.listdir(UPLOAD_FOLDER) if get_team_hash(team) == team_hash), None)
    if not team_folder:
        return abort(404, description="Invalid team URL.")

    return send_from_directory(os.path.join(UPLOAD_FOLDER, team_folder), secure_filename(filename))


# Print team hashes at startup
with app.app_context():
    for team in os.listdir(UPLOAD_FOLDER):
        print(f"Team URL for {team}: /team/{get_team_hash(team)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)