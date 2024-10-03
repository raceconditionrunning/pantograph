import os
import hashlib
import time
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from flask import Flask, request, redirect, render_template, send_from_directory, jsonify
from pillow_heif import register_heif_opener

# Register HEIC/AVIF opener for Pillow
register_heif_opener()

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
# Pull salt from environment variable
SALT = os.getenv('SALT')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_team_hash(team_name):
    return hashlib.sha256((team_name + SALT).encode()).hexdigest()


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
    return None


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
    image_data = []
    for image in images:
        image_path = os.path.join(UPLOAD_FOLDER, team_folder, image)
        capture_time, gps_coordinates = get_exif_data(image_path)
        image_data.append((image, capture_time, gps_coordinates))

    image_data = sorted(image_data, key=lambda x: os.path.getctime(os.path.join(UPLOAD_FOLDER, team_folder, x[0])))  # Sort by creation time
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

    filename = request.args.get('filename')
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

    file = request.files['file']
    if not file:
        return "No file uploaded", 400

    save_path = os.path.join(UPLOAD_FOLDER, team_folder)
    os.makedirs(save_path, exist_ok=True)

    # Save the file with a timestamped filename
    file_path = os.path.join(save_path, f"{int(time.time())}_{file.filename}")
    file.save(file_path)

    return redirect(f'/team/{team_hash}')


@app.route('/uploads/<team_hash>/<filename>')
def serve_image(team_hash, filename):
    team_folder = None
    for team in os.listdir(UPLOAD_FOLDER):
        if get_team_hash(team) == team_hash:
            team_folder = team
            break

    if not team_folder:
        return "Invalid team URL.", 404

    return send_from_directory(os.path.join(UPLOAD_FOLDER, team_folder), filename)


if __name__ == '__main__':
    for team in os.listdir(UPLOAD_FOLDER):
        print(f"Team URL for {team}: /team/{get_team_hash(team)}")
    app.run(host='0.0.0.0', port=5001)