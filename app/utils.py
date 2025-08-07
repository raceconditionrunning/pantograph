import os
import json
import hmac
import hashlib
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from app.config import Config


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


def get_exif_data(image_path):
    """Extract capture time and GPS coordinates from image EXIF metadata"""
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
    """Convert GPS EXIF data to decimal degrees"""
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


def is_allowed_image(filename):
    """Check if filename has allowed image extension"""
    return os.path.splitext(filename)[1].lower() in Config.ALLOWED_EXTENSIONS


def find_team_by_id(team_id):
    """Find team in database by id"""
    from app.models import Team
    return Team.query.filter_by(id=team_id).first()


def find_team_by_gallery_hash(gallery_hash):
    """Find team in database by gallery_hash"""
    from app.models import Team
    return Team.query.filter_by(gallery_hash=gallery_hash).first()


def parse_exif_datetime(exif_datetime_str):
    """Parse EXIF datetime string to Python datetime"""
    if not exif_datetime_str:
        return None
    try:
        from datetime import datetime
        return datetime.strptime(exif_datetime_str, "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return None


def get_mime_type(file_path):
    """Get MIME type from file extension"""
    import mimetypes
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or 'application/octet-stream'