import os
import json
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from app.config import Config


def format_hh_mm_from_seconds(total_seconds):
    """Converts total seconds to a HH:MM formatted string."""
    if total_seconds is None:
        return ""
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{hours:2d}:{minutes:02d}"

def format_mm_ss_from_seconds(total_seconds):
    """Converts total seconds to a MM:SS formatted string."""
    if total_seconds is None:
        return ""
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    return f"{minutes:2d}:{seconds:02d}"

def parse_hh_mm_to_seconds(duration_str):
    """Converts a HH:MM string to total seconds.
    Raises ValueError if format is incorrect or minutes are invalid.
    """
    if not duration_str:
        return 0

    parts = duration_str.split(':')
    if len(parts) != 2:
        raise ValueError("Duration must be in HH:MM format.")

    try:
        hours = int(parts[0])
        minutes = int(parts[1])
    except ValueError:
        raise ValueError("Duration components must be integers.")

    if not (0 <= minutes < 60):
        raise ValueError("Minutes component must be between 00 and 59.")

    return hours * 3600 + minutes * 60

def parse_mm_ss_to_seconds(pace_str):
    """Converts a MM:SS string to total seconds.
    Raises ValueError if format is incorrect or seconds are invalid.
    """
    if not pace_str:
        return 0

    parts = pace_str.split(':')
    if len(parts) != 2:
        raise ValueError("Pace must be in MM:SS format.")

    try:
        minutes = int(parts[0])
        seconds = int(parts[1])
    except ValueError:
        raise ValueError("Pace components must be integers.")

    if not (0 <= seconds < 60):
        raise ValueError("Seconds component must be between 00 and 59.")

    return minutes * 60 + seconds

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


def validate_image_content(file_content):
    """Validate image file content using magic numbers (file signatures)"""

    # Image file signatures (magic numbers)
    image_signatures = {
        b'\xFF\xD8\xFF': ['jpg', 'jpeg'],  # JPEG
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ['png'],  # PNG
        b'\x47\x49\x46\x38\x37\x61': ['gif'],  # GIF87a
        b'\x47\x49\x46\x38\x39\x61': ['gif'],  # GIF89a
        b'\x42\x4D': ['bmp'],  # BMP
        b'\x52\x49\x46\x46': ['webp'],  # WEBP (needs further validation)
        b'\x49\x49\x2A\x00': ['tiff'],  # TIFF (little endian)
        b'\x4D\x4D\x00\x2A': ['tiff'],  # TIFF (big endian)
    }

    if len(file_content) < 12:
        return False

    # Check magic numbers
    for signature, formats in image_signatures.items():
        if file_content.startswith(signature):
            return True

    # Special case for WEBP - needs additional validation
    if file_content.startswith(b'\x52\x49\x46\x46') and len(file_content) >= 12:
        if file_content[8:12] == b'WEBP':
            return True

    # Special case for HEIC/HEIF - check for ftyp box with HEIC brands
    if len(file_content) >= 24:
        # HEIC files start with ftyp box, check for various HEIC brand types
        heic_brands = [b'heic', b'heix', b'hevc', b'hevx', b'heim', b'heis', b'hevm', b'hevs', b'avci']

        # Look for ftyp box (starts at offset 4) and check brand at offset 8
        if file_content[4:8] == b'ftyp':
            brand = file_content[8:12]
            if brand in heic_brands:
                return True

            # Also check compatible brands starting at offset 16
            for i in range(16, min(len(file_content) - 3, 64), 4):
                if file_content[i:i+4] in heic_brands:
                    return True

    return False


def secure_filename_enhanced(filename):
    """Enhanced secure filename that removes more potential security risks"""
    from werkzeug.utils import secure_filename as werkzeug_secure_filename
    import re

    # Use werkzeug's secure_filename first
    filename = werkzeug_secure_filename(filename)

    # Additional security measures
    # Remove any remaining special characters and normalize
    filename = re.sub(r'[^\w\-_.]', '', filename)

    # Ensure filename is not empty
    if not filename or filename.startswith('.'):
        filename = 'upload.bin'

    # Limit filename length
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext

    return filename


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


def convert_heic_to_jpeg(heic_path, jpeg_path, quality=85):
    """Convert HEIC file to JPEG format using pillow-heif"""
    try:
        # pillow-heif is already registered in __init__.py
        image = Image.open(heic_path)

        # Convert to RGB if necessary (HEIC can be in other color spaces)
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Save as JPEG with specified quality
        image.save(jpeg_path, 'JPEG', quality=quality, optimize=True)
        return True
    except Exception as e:
        print(f"Error converting HEIC to JPEG: {e}")
        return False


def is_heic_file(filename):
    """Check if file is HEIC format"""
    return filename.lower().endswith(('.heic', '.heif'))