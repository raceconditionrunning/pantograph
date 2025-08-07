import os
import time
import hashlib
import secrets
from datetime import datetime
from flask import Blueprint, request, redirect, render_template, send_from_directory, jsonify, abort, url_for
from flask_login import current_user
from werkzeug.utils import secure_filename
from app.models import db, Team, TeamMembership
from app.permissions import (
    team_access_required, team_captain_required,
    team_captain_or_member_required, team_upload_allowed
)
from app.utils import get_exif_data, is_allowed_image, find_team_by_id, find_team_by_gallery_hash, load_station_names
from app.config import Config

teams = Blueprint('teams', __name__, url_prefix='/team')

# Also register the public gallery and uploads routes without prefix
teams_public = Blueprint('teams_public', __name__)


@teams.route('/<team_id>/gallery')
@team_access_required()
def gallery(team_id, team):
    from app.models import Image

    # Get images from database
    images = Image.query.filter_by(team_id=team.id).order_by(Image.capture_time.asc(), Image.upload_time.asc()).all()

    # Format image data for template
    image_data = []
    for image in images:
        # Format capture time as string for consistency with old format
        capture_time_str = image.capture_time.strftime("%Y:%m:%d %H:%M:%S") if image.capture_time else None
        gps_coordinates = (image.gps_lat, image.gps_lng) if image.gps_lat and image.gps_lng else None

        image_data.append({
            'id': image.id,
            'filename': os.path.basename(image.file_path),  # For URL generation
            'original_filename': image.filename,
            'capture_time': capture_time_str,
            'gps_coordinates': gps_coordinates,
            'uploader': image.uploader,
            'upload_time': image.upload_time,
            'file_size': image.file_size,
            'mime_type': image.mime_type
        })

    return render_template('gallery.html', team=team, images=image_data, team_id=team_id)


@teams_public.route('/gallery/<gallery_hash>')
def public_gallery(gallery_hash):
    from app.models import Image

    # Find team in database by gallery_hash
    team = find_team_by_gallery_hash(gallery_hash)

    if not team:
        return "Invalid gallery URL.", 404

    # Get images from database
    images = Image.query.filter_by(team_id=team.id).order_by(Image.capture_time.asc(), Image.upload_time.asc()).all()

    # Format image data for template (same as team gallery but read-only)
    image_data = []
    for image in images:
        # Format capture time as string for consistency with old format
        capture_time_str = image.capture_time.strftime("%Y:%m:%d %H:%M:%S") if image.capture_time else None
        gps_coordinates = (image.gps_lat, image.gps_lng) if image.gps_lat and image.gps_lng else None

        image_data.append({
            'id': image.id,
            'filename': os.path.basename(image.file_path),  # For URL generation
            'original_filename': image.filename,
            'capture_time': capture_time_str,
            'gps_coordinates': gps_coordinates,
            'uploader': image.uploader,
            'upload_time': image.upload_time,
            'file_size': image.file_size,
            'mime_type': image.mime_type
        })

    return render_template('gallery.html', team=team, images=image_data, gallery_hash=gallery_hash)


@teams.route('/<team_id>/members')
@team_access_required()
def team_members(team_id, team):
    # If the current user is the captain and hasn't completed their registration for this team,
    # redirect them to their registration page.
    if current_user.is_authenticated and current_user.id == team.captain_id:
        captain_membership = TeamMembership.query.filter_by(team_id=team.id, user_id=current_user.id).first()
        if not captain_membership:
            return redirect(url_for('user.my_registration'))

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


@teams.route('/<team_id>/images/<image_id>', methods=['DELETE'])
@team_upload_allowed()
def delete_image(team_id, image_id, team):
    """Delete a specific image by ID"""
    from app.models import Image

    # Find the image
    image = Image.query.filter_by(id=image_id, team_id=team.id).first()
    if not image:
        return jsonify({"error": "Image not found"}), 404

    # Check permissions - only uploader, captain, or admin can delete
    if not (current_user.is_admin or
            team.captain_id == current_user.id or
            image.uploaded_by == current_user.id):
        return jsonify({"error": "Permission denied"}), 403

    # Delete the physical file
    file_path = os.path.join(Config.UPLOAD_FOLDER, image.file_path)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Delete the database record
    db.session.delete(image)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Image '{image.filename}' deleted successfully"
    })


@teams.route('/<team_id>/images', methods=['POST'])
@team_upload_allowed()
def upload_images(team_id, team):
    """Upload images with database tracking"""
    from app.models import Image
    from app.utils import get_exif_data, parse_exif_datetime, get_mime_type

    # Check existing image count from database
    existing_images_count = Image.query.filter_by(team_id=team.id).count()

    files = request.files.getlist('files')
    if not files:
        return jsonify({"error": "No files uploaded"}), 400

    if existing_images_count + len(files) > Config.MAX_PHOTOS_PER_TEAM:
        return jsonify({"error": "Team photo limit exceeded"}), 400

    save_path = os.path.join(Config.UPLOAD_FOLDER, team.id)
    os.makedirs(save_path, exist_ok=True)

    uploaded_images = []

    for file in files:
        if not file.filename:
            continue

        file_content = file.read()
        if len(file_content) > Config.MAX_FILE_SIZE:
            return jsonify({"error": "File size exceeds 10MB limit"}), 400

        if not is_allowed_image(file.filename):
            continue

        # Compute hash of the file to check for duplicates
        file_hash = hashlib.md5(file_content).hexdigest()

        # Check for duplicate files in database
        existing_image = Image.query.join(Image.team).filter(
            Image.team_id == team.id
        ).all()

        is_duplicate = False
        for img in existing_image:
            img_path = os.path.join(Config.UPLOAD_FOLDER, img.file_path)
            if os.path.exists(img_path):
                with open(img_path, 'rb') as f:
                    existing_file_hash = hashlib.md5(f.read()).hexdigest()
                    if file_hash == existing_file_hash:
                        is_duplicate = True
                        break

        if is_duplicate:
            continue  # Skip saving this file as it is a duplicate

        # Generate unique filename
        timestamp = int(time.time())
        safe_filename = secure_filename(file.filename)
        stored_filename = f"{timestamp}_{safe_filename}"
        file_path = os.path.join(save_path, stored_filename)

        # Save file to disk
        with open(file_path, 'wb') as f:
            f.write(file_content)

        # Extract EXIF data
        capture_time_str, gps_coordinates = get_exif_data(file_path)
        capture_time = parse_exif_datetime(capture_time_str)
        gps_lat, gps_lng = gps_coordinates if gps_coordinates else (None, None)

        # Create Image record
        image = Image(
            filename=file.filename,
            file_path=os.path.join(team.id, stored_filename),
            team_id=team.id,
            uploaded_by=current_user.id,
            capture_time=capture_time,
            gps_lat=gps_lat,
            gps_lng=gps_lng,
            file_size=len(file_content),
            mime_type=get_mime_type(file.filename)
        )

        db.session.add(image)
        uploaded_images.append({
            'id': image.id,
            'filename': image.filename,
            'capture_time': capture_time_str,
            'gps_coordinates': gps_coordinates
        })

    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'{len(uploaded_images)} images uploaded successfully',
        'images': uploaded_images
    })


@teams_public.route('/<team_id>/images/<filename>')
def serve_image(team_id, filename):
    if not is_allowed_image(filename):
        return abort(404, description="Invalid file type.")

    # Find team in database by team_id
    team = find_team_by_id(team_id)
    if not team:
        return abort(404, description="Invalid team URL.")

    return send_from_directory(os.path.join(Config.UPLOAD_FOLDER, team.id), secure_filename(filename))


@teams.route('/<team_id>/withdraw', methods=['POST'])
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


@teams.route('/<team_id>/unwithdraw', methods=['POST'])
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


@teams.route('/<team_id>/cancel', methods=['POST'])
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


@teams.route('/<team_id>/close', methods=['POST'])
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


@teams.route('/<team_id>/reopen', methods=['POST'])
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


@teams.route('/<team_id>/members/<user_id>')
@team_captain_required()
def view_member(team_id, team, user_id):
    """View a specific team member's registration details (admin only)"""

    # Find the membership for this team+user combination
    membership = TeamMembership.query.filter_by(team_id=team_id, user_id=user_id).first()
    if not membership:
        return redirect(url_for('admin.admin_dashboard'))

    stations = load_station_names()[1:]

    return render_template('participant_registration.html',
                         teams=[],
                         stations=stations,
                         user=membership.user,
                         mode='view',
                         existing_team=membership.team,
                         existing_membership=membership,
                         view_only=True)

@teams.route('/<team_id>/members/<user_id>/withdraw', methods=['POST'])
@team_captain_or_member_required()
def withdraw_membership(team_id, user_id, team, membership):
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


@teams.route('/<team_id>/members/<user_id>/unwithdraw', methods=['POST'])
@team_captain_or_member_required()
def unwithdraw_membership(team_id, user_id, team, membership):
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


@teams.route('/<team_id>/members/<user_id>/remove', methods=['POST'])
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


@teams.route('/<team_id>/members/<user_id>/promote', methods=['POST'])
@team_captain_required()
def transfer_captain(team_id, user_id, team):
    try:
        from app.models import User
        # Check if new captain is a member of the team
        new_captain = User.query.get(user_id)
        if not new_captain:
            return jsonify({'error': 'New captain not found'}), 404

        # Verify new captain is an active member of this team
        membership = TeamMembership.query.filter_by(
            team_id=team.id,
            user_id=user_id,
            status='active'
        ).first()

        if not membership:
            return jsonify({'error': 'New captain must be an active member of the team'}), 400

        # Transfer captaincy
        team.captain_id = user_id
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Successfully transferred captaincy to {new_captain.name}'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to transfer captaincy: {str(e)}'}), 500


@teams.route('/<team_id>/details', methods=['POST'])
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


@teams.route('/<team_id>/password', methods=['POST'])
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


@teams.route('/<team_id>/invite-link', methods=['POST'])
@team_captain_required()
def generate_invite_link(team_id, team):
    try:
        # Generate a new secure, URL-safe token (22 characters)
        invite_token = secrets.token_urlsafe(16)
        team.invite_token = invite_token
        db.session.commit()

        # Construct the full invite URL
        invite_url = url_for('user.join_team', invite_token=invite_token, _external=True)

        return jsonify({
            'success': True,
            'invite_link': invite_url,
            'message': 'Invite link generated successfully. Share it with your team members.'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to generate invite link: {str(e)}'}), 500