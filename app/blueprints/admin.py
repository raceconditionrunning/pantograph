import os
import shutil
from flask import Blueprint, render_template, jsonify, url_for, request
from flask_login import current_user
from app.models import db, User, Team, TeamMembership, TeamStatus, TeamFormat, TeamMembershipStatus
from app.permissions import admin_required
from app.utils import is_allowed_image, format_mm_ss_from_seconds
from app.config import Config

admin = Blueprint('admin', __name__, url_prefix='/admin')


@admin.route('/')
@admin_required
def admin_dashboard():
    # Get all teams from database
    db_teams = Team.query.all()

    teams = []
    for team in db_teams:
        team_path = os.path.join(Config.UPLOAD_FOLDER, team.id)

        # Count images in team folder (if it exists)
        image_count = 0
        if os.path.exists(team_path) and os.path.isdir(team_path):
            image_count = len([f for f in os.listdir(team_path)
                              if os.path.isfile(os.path.join(team_path, f)) and is_allowed_image(f)])

        teams.append({
            'name': team.name,
            'id': team.id,
            'url': url_for('teams.gallery', team_id=team.id),
            'image_count': image_count,
            'format': team.format,
            'estimated_duration': format_mm_ss_from_seconds(team.estimated_duration_seconds),
            'captain': team.captain,
            'created_at': team.created_at,
            'member_count': len([m for m in team.memberships if m.status == TeamMembershipStatus.ACTIVE]),
            'status': team.status,
            'comments': team.comments,
            'baton_serial': team.baton_serial
        })

    # Get all users from database
    db_users = User.query.all()

    users = []
    for user in db_users:
        # Get active memberships for this user
        active_memberships = [m for m in user.memberships if m.status == TeamMembershipStatus.ACTIVE]

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


@admin.route('/team/<team_id>', methods=['DELETE'])
@admin_required
def delete_team(team_id):
    try:
        from app.utils import find_team_by_id
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
        team_path = os.path.join(Config.UPLOAD_FOLDER, team.id)
        if os.path.exists(team_path):
            shutil.rmtree(team_path)

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" deleted successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete team: {str(e)}'}), 500





@admin.route('/team/<team_id>/approve', methods=['POST'])
@admin_required
def approve_team(team_id):
    try:
        from app.utils import find_team_by_id
        # Find team in database by team_id
        team = find_team_by_id(team_id)

        if not team:
            return jsonify({'error': 'Team not found'}), 404

        if team.status != TeamStatus.PENDING:
            return jsonify({'error': 'Only pending teams can be approved'}), 400

        # Update team status - Solo teams go to 'closed', Team goes to 'open'
        if team.format == TeamFormat.SOLO:
            team.status = TeamStatus.CLOSED
        else:
            team.status = TeamStatus.OPEN
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Team "{team.name}" approved successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to approve team: {str(e)}'}), 500


@admin.route('/team/<team_id>/baton_serial', methods=['POST'])
@admin_required
def update_baton_serial(team_id):
    try:
        from app.utils import find_team_by_id
        team = find_team_by_id(team_id)
        if not team:
            return jsonify({'error': 'Team not found'}), 404

        data = request.get_json()
        new_serial = data.get('baton_serial')

        team.baton_serial = new_serial
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Baton serial for team "{team.name}" updated successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update baton serial: {str(e)}'}), 500