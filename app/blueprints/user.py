import os
import shutil
import re
from flask import Blueprint, request, render_template, jsonify, redirect, url_for
from flask_login import login_required, current_user
from app.models import db, Team, TeamMembership
from app.utils import load_station_names
from app.config import Config
from app.permissions import user_self_or_admin_required

user = Blueprint('user', __name__)


@user.route('/create-team', methods=['GET', 'POST'])
def create_team():
    # Handle GET request (show form to all users, authenticated or not)
    if request.method == 'GET':
        return render_template('create_team.html', user=current_user)

    # Handle POST request - require authentication for actual submission
    if not current_user.is_authenticated:
        return jsonify({'error': 'Please sign in to create a team', 'redirect_to_login': True}), 401

    # Check if user is already associated with any team (as captain or member)
    existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
    existing_membership = TeamMembership.query.filter_by(user_id=current_user.id, status='active').first()

    if existing_captained_team and existing_captained_team.status not in ['withdrawn', 'cancelled']:
        return jsonify({'error': f'You have already created team "{existing_captained_team.name}"'}), 400

    if existing_membership and existing_membership.team.status not in ['withdrawn', 'cancelled']:
        return jsonify({'error': f'You are already a member of team "{existing_membership.team.name}"'}), 400

    # Handle POST request
    try:
        team_name = request.form.get('team_name', '').strip()
        format_type = request.form.get('format', '').strip()
        estimated_duration = request.form.get('estimated_duration', '').strip()
        comments = request.form.get('comments', '').strip()
        password = request.form.get('password', '').strip()
        previous_baton_serial = request.form.get('previous_baton_serial', '').strip()
        email_opt_in = request.form.get('email_opt_in') == 'true'

        # Validation
        if not team_name:
            return jsonify({'error': 'Team name is required'}), 400

        if format_type not in ['Solo', 'Team']:
            return jsonify({'error': 'Format must be Solo or Team'}), 400

        if not estimated_duration:
            return jsonify({'error': 'Estimated duration is required'}), 400

        # Validate duration format (HH:MM)
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
            previous_baton_serial=previous_baton_serial if previous_baton_serial else None,
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
            redirect_url = url_for('teams.team_members', team_id=new_team.id)
            message = 'Solo entry created successfully! You can edit your preferences anytime.'
        else:
            # Team format captains still need to set their preferences
            # No membership created here - they'll create it via join form
            redirect_url = url_for('user.join_team')
            message = 'Team created successfully! Now enter your preferences.'

        # Update email opt-in status for all team types
        current_user.email_opt_in = email_opt_in

        db.session.commit()

        team_folder_path = os.path.join(Config.UPLOAD_FOLDER, new_team.id)
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


@user.route('/join-team', methods=['GET', 'POST'])
def join_team():
    stations = load_station_names()[1:]

    if request.method == 'GET':
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

        # Get all teams with "Team" format and "complete" status (open for joining)
        # Exclude closed teams as they're not accepting new members
        open_teams = Team.query.filter_by(format='Team', status='complete').all()

        # For authenticated users, handle existing team logic
        if current_user.is_authenticated:
            existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
            existing_membership = TeamMembership.query.filter_by(user_id=current_user.id, status='active').first()
            pending_captain_team = None

            # Handle case where a captain just created a team and needs to join
            if not invited_team and existing_captained_team and existing_captained_team.status == 'pending' and not existing_membership:
                pending_captain_team = existing_captained_team

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
        else:
            # For unauthenticated users, show preview mode
            mode = 'preview'
            existing_team = None
            existing_membership = None
            pending_captain_team = None

        return render_template('participant_registration.html',
                             teams=open_teams,
                             stations=stations,
                             user=current_user,
                             mode=mode,
                             existing_team=existing_team,
                             existing_membership=existing_membership if current_user.is_authenticated else None,
                             pending_captain_team=pending_captain_team if current_user.is_authenticated else None,
                             invited_team=invited_team,
                             error_message=error_message)

    # Handle POST request - require authentication for actual submission
    if not current_user.is_authenticated:
        return jsonify({'error': 'Please sign in to join a team', 'redirect_to_login': True}), 401

    # Handle POST - delegate to shared handler
    return handle_team_registration_post(stations, mode='join')


@user.route('/my-registration', methods=['GET', 'POST'])
@login_required
def my_registration():
    """Handle editing existing team registration/preferences"""
    stations = load_station_names()[1:]

    # Check if user has existing membership or captained team
    existing_captained_team = Team.query.filter_by(captain_id=current_user.id).first()
    existing_membership = TeamMembership.query.filter_by(user_id=current_user.id).first()

    if not existing_membership and not existing_captained_team:
        # No existing registration, redirect to join team
        return redirect(url_for('user.join_team'))

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
                                 existing_membership=existing_membership,
                                 pending_captain_team=None)
        elif existing_captained_team:
            # If it's a solo team, they are redirected to team_members page
            if existing_captained_team.format == 'Solo':
                return redirect(url_for('teams.team_members', team_id=existing_captained_team.id))
            else:
                # This is a 'Team' format captain who needs to fill out their preferences
                # The mode should be 'join' as they are effectively joining their own team
                # And pending_captain_team should be set to display the banner
                return render_template('participant_registration.html',
                                     teams=[existing_captained_team],
                                     stations=stations,
                                     user=current_user,
                                     mode='join',
                                     existing_team=None,
                                     existing_membership=None,
                                     pending_captain_team=existing_captained_team)

    # Fallback (should ideally not be reached)
    return redirect(url_for('user.join_team'))

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
            'redirect_url': url_for('teams.team_members', team_id=team.id)
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to process registration: {str(e)}'}), 500

def _perform_user_deletion(user_to_delete):
    """Helper function to encapsulate user deletion logic."""
    try:
        # Check if user is a captain of any teams
        captained_teams = Team.query.filter_by(captain_id=user_to_delete.id).all()

        for team in captained_teams:
            # Count active team members (excluding captain)
            active_members = TeamMembership.query.filter_by(
                team_id=team.id,
                status='active'
            ).filter(TeamMembership.user_id != user_to_delete.id).count()

            # If team has other active members, cannot delete captain
            if active_members > 0:
                return False, f'Cannot delete user. They are the captain of team "{team.name}" which has other active members. Please transfer captaincy first.'

        # Delete user's team memberships
        TeamMembership.query.filter_by(user_id=user_to_delete.id).delete()

        # Delete any teams where user was the only captain
        for team in captained_teams:
            # Delete team folder if it exists
            team_folder = os.path.join(Config.UPLOAD_FOLDER, team.id)
            if os.path.exists(team_folder):
                shutil.rmtree(team_folder)

            # Delete team from database
            db.session.delete(team)

        # Store user email for response message
        user_email = user_to_delete.email
        user_name = user_to_delete.name

        # Delete the user account
        db.session.delete(user_to_delete)
        db.session.commit()

        return True, f'User "{user_name}" ({user_email}) deleted successfully'

    except Exception as e:
        db.session.rollback()
        return False, f'Failed to delete user: {str(e)}'


@user.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Endpoint to delete the current user's account"""
    from flask_login import logout_user
    success, message = _perform_user_deletion(current_user)
    if success:
        logout_user()
        return jsonify({'success': True, 'message': message}), 200
    else:
        return jsonify({'error': message}), 400


@user.route('/user/<user_id>', methods=['DELETE'])
@user_self_or_admin_required()
def delete_user(user_id, user):
    success, message = _perform_user_deletion(user)
    if success:
        return jsonify({'success': True, 'message': message}), 200
    else:
        return jsonify({'error': message}), 400