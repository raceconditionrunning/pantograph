from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone

db = SQLAlchemy()

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    short_id = db.Column(db.String(8), unique=True, nullable=False)  # Short random ID for URLs
    gallery_hash = db.Column(db.String(8), unique=True, nullable=False)  # Public gallery view hash
    format = db.Column(db.String(50), nullable=False)  # 'Solo' or 'Team'
    estimated_duration = db.Column(db.String(10), nullable=False)  # Format: 'HH:MM'
    comments = db.Column(db.Text, nullable=True)
    password = db.Column(db.String(255), nullable=True)  # Optional password for joining
    status = db.Column(db.String(20), nullable=False, default='pending')  # 'pending', 'complete', 'withdrawn'
    captain_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    captain = db.relationship('User', foreign_keys=[captain_id], backref='captained_teams')
    
    @property
    def members(self):
        """Get all users who are members of this team"""
        return [membership.user for membership in self.memberships]
    
    def __repr__(self):
        return f'<Team {self.name}>'

class TeamMembership(db.Model):
    __tablename__ = 'team_membership'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    
    # Join preferences
    willing_to_lead = db.Column(db.Boolean, nullable=False, default=False)
    preferred_miles = db.Column(db.Integer, nullable=True)
    planned_pace = db.Column(db.String(10), nullable=True)  # Format: 'MM:SS'
    preferred_station = db.Column(db.String(255), nullable=True)
    comments = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='active')  # 'active', 'withdrawn'
    
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships to User and Team
    user = db.relationship('User', backref='memberships')
    team = db.relationship('Team', backref='memberships')
    
    # Unique constraint to prevent duplicate memberships
    __table_args__ = (db.UniqueConstraint('user_id', 'team_id', name='unique_membership'),)
    
    def __repr__(self):
        return f'<TeamMembership {self.user.name} in {self.team.name}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    avatar_url = db.Column(db.String(500), nullable=True)
    provider = db.Column(db.String(50), nullable=False)  # 'google', 'github', or 'meta'
    provider_id = db.Column(db.String(255), nullable=False)  # OAuth provider user ID
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_admin = db.Column(db.Boolean, default=False)
    
    @property
    def teams(self):
        """Get all teams this user is a member of"""
        return [membership.team for membership in self.memberships]
    
    # Unique constraint on provider + provider_id
    __table_args__ = (db.UniqueConstraint('provider', 'provider_id', name='provider_user_uc'),)
    
    def is_captain_of(self, team):
        """Check if user is captain of a specific team"""
        return team.captain_id == self.id
    
    def get_captained_teams(self):
        """Get all teams this user captains"""
        return Team.query.filter_by(captain_id=self.id).all()
    
    def __repr__(self):
        return f'<User {self.email}>'