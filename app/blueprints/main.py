from flask import Blueprint, render_template, current_app

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/payment')
def payment():
    return render_template('payment.html', contact_email=current_app.config['CONTACT_EMAIL'])


@main.route('/privacy')
def privacy_policy():
    """Renders the privacy policy page."""
    return render_template('privacy.html')