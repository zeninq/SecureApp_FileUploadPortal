# -*- coding: utf-8 -*-

import os

from flask import Flask
from flask_babel import Babel
from flask_mail import Mail
from flask_login import LoginManager, UserMixin
from flask_talisman import Talisman
import logging
from logging.handlers import RotatingFileHandler


# Flaskup!
FLASKUP_TITLE = 'Flaskup!'
FLASKUP_UPLOAD_FOLDER = '/tmp/flaskup'
FLASKUP_MAX_DAYS = 30
FLASKUP_KEY_LENGTH = 6
FLASKUP_DELETE_KEY_LENGTH = 4
FLASKUP_ADMINS = []
FLASKUP_NOTIFY = []
FLASKUP_NGINX_UPLOAD_MODULE_ENABLED = False
FLASKUP_NGINX_UPLOAD_MODULE_STORE = None
FLASKUP_MAX_CONTACTS = 10
FLASKUP_UPLOAD_PASSWORDS = []
FLASKUP_UPLOAD_PASSWORDS_CHECK = lambda a, b: a == b

# Flask
DEBUG = False
SECRET_KEY = None

# Babel
BABEL_DEFAULT_LOCALE = 'en'
BABEL_DEFAULT_TIMEZONE = 'UTC'

# Mail
DEFAULT_MAIL_SENDER = 'flaskup@example.com'
MAIL_SERVER = '127.0.0.1'
MAIL_PORT = 25

# Create our app
app = Flask(__name__)
app.config['DEBUG'] = False
app.config.from_object(__name__)
app.config.from_envvar('FLASKUP_CONFIG')

assert app.config['SECRET_KEY'] is not None, \
    "You must define SECRET_KEY"
assert app.config['FLASKUP_MAX_DAYS'] > 0
assert app.config['FLASKUP_KEY_LENGTH'] >= 1 \
    and app.config['FLASKUP_KEY_LENGTH'] <= 32
assert app.config['FLASKUP_DELETE_KEY_LENGTH'] >= 1 \
    and app.config['FLASKUP_DELETE_KEY_LENGTH'] <= 32
assert os.access(app.config['FLASKUP_UPLOAD_FOLDER'], os.W_OK), \
    "No write access to '%s'" % app.config['FLASKUP_UPLOAD_FOLDER']
if app.config['FLASKUP_NGINX_UPLOAD_MODULE_ENABLED']:
    assert app.config['FLASKUP_NGINX_UPLOAD_MODULE_STORE'] is not None, \
        "You must define FLASKUP_NGINX_UPLOAD_MODULE_STORE"
    assert not app.config['FLASKUP_NGINX_UPLOAD_MODULE_STORE'] == '', \
        "You must define FLASKUP_NGINX_UPLOAD_MODULE_STORE"
assert isinstance(app.config['FLASKUP_MAX_CONTACTS'], int) and \
    app.config['FLASKUP_MAX_CONTACTS'] >= 0, \
    "FLASKUP_MAX_CONTACTS must be an integer, greater than or equal to 0"


# Babel (i18n)
babel = Babel(app)

# Mail
mail = Mail(app)

# Detect local environment
is_local = os.environ.get("FLASK_ENV", "development") == "development"

# Configure basic CSP and enforce HTTPS
Talisman(
    app,
    content_security_policy={
        'default-src': [
            "'self'",
            "'unsafe-inline'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
        ]
    },
    force_https=not is_local,  # HTTPS only in production
    strict_transport_security=True,
    strict_transport_security_preload=True,
    strict_transport_security_max_age=31536000
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'   # route name for login page

# Minimal User class — simple single admin user for project purposes
class User(UserMixin):
    def __init__(self, user_id: str):
        self.id = user_id

# Loader callback used by flask-login to reload user object from session
@login_manager.user_loader
def load_user(user_id):
    # For this project we only support a single hardcoded admin 'admin'.
    # In a real app you'd load the user from a database.
    if user_id == 'admin':
        return User(user_id)
    return None

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure rotating log handler
log_file = os.path.join('logs', 'app.log')
handler = RotatingFileHandler(log_file, maxBytes=5000000, backupCount=5)

# Use a secure, timestamped format
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s'
)
handler.setFormatter(formatter)
handler.setLevel(logging.WARNING)

app.logger.addHandler(handler)
app.logger.setLevel(logging.WARNING)

# Load dependencies
import flaskup.views
import flaskup.filters
import flaskup.i18n
import flaskup.errorhandler
