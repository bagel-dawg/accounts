import logging
import MySQLdb
from flask import Flask
from config import Config
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, UserMixin, current_user
from flask_ldap3_login import LDAP3LoginManager
from datetime import datetime, timedelta
import jinja2

def get_environment_variable(value, key):
    return os.getenv(key,value)

app = Flask(__name__)
app.config.from_object(Config)
app.jinja_env.filters['get_env'] = get_environment_variable

login_manager = LoginManager(app)
ldap_manager = LDAP3LoginManager(app)

users = {}

# Provides default implementation for methods that Flask-Login expects user objects to have
class User(UserMixin):
    def __init__(self, dn, username, email, data):
        self.dn = dn
        self.username = username
        self.email = email
        self.data = data

    def __repr__(self):
        return "User(%r/%r/%r/%r)" % (self.dn, self.username, self.email, self.data)

    def get_id(self):
        return self.dn

#Takes the unicode ID of a user and returns the corresponding user object
@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None

#Looks up user in LDAP and saves to our users dictionary in memory
@ldap_manager.save_user
def save_user(dn, username, email, data, memberships):
    user = User(dn, username, email, data)
    users[dn] = user
    return user

logging.basicConfig(level=logging.DEBUG,filename="accounts.log")
logging.getLogger('accounts-init').addHandler(logging.StreamHandler())
logger = logging.getLogger('accounts-init')

from app import routes