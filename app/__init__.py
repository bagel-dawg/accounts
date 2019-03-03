from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
import logging

from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager, login_user, UserMixin, current_user




app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
ldap_manager = LDAP3LoginManager(app)

users = {}

logging.basicConfig(level=logging.DEBUG,filename="accounts.log")
logging.getLogger('accounts-init').addHandler(logging.StreamHandler())
logger = logging.getLogger('accounts-init')



from app import routes, models, cron