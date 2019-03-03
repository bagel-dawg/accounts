from datetime import datetime, timedelta
from app import app,db,login_manager,ldap_manager,users
from ldap3 import Server, Connection, SUBTREE
from config import Config
from ldap3 import Server, Connection, SUBTREE
from flask_login import UserMixin

class EnrollFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(128))
    lastname = db.Column(db.String(128))
    uin = db.Column(db.String(128))
    email = db.Column(db.String(128))
    grad = db.Column(db.Boolean())


class EmailValidator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expiration = db.Column(db.DateTime, index=True, default=(datetime.utcnow() + timedelta(days=1)))
    user_id = db.Column(db.Integer, db.ForeignKey('enroll_file.id'))

class User(UserMixin):
    def __init__(self, dn, username, data):
        self.dn = dn
        self.username = username
        self.data = data

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn

    def is_active(self):
        return True




@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    user = User(dn, username, data)
    users[dn] = user
    return user