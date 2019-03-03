import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, '')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ENROLL_FILE = os.environ.get('ENROLL_FILE') or ''
    LDAP_SERVER = os.environ.get('LDAP_SERVER') or ''
    LDAP_PORT = os.environ.get('LDAP_PORT') or ''
    LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN') or ''
    LDAP_BIND_PW = os.environ.get('LDAP_BIND_PW') or ''
    LDAP_SEARCH_BASE = os.environ.get('LDAP_SEARCH_BASE') or ''
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or ''