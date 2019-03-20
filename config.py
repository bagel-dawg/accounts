import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or ''
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ENROLL_FILE = os.environ.get('ENROLL_FILE')
    LDAP_HOST = os.environ.get('LDAP_HOST') or ''
    LDAP_PORT = int(os.environ.get('LDAP_PORT')) or 389
    LDAP_BIND_USER_DN = os.environ.get('LDAP_BIND_DN') or ''
    LDAP_BIND_USER_PW = os.environ.get('LDAP_BIND_PW') or ''
    LDAP_SEARCH_BASE = os.environ.get('LDAP_SEARCH_BASE') or ''
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or ''
    APP_ADMIN_GROUP = os.environ.get('APP_ADMIN_GROUP') or ''
    SMTP_HOST = os.environ.get('SMTP_HOST') or ''
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME') or ''
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD') or ''
    SMTP_PORT = os.environ.get('SMTP_PORT') or ''
    SMTP_TLS = os.environ.get('SMTP_TLS') or True
    SMTP_FROM_ADDRESS = os.environ.get('SMTP_FROM_ADDRESS') or ''
    SMTP_LOGIN_REQUIRED = os.environ.get('SMTP_LOGIN_REQUIRED') or True
    SMTP_IGNORE_CERT = os.environ.get('SMTP_IGNORE_CERT') or True