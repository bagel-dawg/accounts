#Short, useful function that may or may not deserve their own files.
from app import app,logging
from config import Config
from ldap3 import Server, Connection, SUBTREE, MODIFY_ADD, MODIFY_REPLACE
import ssl
import re

logging.getLogger('accounts-helpers').addHandler(logging.StreamHandler())
logger = logging.getLogger('accounts-helpers')

def is_admin(username):
    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_SEARCH_BASE']
    admin_group = app.config['APP_ADMIN_GROUP']
    s_filter='(&(objectClass=user)(memberof='+str(admin_group)+'))'
    conn.search(search_base=s_base, search_filter=s_filter, search_scope=SUBTREE, attributes = ['sAMAccountName'])
    for entry in conn.entries:
        if entry.sAMAccountName.value == username:
            return True
    return False

