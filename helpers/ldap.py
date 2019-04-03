from app import app,logging
from config import Config
from ldap3 import Server, Connection, SUBTREE, MODIFY_ADD, MODIFY_REPLACE

def AD_Connect_SSL():
  servname = app.config['LDAP_HOST']
  po = app.config['LDAP_PORT']
  dn = app.config['LDAP_BIND_USER_DN']
  pw = app.config['LDAP_BIND_USER_PW']
  server = Server(servname, port=int(po), use_ssl=True)
  logger.info('Attempting to connect to %s:%s using the user account %s' % (servname,po,dn))
  return Connection(server, user=dn, password=pw, auto_bind=True, return_empty_attributes=True)