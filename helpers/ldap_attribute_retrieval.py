from app import app,logging
from config import Config
from ldap3 import Server, Connection, SUBTREE, MODIFY_ADD, MODIFY_REPLACE

def check_exists_or_archived(email):
    exists = False
    archived = False
    absent = True
    if email:
        s_filter = '(mail='+str(email)+')'

        s_base = app.config['LDAP_SEARCH_BASE']
    
        logger.info('Searching LDAP for mail=%s' % email)
        conn = AD_Connect_SSL()
        conn.search(search_base=s_base, search_filter=s_filter, search_scope=SUBTREE, attributes = ['distinguishedName'])
        
        #Check if user exists and/or is archived
        if len(conn.entries > 0):
            exists = True
            absent = False
            if is_archived(email):
                archived = True
    
        conn.unbind()

    logger.debug('check_exists_or_archived: Exists: %s, Archived: %s, Absent: %s - Attributes: email:%s' % (exists, archived, absent, email))
    return {'exists' : exists, 'archived' : archived, 'absent' : absent }

def get_user_attributes(sAMAccountName):

    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_SEARCH_BASE']

    s_attributes = app.config['USER_INFORMATION_DISPLAYED']

    conn.search(search_base=s_base, search_filter='(sAMAccountName='+str(sAMAccountName)+')', search_scope=SUBTREE, attributes = s_attributes)

    return_dict = conn.entries[0]

    return return_dict

def is_archived(email):
    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_SEARCH_BASE']
    archived_group = app.config['LDAP_ARCHIVED_GROUP']
    s_filter='(&(objectClass=user)(memberof='+str(archived_group)+'))'
    conn.search(search_base=s_base, search_filter=s_filter, search_scope=SUBTREE, attributes = ['mail'])
    for entry in conn.entries:
        if entry.mail.value == email:
            return True
    return False