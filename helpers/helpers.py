#Short, useful function that may or may not deserve their own files.
from app import app,logging
from config import Config
from ldap3 import Server, Connection, SUBTREE, MODIFY_ADD, MODIFY_REPLACE
from itsdangerous import URLSafeTimedSerializer
import re

logging.getLogger('accounts-helpers').addHandler(logging.StreamHandler())
logger = logging.getLogger('accounts-helpers')

def AD_Connect_SSL():
  servname = app.config['LDAP_HOST']
  po = app.config['LDAP_PORT']
  dn = app.config['LDAP_BIND_DN']
  pw = app.config['LDAP_BIND_PW']
  server = Server(servname, port=int(po), use_ssl=True)
  return Connection(server, user=dn, password=pw, auto_bind=True, return_empty_attributes=True)


def check_exists_or_archived(email):
    exists = False
    archived = False
    absent = True
    if email:
        s_filter = '(mail='+str(email)+')'

        s_base = app.config['LDAP_BASE_DN']
        archived_base = app.config['LDAP_ARCHIVED_BASE']
    
        conn = AD_Connect_SSL()
        conn.search(search_base=s_base, search_filter=s_filter, search_scope=SUBTREE, attributes = ['distinguishedName'])
        dn = conn.entries[0].distinguishedName
        
        #Check if user exists and/or is archived
        if len(conn.entries > 0):
            exists = True
            absent = False
            if archived_base in dn:
                archived = True
    
        conn.unbind()

    logger.debug('check_exists_or_archived: Exists: %s, Archived: %s, Absent: %s - Attributes: email:%s' % (exists, archived, absent, email))
    return {'exists' : exists, 'archived' : archived, 'absent' : absent }


def retrieve_username(email):
   
    status = check_exists_or_archived(email)

    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_SEARCH_BASE']
    conn.search(search_base=s_base, search_filter='(mail='+email+')', search_scope=SUBTREE, attributes = ['sAMAccountName'])


    if status['archived']:
        message = 'This account has been archived, however, the username is: %s. Please contact your Systems Administrator.' % conn.entries[0].sAMAccountName.value
        category = 'error'
    elif status['exists']:
        message = 'Your username is: %s' % conn.entries[0].sAMAccountName.value
        category = 'success'
    else:
        message = 'A account associated with the email: %s could not be found.' % email
        category = 'error'

    conn.unbind()

    #logger.debug('retrieve_username: Username:%s - uin: %s email:%s' % (conn.entries[0].sAMAccountName.value, uin, email))
    return { 'return_message' : message, 'return_category' : category  }

def get_user_attributes(sAMAccountName):

    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_SEARCH_BASE']

    s_attributes = app.config['USER_INFORMATION_DISPLAYED']

    conn.search(search_base=s_base, search_filter='(sAMAccountName='+str(sAMAccountName)+')', search_scope=SUBTREE, attributes = s_attributes)

    return_dict = conn.entries[0]

    return return_dict

def determine_username(email, fname, lname):

    status = {}
    status['exists'] = True
    uniq_num = 0

    username = fname[0] + lname[:7]
    status = check_exists_or_archived(email)

    while status['exists'] == True:
        if int(len(username)) <= 3:
            username = username+ "_" + str(uniq_num)
        elif "_" in username:
            uniq_num += 1
            username = username.split("_")[0]+ "_" + str(uniq_num)
        else:
            username = username[:-1]

        status = check_exists_or_archived(sam=username)

    logger.debug('determine_username: Username Determined:%s Fname:%s Lname:%s' % (username,fname,lname))
    return username

def create_account(fname,lname,uin,email,grad,samaccountname='',type=''):

    if samaccountname == '':
        samaccountname = determine_username(fname,lname)

    message = 'New username: %s' % samaccountname
    category = 'success'
    return {'return_message' : message, 'return_category': category}

def reset_pw(pw,email='', uin='', samaccountname=''):

    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_SEARCH_BASE']

    #If function is passed a samaccountname, find the user using that. This is the most reliably way.
    if samaccountname is not '':
        s_filter = '(sAMAccountName='+str(samaccountname)+')'
    #If function is passed a UIN, find the user using that. It is more reliable this way.
    elif str(uin) is not '':
        s_filter = '(employeeNumber='+str(uin)+')'
    #If the function is passed an email instead, use that. Less ideal, but still workable as they should be globally unique in most cases.
    elif email is not '':
        s_filter = '(extensionAttribute1='+str(email)+')'

    conn.search(search_base=s_base, search_filter=s_filter, search_scope=SUBTREE, attributes = ['sAMAccountName','givenName','sn',"distinguishedName"])

    if len(conn.entries) < 1:
        message = 'Account was not found %s' % s_filter
        category = 'error'
    else:
        error_dict = password_check(pw, conn.entries[0].givenName.value, conn.entries[0].sn.value, conn.entries[0].sAMAccountName.value)

        if error_dict['password_ok'] == False:

            message = 'Complexity error, please re-enter password: '

            for key in error_dict.keys():
                if key == 'password_ok':
                    continue
                if error_dict[key] == True:
                    category = 'error'
                    message += '-' + key + '-'
            return {'return_message' : message, 'return_category': category}
        else:
            pw = pw.encode('utf-16-le')
            conn.modify(conn.entries[0].distinguishedName.value, {'unicodePwd': [(MODIFY_REPLACE, [pw])]})
            message = 'Password Reset! You may test your credentials by logging in to this page.'
            category = 'success'

    conn.unbind()    
    return {'return_message' : message, 'return_category': category}



def password_check(password,fname,lname,username):
  #"""
  #  Verify the strength of 'password'
  #  Returns a dict indicating the wrong criteria
  #  A password is considered strong if:
  #      8 characters length or more
  #      1 digit or more
  #      1 symbol or more
  #      1 uppercase letter or more
  #      1 lowercase letter or more
  #  """

  # calculating the length
  length_error = len(password) < 8

  # searching for digits
  digit_error = re.search(r"\d", password) is None

  # searching for uppercase
  uppercase_error = re.search(r"[A-Z]", password) is None

  # searching for lowercase
  lowercase_error = re.search(r"[a-z]", password) is None

  # searching for symbols
  symbol_error = re.search(r"[!$@%&\-=_\+\*]", password) is None

  #check for username inclusion
  uname_error = username.lower() in password.lower()

  #check for firstname inclusion
  fname_error = fname.lower() in password.lower()

  #check for lastname inclusion
  lname_error = lname.lower() in password.lower()

  # overall result
  password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error or uname_error or fname_error or lname_error)

  return {
    'password_ok' : password_ok,
    'not_enough_characters' : length_error,
    'not_enough_numbers' : digit_error,
    'no_uppercase_error' : uppercase_error,
    'no_lowercase_error' : lowercase_error,
    'no_symbols_error' : symbol_error,
    'username_in_password' : uname_error,
    'first_name_in_password' : fname_error,
    'last_name_in_password' : lname_error,
  }

def is_admin(username):
    conn = AD_Connect_SSL()
    s_base = app.config['LDAP_BASE_DN']
    admin_group = app.config['APP_ADMIN_GROUP']
    s_filter='(&(objectClass=user)(memberof='+str(admin_group)+'))'
    conn.search(search_base=s_base, search_filter=s_filter, search_scope=SUBTREE, attributes = ['sAMAccountName'])
    for entry in conn.entries:
        if entry.sAMAccountName.value == username:
            return True
    return False

def send_email(message,to,subject):
    print(message)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email