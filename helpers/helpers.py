#Short, useful function that may or may not deserve their own files.
from app import app,logging
from config import Config
from ldap3 import Server, Connection, SUBTREE, MODIFY_ADD, MODIFY_REPLACE
from itsdangerous import URLSafeTimedSerializer
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import ssl
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

def send_email(subject=str, to=str, cc='', body='', is_html=True):

    SMTP_HOST =             app.config['SMTP_HOST']
    SMTP_USERNAME =         app.config['SMTP_USERNAME']
    SMTP_PASSWORD =         app.config['SMTP_PASSWORD']
    SMTP_PORT =             app.config['SMTP_PORT']
    SMTP_TLS =              app.config['SMTP_TLS']
    SMTP_FROM_ADDRESS =     app.config['SMTP_FROM_ADDRESS']
    SMTP_LOGIN_REQUIRED =   app.config['SMTP_LOGIN_REQUIRED']
    SMTP_IGNORE_CERT =      app.config['SMTP_IGNORE_CERT']

    logger = logging.getLogger('accounts-helpers')

    logger.info("Connection details: Host: %s Port: %s TLS: %s Ignore Cert: %s Login Required: %s as %s" % (SMTP_HOST, SMTP_PORT, SMTP_TLS, SMTP_IGNORE_CERT, SMTP_LOGIN_REQUIRED, SMTP_USERNAME))
    logger.info("from: %s subject: %s to: %s  body: %s" % (SMTP_FROM_ADDRESS, subject, to, body))

    

    # TODO, currently doesn't work because of ssl.SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1045)
    # In addition, the certificate isn't properly ignored.
    #if SMTP_SSL:
    #    if SMTP_IGNORE_CERT:
    #        context = ssl._create_unverified_context(protocol=ssl.PROTOCOL_TLSv1_1)
    #        context.check_hostname = False
    #        context.verify_mode = ssl.CERT_NONE
    #        s = smtplib.SMTP_SSL(host=SMTP_HOST, port=SMTP_PORT, context=context)
    #    else:
    #        s = smtplib.SMTP_SSL(host=SMTP_HOST, port=SMTP_PORT)
    #else:
    #    s = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)

    s = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)

    try:
        s.ehlo()
    except Exception as e:
        logger.error("SMTP EHLO Error caught: %s" % e)
        return False

    if SMTP_TLS:
        
        # TODO, Not sure what's going on here. Even if we give a bogus servername, starttls still connects without warning.
        # Basically, SMTP_IGNORE_CERT fails insecurely and will always send the message.
        if SMTP_IGNORE_CERT:
            context = ssl._create_unverified_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        

        try:
            s.starttls()
        except Exception as e:
            logger.error("SMTP STARTTLS Error caught: %s" % e)
            return False

    if SMTP_LOGIN_REQUIRED:
        try:
            s.login(SMTP_USERNAME, SMTP_PASSWORD)
        except Exception as e:
            logger.error("SMTP Login Error caught: %s" % e)
            return False
    
    envelope = MIMEMultipart()

    envelope['From'] = SMTP_FROM_ADDRESS
    envelope['To'] = to
    envelope['Subject'] = subject

    if is_html:
        envelope.attach(MIMEText(body,'html'))
    else:
        envelope.attach(MIMEText(body,'plain'))

    try:
        s.send_message(envelope)
        return True
    except Exception as e:
        logger.error("SMTP Error caught: %s" % e)
        return False

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