from app import app,logging
from config import Config
from ldap3 import Server, Connection, SUBTREE, MODIFY_ADD, MODIFY_REPLACE

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