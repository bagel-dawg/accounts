from app import app,logging
from config import Config

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