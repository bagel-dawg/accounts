from flask import render_template, flash, redirect, url_for
from app import app
from app.forms import LoginForm, FindUser, Account_Request, PWReset, PWChoose, Admin_User_Info_Lookup
from helpers import helpers
from flask_ldap3_login.forms import LDAPLoginForm
from flask_login import LoginManager, login_user, UserMixin, current_user, logout_user, login_required

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    #User is authenticated so send them to the dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LDAPLoginForm()

    if form.validate_on_submit():
        # Successfully logged in, We can now access the saved user object
        # via form.user.
        login_user(form.user)  # Tell flask-login to log them in.
        return redirect(url_for('dashboard'))  # Send them home

    return render_template('login.html', title='Accounts - Login', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    #If the user is an administrative user, redirect to admin dashboard.
    if helpers.is_admin(current_user.username):
        return redirect(url_for('admin'))
    #If not an admin, but logged in: send to regular dashboard.
    else:
        attributes = helpers.get_user_attributes(current_user.username)
        return render_template('dashboard.html', title='Accounts - Dashboard', attributes=attributes, username=current_user.username)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():

    #get_user_info = Admin_User_Info_Lookup()
    #Need to populate memberOf in OpenLDAP
    if not helpers.is_admin(current_user.username):
        flash('This account does not have access to the Admin Dashboard.', category='error')
        return redirect(url_for('login'))

#    if get_user_info.validate_on_submit():

    attributes = helpers.get_user_attributes(current_user.username)
    return render_template('admin.html', title='Accounts - Admin Dashboard', attributes=attributes, username=current_user.username)

@app.route('/tos')
def tos():
    return render_template('tos.html', title='Accounts - Terms of Service')

@app.route('/validate/finduser', methods=['GET', 'POST'])
@app.route('/finduser', methods=['GET', 'POST'])
def finduser():
    form = FindUser()
    #Need to have them go through secure email workflow
    if form.validate_on_submit():
        returned = helpers.retrieve_username(form.email.data)
        flash(returned['return_message'], category=returned['return_category'])
    return render_template('finduser.html', title='Accounts - Forgotten Username', form=form)

@app.route('/validate', methods=['GET', 'POST'])
@app.route('/validate/create', methods=['GET', 'POST'])
@app.route('/request', methods=['GET', 'POST'])
def request():
    form = Account_Request()
    if form.validate_on_submit():

        email = form.email.data
        #Need to check that the email domain provided is valid

        #This check prevents the user from requesting accounts with the same information.
        #Email should be used as unique identifier in LDAP Directory
        #Use switch for active vs archived vs absent
        account_status = helpers.check_exists_or_archived(current_user.email)
        if account_status['exists'] == True:
            returned = {}
            returned['return_message'] = 'An account with this email address has already been created. You may check the username using the form below.'
            returned['return_category'] = 'error'
            flash(returned['return_message'], category=returned['return_category'])
            return redirect(url_for('finduser'))

        token = helpers.generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)

        #This message should be sent as an email
        message = 'Please check your %s mailbox for a confirmation email. Validation link: %s ' % (email, confirm_url)
        category = 'success'
        flash(message, category=category)
    
    return render_template('request.html', title='Accounts - Account Creation', form=form)

@app.route('/validate/pwreset', methods=['GET', 'POST'])
@app.route('/pwreset', methods=['GET', 'POST'])
def pwreset():
    form = FindUser()
    if form.validate_on_submit():

        email = form.email.data

        account_status = helpers.check_exists_or_archived(email)
        
        #use case here
        if account_status['archived']:
            message = 'This account has been archived, and the password cannot be reset. Please contact your Systems Administrator'
            category = 'error'
        elif account_status['exists']:
            token = helpers.generate_confirmation_token(email)
            confirm_url = url_for('pwreset_confirm_email', token=token, _external=True)

            #This message should be sent as an email
            message = 'Please check your %s mailbox for a confirmation email. Validation link: %s ' % (email, confirm_url)
            category = 'success'
        else:
            message = 'An account could not be found for the email provided.'
            category = 'error'


        flash(message, category=category)
        return render_template('pwreset.html', title='Accounts - Reset Password', form=form)

    return render_template('pwreset.html', title='Accounts - Reset Password', form=form)


@app.route('/pwreset/<token>', methods=['GET','POST'])
def pwreset_confirm_email(token):
    #reset_pw helper needs to be re-written

    form = PWChoose()

    #This code will only run if no info has been entered in the form.
    #Confirm that there is a valid token. If the token is valid, render the password input screen.
    email = helpers.confirm_token(token)
    if email:
        return render_template('pwchoose.html', title='Accounts - Choose Account Password', form=form)
    else:
        message = 'You do not have a valid token. It either doesn\'t exist or has expired. You may request an account using this form.'
        category = 'error'
        flash(message, category=category)
        return redirect(url_for('pwreset'))

    #This code will only run if the page has proper info POST'd to it.
    #Account validation doesn't need to be done here, because we check that the account exists 
    #before sending out the email with the token. It also gets checked in the password_reset() function.
    if form.validate_on_submit():
        
        #Pull their uin from the serialized token
        email = helpers.confirm_token(token)
        returned = helpers.reset_pw(form.pw.data,email=email)
        
        if returned['return_category'] == 'success':
            flash(returned['return_message'], category=returned['return_category'])
            return redirect(url_for('login'))
        else:
            flash(returned['return_message'], category=returned['return_category'])
            return render_template('pwchoose.html', title='Accounts - Choose Account Password', form=form)

@app.route('/confirm/<token>', methods=['GET','POST'])
def confirm_email(token):

    form = PWChoose()

    #This code will only run if no info has been entered in the form.
    #Confirm that a valid token as been GET'd. If the token is valid, render the password input screen.
    email = helpers.confirm_token(token)


    #This check prevents the user from double-opening the validation link to create multiple accounts.
    exists_status = helpers.check_exists_or_archived(email)
    if exists_status['exists'] == True:
        returned = {}
        returned['return_message'] = 'An account with this information has already been created. You may check the username using the form below.'
        returned['return_category'] = 'error'
        flash(returned['return_message'], category=returned['return_category'])
        return redirect(url_for('finduser'))

    if email:
        return render_template('pwchoose.html', title='Accounts - Choose Account Password', form=form)
    else:
        message = 'You do not have a valid token. It either doesn\'t exist or has expired. You may request an account using this form.'
        category = 'error'
        flash(message, category=category)
        return redirect(url_for('request'))

    #This code will only run if the page has proper info POST'd to it.
    #Check the password complexity, and then create the account. If password isnt 
    # complex enough, flash a warning to re-enter a password.
    if form.validate_on_submit():
        
        #Pull their email address from the token
        email = helpers.confirm_token(token)


        #Need to pull user details from form as opposed to relying on enrollfile
        #user = EnrollFile.query.filter_by(email=email).first()
       
        samaccountname = helpers.determine_username(user.email,user.firstname,user.lastname)

        #Check the password for complexity errors. If found, re-prompt at display the errors.
        error_dict = helpers.password_check(form.pw.data, user.firstname,user.lastname, samaccountname)

        if error_dict['password_ok'] == False:

            returned = {}
            returned['return_message'] = 'Complexity error, please re-enter password: '

            for key in error_dict.keys():
                if key == 'password_ok':
                    continue
                if error_dict[key] == True:
                    returned['return_category'] = 'error'
                    returned['return_message'] += '-' + key + '-'

            flash(returned['return_message'], category=returned['return_category'])
            return render_template('pwchoose.html', title='Accounts - Choose Account Password', form=form)

        #After checking the account password, we can finally move on to initiating the account creation.
        returned = helpers.create_account(user.firstname,user.lastname,user.uin,user.email,user.grad, samaccountname=samaccountname)

        if returned['return_category'] == 'success':
            #We should output their username to the browser when we redirect back to login as well as send a final email
            flash(returned['return_message'], category=returned['return_category'])
            return redirect(url_for('login'))
        else:
            returned['return_message'] = 'A creation error has occured when attempting to create your account. Please contact your Systems Administrator and take note of the time of this error.'
            returned['return_category'] = 'error'
            flash(returned['return_message'], category=returned['return_category'])
            return redirect(url_for('login'))
