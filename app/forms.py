from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, EqualTo, Email


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class FindUser(FlaskForm):
    oduemail = StringField('Email', validators=[DataRequired(),Email(message='You must enter a valid email address.')])
    uin = StringField('UIN', validators=[DataRequired()])
    submit = SubmitField('Submit')

class PWReset(FlaskForm):
    oduemail = StringField('Email', validators=[DataRequired(),Email(message='You must enter a valid email address.')])
    uin = StringField('UIN', validators=[DataRequired()])
    submit = SubmitField('Submit')

class PWChoose(FlaskForm):
    pw = PasswordField('Password', validators=[DataRequired(),EqualTo('pw_check', message='Passwords must match')])
    pw_check = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class Account_Request(FlaskForm):
    oduemail = StringField('Email', validators=[DataRequired(),Email(message='You must enter a valid email address.')])
    uin = StringField('UIN', validators=[DataRequired()])
    accepted = BooleanField('I Agree to the Terms of Service', validators=[DataRequired()])
    submit = SubmitField('Submit')

class Admin_User_Info_Lookup(FlaskForm):
    oduemail = StringField('Email')
    uin = IntegerField('UIN')
    username = StringField('CS Username')
    uidNumber = IntegerField('Unix UID')
    submit = SubmitField('Submit')