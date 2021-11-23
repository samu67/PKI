from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class updateCredentials(FlaskForm):
    lastname = StringField('lastname', validators=[DataRequired(), Length(min=2, max=20)])
    firstname = StringField('firstname',validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('CurrentPassword', validators=[DataRequired()])
    password2 = PasswordField('Password2', validators=[DataRequired(), EqualTo('password1', message='Password must match')])
    password1 = PasswordField('Password1', validators=[DataRequired()])
    update = SubmitField('update')


class SignIn(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    login = SubmitField('login')

class RevokeCert(FlaskForm):
    uid = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    sn = StringField('Serialnumber', validators=[DataRequired()])
    revoke = SubmitField('Revoke')
