from flask.ext.wtf import Form, RecaptchaField
from wtforms import StringField, BooleanField, SelectMultipleField
from wtforms.validators import DataRequired

class LoginForm(Form):
    phonenumber = StringField('user', validators=[DataRequired()])
    password = StringField('pass', validators=[DataRequired()])
    remember_me = BooleanField('remember_me', default=False)

class SignupForm(Form):
    phonenumber = StringField('user', validators=[DataRequired()])
    key = StringField('key', validators=[DataRequired()])
    recaptcha = RecaptchaField()

class VerifyForm(Form):
    verify_key = StringField('key', validators=[DataRequired()])

class PasswordForm(Form):
    password = StringField('pass', validators=[DataRequired()])
    repeat_password = StringField('repeat_pass', validators=[DataRequired()])

class ResetForm(Form):
    phonenumber = StringField('user', validators=[DataRequired()])

class ResetByTokenForm(Form):
    token = StringField('token', validators=[DataRequired()])

class IndexForm(Form):
    enabled = BooleanField('enabled')

class AdminForm(Form):
    pass

class LogoutForm(Form):
    pass

class DeleteForm(Form):
    pass
