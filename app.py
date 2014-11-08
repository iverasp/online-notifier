from flask import Flask, jsonify, render_template, redirect, url_for, \
    flash, session, request
from flask.ext.login import LoginManager, login_user , logout_user , \
    current_user , login_required
from flask.ext.wtf import CsrfProtect
import random, string, json, os
from forms import *
from talkmoreapi import *
from models import *

config_file = "%s/.talkmore.json" % os.getenv("HOME")
config = json.loads(open(config_file, 'r').read())
phonenumber = config["phonenumber"]
password = config["password"]
t = TalkmoreAPI(phonenumber, password)
random.seed()

app = Flask(__name__)
app.config.from_object('config')
db.init_app(app)
CsrfProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id))

@app.before_request
def before_request():
    user = current_user

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_form = IndexForm()
    logout_form = LogoutForm()
    if user_form.validate_on_submit():
        current_user.enabled = user_form.enabled.data
        db.session.commit()
    if current_user.admin:
        admin_form = AdminForm()
        delete_form = DeleteForm()
        if delete_form.validate_on_submit():
            for id in request.form.getlist('chk_group_users'):
                d = Users.query.filter_by(
                    id = id
                ).first()
                db.session.delete(d)
                db.session.commit()
                flash('Deleted user ' + str(d.phonenumber))
            return redirect(url_for('index'))
        return render_template('admin.html',
                                title='Hi admin',
                                user=current_user,
                                users=Users.query.all(),
                                keys=BetaKeys.query.all(),
                                smss=SMS.query.order_by(SMS.date.desc()).all(),
                                user_form=user_form,
                                logout_form=logout_form,
                                admin_form=admin_form,
                                delete_form=delete_form)
    return render_template('user.html',
                            title='Hi user',
                            user=current_user,
                            user_form=user_form,
                            logout_form=logout_form)

@app.route('/gen_key', methods=['POST'])
@login_required
def gen_key():
    admin_form = AdminForm()
    if current_user.admin:
        if admin_form.validate_on_submit():
            generate_key()
            flash('Generated new key')
            return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        registered_user = Users.query.filter_by(
            phonenumber=form.phonenumber.data,
        ).first()
        if registered_user is None \
            or not registered_user.check_password(form.password.data):
            flash('Wrong phone number or password')
            return redirect(url_for('login'))
        login_user(registered_user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html',
                            title='Log in',
                            form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signup_form = SignupForm()
    verify_form = VerifyForm()
    if signup_form.validate_on_submit():
        if not validate_key(signup_form.key.data):
            flash('Invalid key')
            return redirect(url_for('signup'))

        registered_user = Users.query.filter_by(
            phonenumber=signup_form.phonenumber.data,
        ).first()
        if registered_user is not None:
            flash('Phone number already registered')
            return redirect(url_for('signup'))
        session['verify_key'] = random_string(4)
        session['phonenumber'] = signup_form.phonenumber.data
        send_sms(session['phonenumber'],
            "Verification code: " + session['verify_key'])
        flash('Verification code sent to ' + session['phonenumber'])
        return render_template('signup.html',
                                title='Sign up',
                                signup_form=signup_form,
                                verify_form=verify_form)
        print(session['verify_key'])

    return render_template('signup.html',
                            title='Sign up',
                            signup_form=signup_form)

@app.route('/verify', methods=['POST'])
def verify():
    verify_form = VerifyForm()
    if verify_form.validate_on_submit():
        if verify_form.verify_key.data == session['verify_key']:
            password_form = PasswordForm()
            return render_template('signup.html',
                                    title='Sign up',
                                    password_form=password_form)
    flash('Incorrect verifiation code')
    return redirect(url_for('signup'))

@app.route('/create', methods=['POST'])
def create():
    password_form = PasswordForm()
    if password_form.validate_on_submit():
        if password_form.password.data == password_form.repeat_password.data:
            create_user(session['phonenumber'], password_form.password.data)
            registered_user = Users.query.filter_by(
                phonenumber=session['phonenumber']
            ).first()
            if registered_user.check_password(password_form.password.data):
                login_user(registered_user)
                return redirect(url_for('index'))
            else:
                flash('Something went wrong')
                return redirect(url_for('signup'))
    flash('Something went wrong')
    return redirect(url_for('signup'))

@app.route('/update', methods=['POST'])
def update():
    password_form = PasswordForm()
    if password_form.validate_on_submit():
        if password_form.password.data == password_form.repeat_password.data:
            update_password(session['phonenumber'], password_form.password.data)
            registered_user = Users.query.filter_by(
                phonenumber=session['phonenumber']
            ).first()
            if registered_user.check_password(password_form.password.data):
                login_user(registered_user)
                return redirect(url_for('index'))
            else:
                flash('Something went wrong')
                return redirect(url_for('signup'))
    flash('Something went wrong')
    return redirect(url_for('signup'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    form = LogoutForm()
    if form.validate_on_submit():
        session.clear()
        logout_user()
    return redirect(url_for('index'))

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    reset_form = ResetForm()
    if reset_form.validate_on_submit():
        if Users.query.filter_by(
            phonenumber = reset_form.phonenumber.data
        ).first():
            reset_by_token_form = ResetByTokenForm()
            session['reset_token'] = random_string(6)
            send_sms(reset_form.phonenumber.data,
                'Reset token: ' + session['reset_token'])
            flash('Reset token sent to ' + reset_form.phonenumber.data)
            session['phonenumber'] = reset_form.phonenumber.data
            return render_template('reset.html',
                                    title='Reset password',
                                    reset_form=reset_form,
                                    reset_by_token_form=reset_by_token_form)
        else:
            flash('Phone number not found')
            return redirect(url_for('reset'))
    return render_template('reset.html',
                            title='Reset password',
                            reset_form=reset_form)
@app.route('/reset_token', methods=['POST'])
def reset_token():
    reset_by_token_form = ResetByTokenForm()
    if reset_by_token_form.validate_on_submit():
        if reset_by_token_form.token.data == session['reset_token']:
            password_form = PasswordForm()
            return render_template('reset.html',
                                    title='Reset password',
                                    password_form=password_form)
        flash('Wrong token')
        return redirect(url_for('reset'))
    flash('Something went wrong')
    return redirect(url_for('reset'))


def validate_key(key):
    key_entry = BetaKeys.query.filter_by(
        key = key
    ).first()

    if key_entry is not None:
        db.session.delete(key_entry)
        db.session.commit()
        return True
    return False

def generate_key():
    new_key = BetaKeys(key=random_string(6))
    db.session.add(new_key)
    db.session.commit()

def random_string(n):
    return ''.join(random.choice(string.ascii_uppercase + \
        string.digits) for _ in range(n))

def create_user(phonenumber, password):
    user = Users(
        phonenumber,
        password,
        enabled=True,
        admin=False
    )
    db.session.add(user)
    db.session.commit()

def update_password(phonenumber, password):
    user = Users.query.filter_by(
        phonenumber=phonenumber
    ).first()
    user.set_password(password)
    db.session.commit()

def send_sms(phonenumber, message):
    t.login()
    t.send_sms([phonenumber], message)
    sms = SMS(phonenumber, message)
    db.session.add(sms)
    db.session.commit()

if __name__=='__main__':
    app.run(debug=True)
