from flask.ext.sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class SMS(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.now)
    receiver = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String)

    def __init__(self, receiver, content):
        self.receiver = receiver
        self.content = content

    def pretty_date(self):
        return unicode(self.date.replace(microsecond=0))

    def __repr__(self):
        return '<Date ' + self.date + ', Receiver ' + self.receiver + ', Content ' + self.content + '>'

class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String, nullable=False)
    registration_start = db.Column(db.DateTime, nullable=False)

    def __init__(self, event_id, name, registration_start):
        self.event_id = event_id
        self.name = name
        self.registration_start = registration_start

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phonenumber = db.Column(db.Integer, nullable=False)
    password = db.Column(db.String, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    admin = db.Column(db.Boolean, nullable=False)

    def __init__(self, phonenumber, password, enabled, admin):
        self.phonenumber = phonenumber
        self.set_password(password)
        self.enabled = enabled
        self.admin = admin

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def __repr__(self):
        return '<Phone %r>' % (self.phonenumber)

class BetaKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, nullable=False)
