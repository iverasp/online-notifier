from flask import Flask, jsonify, render_template
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

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
    admin = db.Column(db.Boolean, nullable=False)
    verification_code = db.Column(db.String)

class BetaKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

if __name__=='__main__':
    app.run(debug=True)

