from app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    offices = db.relationship('Office', backref='user', lazy=True)

class Office(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    rooms = db.relationship('Room', backref='office', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    office_id = db.Column(db.Integer, db.ForeignKey('office.id'), nullable=False)

class TaskSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_type = db.Column(db.String(100), nullable=False)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
