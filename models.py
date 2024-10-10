# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# No need to import db from app.py. We initialize it here
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    offices = db.relationship('Office', backref='user', lazy=True)
    task_submissions = db.relationship('TaskSubmission', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"

class Office(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    rooms = db.relationship('Room', backref='office', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Office {self.name}>"

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    office_id = db.Column(db.Integer, db.ForeignKey('office.id'), nullable=False)
    task_submissions = db.relationship('TaskSubmission', backref='room', lazy=True)

    def __repr__(self):
        return f"<Room {self.name}>"

class TaskSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_type = db.Column(db.String(100), nullable=False)  # Type of task performed, e.g., 'Cleaning'
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)  # To link the task submission to a room

    def __repr__(self):
        return f"<TaskSubmission {self.task_type} by User {self.user_id} in Room {self.room_id}>"
