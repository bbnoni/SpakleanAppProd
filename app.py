from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_migrate import Migrate
from datetime import datetime
from config import Config

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
cors = CORS()
jwt = JWTManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    cors.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)

    # MODELS
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

    # ROUTES

    @app.route('/')
    def index():
        return jsonify({"message": "Welcome to the Spaklean API"}), 200
    
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({"status": "healthy"}), 200

    @app.route('/api/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data['username']
        password = data['password']
        role = data['role']

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=password_hash, role=role)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201
    
    @app.route('/api/admin/users', methods=['GET'])
    def get_users():
        users = User.query.all()
        users_data = [{'id': user.id, 'username': user.username} for user in users]
        return jsonify({"users": users_data}), 200


    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Retrieve the user based on the provided username
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password is correct
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Create an access token with the user's role and username in the identity payload
            access_token = create_access_token(identity={'username': user.username, 'role': user.role})
            
            # Return the access_token along with the user's role in the response
            return jsonify({
                'access_token': access_token,
                'role': user.role, # Returning the user's role here
                'user_id': user.id  # Ensure you return user_id
            }), 200

        # If login fails, return a 401 error
        return jsonify({"message": "Invalid credentials"}), 401


    @app.route('/api/admin/create_office', methods=['POST'])
    def create_office():
        data = request.get_json()
        name = data['name']
        user_id = data['user_id']
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        new_office = Office(name=name, user_id=user.id)
        db.session.add(new_office)
        db.session.commit()

        return jsonify({"message": "Office created successfully"}), 201

    @app.route('/api/admin/create_room', methods=['POST'])
    def create_room():
        data = request.get_json()
        name = data['name']
        office_id = data['office_id']

        office = Office.query.get(office_id)
        if not office:
            return jsonify({"message": "Office not found"}), 404

        new_room = Room(name=name, office_id=office.id)
        db.session.add(new_room)
        db.session.commit()

        return jsonify({"message": "Room created successfully"}), 201

    @app.route('/api/tasks/submit', methods=['POST'])
    def submit_task():
        data = request.get_json()
        task_type = data['task_type']
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        user_id = data['user_id']
        room_id = data['room_id']

        user = User.query.get(user_id)
        room = Room.query.get(room_id)

        if not user or not room:
            return jsonify({"message": "User or Room not found"}), 404

        new_task = TaskSubmission(task_type=task_type, latitude=latitude, longitude=longitude, user_id=user.id, room_id=room.id)
        db.session.add(new_task)
        db.session.commit()

        return jsonify({"message": "Task submitted successfully"}), 201
    
    @app.route('/api/users/<int:user_id>/offices', methods=['GET'])
    def get_assigned_offices(user_id):
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Get all offices assigned to the user
        assigned_offices = Office.query.filter_by(user_id=user_id).all()

        offices_data = [{'id': office.id, 'name': office.name} for office in assigned_offices]

        return jsonify({"offices": offices_data}), 200


    return app

# Expose the app object for Gunicorn
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
