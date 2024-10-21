from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from datetime import datetime
from config import Config
import json  # Needed for handling area_scores JSON field
from mail_utils import send_mailjet_email  # Import the helper function#
import requests


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
        password_change_required = db.Column(db.Boolean, default=True)
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
        zone = db.Column(db.String(120), nullable=False)  # Zone added to room
        office_id = db.Column(db.Integer, db.ForeignKey('office.id'), nullable=False)
        task_submissions = db.relationship('TaskSubmission', backref='room', lazy=True)

        def __repr__(self):
            return f"<Room {self.name} in Zone {self.zone}>"

    # Add room_score, area_scores (JSON), and zone_name to TaskSubmission
    class TaskSubmission(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        task_type = db.Column(db.String(100), nullable=False)  # Type of task performed, e.g., 'Cleaning'
        date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
        latitude = db.Column(db.Float, nullable=True)
        longitude = db.Column(db.Float, nullable=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)  # To link the task submission to a room
        room_score = db.Column(db.Float, nullable=True)  # Room score for the inspection
        area_scores = db.Column(db.Text, nullable=True)  # Area scores stored as JSON text
        zone_name = db.Column(db.String(120), nullable=True)  # Zone name for this task
        zone_score = db.Column(db.Float, nullable=True)  # New field for zone score
        facility_score = db.Column(db.Float, nullable=True)  # New field for facility score

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
        
        # Send a welcome email via Mailjet
        subject = "Welcome to Spaklean"
        content = f"Hello {username},\n\nYour account has been created successfully. You can now log in using your credentials."
        send_mailjet_email(username, subject, content)

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

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity={'username': user.username, 'role': user.role})
            
            # Check if user needs to change password (example: admin-created users)
            password_change_required = user.password_change_required

            return jsonify({
                'access_token': access_token,
                'role': user.role,
                'user_id': user.id,
                'password_change_required': password_change_required  # Include this in response
            }), 200

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

    from urllib.parse import unquote


    @app.route('/api/tasks/submit', methods=['POST'])
    def submit_task():
        data = request.get_json()
        print("Received task submission:", data)  # Log the incoming data

        try:
            # Decode zone_name if it's URL-encoded
            zone_name = unquote(data.get('zone_name'))
            print(f"Decoded zone_name: {zone_name}")  # Log decoded zone_name

            task_type = data['task_type']
            latitude = data.get('latitude')
            longitude = data.get('longitude')
            user_id = int(data['user_id'])  # Ensure user_id is an integer
            room_id = int(data['room_id'])  # Ensure room_id is an integer
            area_scores = data.get('area_scores', {})
            zone_score = data.get('zone_score')  # Expecting a double precision value
            facility_score = data.get('facility_score')  # Expecting a double precision value

            # Check if required fields are present
            if not all([task_type, user_id, room_id, zone_name]):
                print("Missing required fields.")  # Log missing fields
                return jsonify({"message": "Missing required fields"}), 400

            # Fetch user and room information from the database
            user = User.query.get(user_id)
            room = Room.query.get(room_id)

            if not user or not room:
                print(f"User or Room not found: user_id={user_id}, room_id={room_id}")  # Log missing user/room
                return jsonify({"message": "User or Room not found"}), 404

            # Calculate room score from area scores
            if area_scores:
                room_score = sum(area_scores.values()) / len(area_scores)
            else:
                room_score = 0.0  # Default value if no area scores
            print(f"Calculated room_score: {room_score}")  # Log room score

            # Make sure zone_score and facility_score are valid double precision values
            if zone_score is not None:
                zone_score = float(zone_score)
                print(f"Valid zone_score: {zone_score}")  # Log valid zone score
            else:
                print("Zone score is None")  # Log if zone_score is None

            if facility_score is not None:
                facility_score = float(facility_score)
                print(f"Valid facility_score: {facility_score}")  # Log valid facility score
            else:
                print("Facility score is None")  # Log if facility_score is None

            # Ensure area_scores is valid JSON
            try:
                area_scores_json = json.dumps(area_scores)
            except Exception as e:
                print(f"Error converting area_scores to JSON: {e}")  # Log JSON conversion error
                return jsonify({"message": "Invalid area_scores format"}), 400

            # Save the task submission to the database
            new_task = TaskSubmission(
                task_type=task_type,
                latitude=latitude,
                longitude=longitude,
                user_id=user.id,
                room_id=room.id,
                room_score=room_score,
                area_scores=area_scores_json,  # Store the area scores as JSON
                zone_name=zone_name,
                zone_score=zone_score,  # Should be a double or None
                facility_score=facility_score  # Should be a double or None
            )

            # Commit the new task to the database
            db.session.add(new_task)
            db.session.commit()
            print("Task submitted successfully.")  # Log successful task submission

            return jsonify({"message": "Task submitted successfully"}), 201

        except Exception as e:
            # Log any exceptions for debugging
            print(f"Error submitting task: {e}")
            return jsonify({"message": "Failed to submit task", "error": str(e)}), 500





    # Route to retrieve the most recent report for a room //
    @app.route('/api/rooms/<int:room_id>/report', methods=['GET'])
    def get_room_report(room_id):
        task = TaskSubmission.query.filter_by(room_id=room_id).order_by(TaskSubmission.date_submitted.desc()).first()

        if not task:
            return jsonify({"message": "No task submission found for this room"}), 404

        # Decode the area_scores from JSON
        area_scores = json.loads(task.area_scores) if task.area_scores else {}

        return jsonify({
            "room_name": task.room.name,
            "room_score": task.room_score,
            "area_scores": area_scores,  # Include area scores in the response
            "zone_name": task.zone_name
        }), 200


    # Route to get all task submissions for a specific room
    @app.route('/api/rooms/<int:room_id>/tasks', methods=['GET'])
    def get_tasks_by_room(room_id):
        tasks = TaskSubmission.query.filter_by(room_id=room_id).all()

        if not tasks:
            return jsonify({"message": "No tasks found for this room"}), 404

        tasks_data = []
        for task in tasks:
            tasks_data.append({
                "task_type": task.task_type,
                "date_submitted": task.date_submitted,
                "room_score": task.room_score,
                "area_scores": json.loads(task.area_scores) if task.area_scores else {},
                "zone_name": task.zone_name,
                "latitude": task.latitude,
                "longitude": task.longitude
            })

        return jsonify({"tasks": tasks_data}), 200

    @app.route('/api/users/<int:user_id>/offices', methods=['GET'])
    def get_assigned_offices(user_id):
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Get all offices assigned to the user
        assigned_offices = Office.query.filter_by(user_id=user_id).all()

        if not assigned_offices:
            return jsonify({"message": "No offices assigned to this user"}), 200

        offices_data = []
        for office in assigned_offices:
            # Count the number of rooms in each office
            room_count = Room.query.filter_by(office_id=office.id).count()
            offices_data.append({
                'id': office.id,
                'name': office.name,
                'room_count': room_count,  # Add room count to the response
            })

        return jsonify({"offices": offices_data}), 200


    # Updated route to create office and room(s) and assign them to a user and zone
    @app.route('/api/admin/create_office_and_room', methods=['POST'])
    def create_office_and_room():
        data = request.get_json()
        office_name = data['office_name']
        room_names = data['room_names']  # Expecting a list of room names
        zone = data['zone']
        user_id = data['user_id']
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Create the office
        new_office = Office(name=office_name, user_id=user.id)
        db.session.add(new_office)
        db.session.commit()

        # List to store the created room IDs
        room_ids = []

        # Create each room under the office and assign it to the zone
        for room_name in room_names:
            new_room = Room(name=room_name, zone=zone, office_id=new_office.id)
            db.session.add(new_room)
            db.session.commit()  # Commit each room individually (optional)

            # Append the room ID to the list
            room_ids.append(new_room.id)

        return jsonify({
            "message": "Office and Rooms created successfully",
            "office_id": new_office.id,
            "room_ids": room_ids
        }), 201

    @app.route('/api/users/<int:user_id>/offices/<int:office_id>/rooms/<string:zone>', methods=['GET'])
    def get_rooms_by_office_and_zone(user_id, office_id, zone):
        user = User.query.get(user_id)

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Fetch rooms that belong to the specific office and match the requested zone
        rooms = Room.query.filter_by(office_id=office_id, zone=zone).all()

        rooms_data = [{'id': room.id, 'name': room.name, 'zone': room.zone} for room in rooms]

        return jsonify({"rooms": rooms_data}), 200
    
    @app.route('/api/users/<int:user_id>/tasks', methods=['GET'])
    def get_tasks_by_user(user_id):
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Fetch all task submissions for the user
        tasks = TaskSubmission.query.filter_by(user_id=user_id).all()

        tasks_data = []
        for task in tasks:
            tasks_data.append({
                "task_type": task.task_type,
                "date_submitted": task.date_submitted.isoformat(),  # Convert datetime to ISO format string
                "room_score": task.room_score if task.room_score else "Not available",  # Handle null scores
                "zone_name": task.zone_name if task.zone_name else "N/A",  # Handle null zones
                "latitude": task.latitude if task.latitude else "Not available",  # Handle missing lat/long
                "longitude": task.longitude if task.longitude else "Not available",
                "area_scores": json.loads(task.area_scores) if task.area_scores else {},  # Parse area_scores JSON
                "zone_score": task.zone_score if task.zone_score else "N/A",  # Include zone score
                "facility_score": task.facility_score if task.facility_score else "N/A"  # Include facility score
            })

        return jsonify({"tasks": tasks_data}), 200


    @app.route('/api/auth/change_password', methods=['POST'])
    @jwt_required()
    def change_password():
        data = request.get_json()
        new_password = data['new_password']
        user_id = data['user_id']

        user = User.query.get(user_id)

        if user:
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password_change_required = False  # Set to False after password change
            db.session.commit()

            return jsonify({"message": "Password changed successfully."}), 200

        return jsonify({"message": "User not found."}), 404
    

    @app.route('/api/auth/reset_password', methods=['POST'])
    @jwt_required()  # Ensure the request is authenticated
    def reset_password():
        data = request.get_json()
        user_id = data.get('user_id')
        new_password = data.get('new_password')

        # Check if the required fields are provided
        if not user_id or not new_password:
            return jsonify({"message": "User ID and new password are required"}), 400

        # Find the user by user_id
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Hash the new password and update the user's password
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password_change_required = True  # User is required to change the password on next login
        #user.password_change_required = False  # Reset password change flag if it exists


        db.session.commit()

        return jsonify({"message": "Password reset successfully"}), 200
    

    @app.route('/api/admin/add_more_rooms', methods=['POST'])
    def add_more_rooms():
        data = request.get_json()
        user_id = data.get('user_id')
        office_id = data.get('office_id')
        room_names = data.get('room_names')
        zone = data.get('zone')

        if not user_id or not office_id or not room_names or not zone:
            return jsonify({"message": "Missing required fields"}), 400

        # Assuming you have an Office and Room model to handle database records#
        for room_name in room_names:
            new_room = Room(name=room_name, office_id=office_id, zone=zone)
            db.session.add(new_room)

        db.session.commit()

        return jsonify({"message": "Rooms added successfully"}), 200
    
    
    from urllib.parse import unquote

    @app.route('/api/zones/<string:zone_name>/score', methods=['GET'])
    def get_zone_score(zone_name):
        # Decode the URL-encoded zone_name
        zone_name = unquote(zone_name)
        print(f"Decoded zone_name: {zone_name}")
        
        # Get the office_id from the query parameters
        office_id = request.args.get('office_id')
        if not office_id:
            return jsonify({"message": "office_id is required"}), 400

        # Fetch rooms in the specified zone and office
        rooms = Room.query.filter_by(zone=zone_name, office_id=office_id).all()

        if not rooms:
            print(f"No rooms found for zone: {zone_name} in office: {office_id}")
            # Return N/A for the zone score if no rooms are found
            return jsonify({"zone_name": zone_name, "zone_score": "N/A"}), 200

        total_room_score = 0
        room_count = 0

        # Loop through each room and fetch the latest task submission
        for room in rooms:
            task = TaskSubmission.query.filter_by(room_id=room.id).order_by(TaskSubmission.date_submitted.desc()).first()
            if task:
                total_room_score += task.room_score
                room_count += 1

        if room_count == 0:
            print(f"No tasks found for zone: {zone_name} in office: {office_id}")
            # Return N/A if no tasks have been submitted for the zone
            return jsonify({"zone_name": zone_name, "zone_score": "N/A"}), 200

        # Calculate the average room score for the zone
        zone_score = total_room_score / room_count
        print(f"Zone score for {zone_name} in office {office_id}: {zone_score}")
        return jsonify({"zone_name": zone_name, "zone_score": zone_score}), 200


    

    @app.route('/api/facility/score', methods=['GET'])
    def get_total_facility_score():
        # Get the office_id from the query parameters
        office_id = request.args.get('office_id')
        if not office_id:
            return jsonify({"message": "office_id is required"}), 400

        # Fetch all unique zones from the Room table for the specified office
        zones = db.session.query(Room.zone).filter_by(office_id=office_id).distinct().all()

        if not zones:
            return jsonify({"message": f"No zones found for office {office_id}"}), 404

        total_zone_score = 0
        zone_count = 0

        # Loop through each zone and calculate the zone score for the given office
        for zone in zones:
            zone_name = zone[0]  # Zone name is fetched as a tuple (zone,)
            rooms = Room.query.filter_by(zone=zone_name, office_id=office_id).all()
            total_room_score = 0
            room_count = 0

            # Calculate the average room score for each zone in the office
            for room in rooms:
                task = TaskSubmission.query.filter_by(room_id=room.id).order_by(TaskSubmission.date_submitted.desc()).first()
                if task:
                    total_room_score += task.room_score
                    room_count += 1

            # Skip zones with no tasks
            if room_count > 0:
                zone_score = total_room_score / room_count
                total_zone_score += zone_score
                zone_count += 1

        # If no zones have room scores
        if zone_count == 0:
            return jsonify({"message": f"No zones with room scores found for office {office_id}"}), 404

        # Calculate the total facility score as the average of all zone scores for the office
        total_facility_score = total_zone_score / zone_count

        return jsonify({"total_facility_score": total_facility_score}), 200




    return app

# Expose the app object for Gunicorn
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
