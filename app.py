from flask import Flask, request, jsonify,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from datetime import datetime, date
from config import Config
import json  # Needed for handling area_scores JSON field
from mail_utils import send_mailjet_email  # Import the helper function#
import requests
import random
import string
import db_reconnect



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

    # Add the association table for many-to-many relationships between User and Office
    user_office = db.Table('user_office',
        db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
        db.Column('office_id', db.Integer, db.ForeignKey('office.id'), primary_key=True)
    )

    # MODELS#
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        first_name = db.Column(db.String(64), nullable=False)  # First name
        middle_name = db.Column(db.String(64), nullable=True)   # Middle name (optional)
        last_name = db.Column(db.String(64), nullable=False)    # Last name
        username = db.Column(db.String(64), unique=True, nullable=False)
        password_hash = db.Column(db.String(128), nullable=False)
        role = db.Column(db.String(20), nullable=False)
        password_change_required = db.Column(db.Boolean, default=True)
        #offices = db.relationship('Office', backref='user', lazy=True)
        offices = db.relationship('Office', secondary=user_office, back_populates='users')
        task_submissions = db.relationship('TaskSubmission', backref='user', lazy=True)
        notifications = db.relationship('Notification', backref='user', lazy=True)

        def __repr__(self):
            return f"<User {self.username} - {self.first_name} {self.last_name}>"

    class Office(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(120), unique=True, nullable=False)
        rooms = db.relationship('Room', backref='office', lazy=True)
        sector = db.Column(db.String(100), nullable=False)  # Added sector field
        #user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        #user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
        users = db.relationship('User', secondary=user_office, back_populates='offices') 

        def __repr__(self):
            return f"<Office {self.name} in sector {self.sector}>"

    class Room(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(120), nullable=False)
        zone = db.Column(db.String(120), nullable=False)  # Zone added to room
        office_id = db.Column(db.Integer, db.ForeignKey('office.id'), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # New field
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
        

        # Define the Attendance model
    class Attendance(db.Model):
        __tablename__ = 'attendance'

        id = db.Column(db.Integer, primary_key=True)  # Primary key
        user_id = db.Column(db.Integer, nullable=False)  # Reference to the user
        office_id = db.Column(db.Integer, nullable=False)  # Reference to the office
        check_in_time = db.Column(db.DateTime, nullable=True, default=None)  # Check-in timestamp
        check_in_lat = db.Column(db.Float, nullable=True)  # Check-in latitude
        check_in_long = db.Column(db.Float, nullable=True)  # Check-in longitude
        check_out_time = db.Column(db.DateTime, nullable=True, default=None)  # Check-out timestamp
        check_out_lat = db.Column(db.Float, nullable=True)  # Check-out latitude
        check_out_long = db.Column(db.Float, nullable=True)  # Check-out longitude
        created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # Record creation timestamp

        def __repr__(self):
            return f'<Attendance {self.id} for User {self.user_id}>'
        

    class MonthlyScoreSummary(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        month = db.Column(db.Integer, nullable=False)
        year = db.Column(db.Integer, nullable=False)
        office_id = db.Column(db.Integer, db.ForeignKey('office.id'), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        zone_name = db.Column(db.String(120), nullable=True)  # Optional if not a specific zone
        total_zone_score = db.Column(db.Float, nullable=True)
        total_facility_score = db.Column(db.Float, nullable=True)

        def __repr__(self):
            return f"<MonthlyScoreSummary Month={self.month} Year={self.year} Office={self.office_id} User={self.user_id}>"
        

    class Notification(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
        message = db.Column(db.String(256), nullable=False)
        timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        is_read = db.Column(db.Boolean, default=False, nullable=False)
        done_by_user_id = db.Column(db.Integer, nullable=True)  # User who performed the task
        done_on_behalf_of_user_id = db.Column(db.Integer, nullable=True)  # User on whose behalf it was done

        def __repr__(self):
            return f"<Notification for User {self.user_id}: {self.message}>"    

        




    # ROUTES

    @app.route('/')
    def index():
        return jsonify({"message": "Welcome to the Spaklean API"}), 200
    
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({"status": "healthy"}), 200

    # @app.route('/api/auth/register', methods=['POST'])
    # def register():
    #     data = request.get_json()
    #     username = data['username']
    #     password = data['password']
    #     role = data['role']

    #     password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    #     new_user = User(username=username, password_hash=password_hash, role=role)
    #     db.session.add(new_user)
    #     db.session.commit()
        
    #     # Send a welcome email via Mailjet
    #     subject = "Welcome to Spaklean"
    #     content = f"Hello {username},\n\nYour account has been created successfully. You can now log in using your credentials."
    #     send_mailjet_email(username, subject, content)

    #     return jsonify({"message": "User registered successfully"}), 201


    @app.route('/api/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        
        # Extract name fields, middle_name is optional
        first_name = data.get('first_name')
        middle_name = data.get('middle_name', '')  # Default to empty string if not provided
        last_name = data.get('last_name')
        username = data.get('username')
        password = data.get('password')  # Plain text password provided/generated
        role = data.get('role')

        # Validate required fields
        if not all([first_name, last_name, username, password, role]):
            return jsonify({"message": "First name, last name, username, password, and role are required."}), 400

        # Hash the password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create new user with hashed password and optional middle name
        new_user = User(
            first_name=first_name,
            middle_name=middle_name,  # Optional field
            last_name=last_name,
            username=username,
            password_hash=password_hash,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        # Send a welcome email via Mailjet with the plain password
        subject = "Welcome to Spaklean"
        content = f"""Hello {first_name} {last_name},

        Your account has been created successfully. Here are your login credentials:

        Username: {username}
        Password: {password}

        You will be required to change your password upon logging in for the first time.

        You can download the Spaklean app by clicking on the following link:

        [Download App](https://drive.google.com/uc?export=download&id=1ZejzQHyBm28fphnUHwQFrxEvUle5pJXb)

        Best regards,
        The Spaklean Team
        """
        
        # Assuming send_mailjet_email takes (recipient_email, subject, content)
        send_mailjet_email(username, subject, content)

        return jsonify({"message": "User registered successfully"}), 201



    
    # @app.route('/api/admin/users', methods=['GET'])
    # def get_users():
    #     users = User.query.all()
    #     users_data = [{'id': user.id, 'username': user.username} for user in users]
    #     return jsonify({"users": users_data}), 200

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data['username'].strip()
        password = data['password']
        
        print(f"Attempting login for username: {username}")

        # Print all users in the database for verification
        all_users = User.query.all()
        print("Current users in database:", [(u.username, u.id) for u in all_users])

        # Perform a case-insensitive, whitespace-trimmed lookup
        user = User.query.filter(db.func.lower(db.func.trim(User.username)) == db.func.lower(username)).first()
        
        if user:
            print("User found:", user.username)
            if bcrypt.check_password_hash(user.password_hash, password):
                access_token = create_access_token(identity={'username': user.username, 'role': user.role})
                password_change_required = user.password_change_required
                return jsonify({
                    'access_token': access_token,
                    'role': user.role,
                    'user_id': user.id,
                    'password_change_required': password_change_required
                }), 200
            else:
                print("Password mismatch.")
                return jsonify({"message": "Invalid credentials"}), 401
        else:
            print("User not found.")
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
        user_id = data['user_id']  # Expecting the user_id of the user to whom the room is assigned

        # Validate office and user
        office = Office.query.get(office_id)
        user = User.query.get(user_id)

        if not office:
            return jsonify({"message": "Office not found"}), 404
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Create a new room and assign it to the specific user
        new_room = Room(name=name, office_id=office.id, user_id=user.id)
        db.session.add(new_room)
        db.session.commit()

        return jsonify({"message": "Room created successfully", "room_id": new_room.id}), 201


    from urllib.parse import unquote


    from sqlalchemy import func, extract  # Import necessary SQLAlchemy functions




    @app.route('/api/tasks/submit', methods=['POST'])
    def submit_task():
        data = request.get_json()
        print("Received task submission:", data)  # Log the incoming data

        try:
            # Decode zone_name if it's URL-encoded
            zone_name = unquote(data.get('zone_name'))
            print(f"Decoded zone_name: {zone_name}")  # Log decoded zone_name

            # Extract and validate fields, logging each one for debugging
            task_type = data.get('task_type')
            latitude = data.get('latitude')
            longitude = data.get('longitude')

            # Validate that user_id and room_id are provided and are valid integers
            user_id = data.get('user_id')
            if user_id is None:
                print("Error: user_id is missing or None")
                return jsonify({"message": "user_id is required"}), 400
            user_id = int(user_id)  # Convert user_id to integer

            room_id = data.get('room_id')
            if room_id is None:
                print("Error: room_id is missing or None")
                return jsonify({"message": "room_id is required"}), 400
            room_id = int(room_id)  # Convert room_id to integer

            area_scores = data.get('area_scores', {})
            zone_score = data.get('zone_score')
            facility_score = data.get('facility_score')
            done_on_behalf_of_user_id = data.get('done_on_behalf_of_user_id')

            # Check if required fields are present
            if not all([task_type, zone_name]):
                print("Missing required fields: task_type or zone_name.")
                return jsonify({"message": "Missing required fields"}), 400

            # Fetch user and room information from the database
            user = User.query.get(user_id)
            room = Room.query.get(room_id)

            if not user or not room:
                print(f"User or Room not found: user_id={user_id}, room_id={room_id}")
                return jsonify({"message": "User or Room not found"}), 404

            # Validate area_scores
            if not isinstance(area_scores, dict):
                print("Invalid area_scores format. Must be a dictionary.")
                return jsonify({"message": "Invalid area_scores format"}), 400

            # Check each area score for valid float values
            try:
                area_scores = {k: float(v) for k, v in area_scores.items()}
            except ValueError:
                print("Invalid value in area_scores. Must be numeric.")
                return jsonify({"message": "Invalid value in area_scores. Must be numeric."}), 400

            # Calculate room score from area scores
            if area_scores:
                room_score = sum(area_scores.values()) / len(area_scores)
            else:
                room_score = 0.0
            print(f"Calculated room_score: {room_score}")

            # Convert zone_score and facility_score to floats if provided
            try:
                zone_score = float(zone_score) if zone_score is not None else None
            except ValueError:
                print("Invalid zone_score format. Must be a numeric value.")
                return jsonify({"message": "Invalid zone_score format. Must be numeric."}), 400

            try:
                facility_score = float(facility_score) if facility_score is not None else None
            except ValueError:
                print("Invalid facility_score format. Must be numeric.")
                return jsonify({"message": "Invalid facility_score format. Must be numeric."}), 400

            # Convert area_scores to JSON
            try:
                area_scores_json = json.dumps(area_scores)
            except Exception as e:
                print(f"Error converting area_scores to JSON: {e}")
                return jsonify({"message": "Invalid area_scores format"}), 400

            # Save the task submission to the database
            new_task = TaskSubmission(
                task_type=task_type,
                latitude=latitude,
                longitude=longitude,
                user_id=user.id,  # This is the 'done by' user
                room_id=room.id,
                room_score=room_score,
                area_scores=area_scores_json,
                zone_name=zone_name,
                zone_score=zone_score,
                facility_score=facility_score
            )

            # Transaction for task submission and notification
            try:
                db.session.add(new_task)
                db.session.commit()
                print("Task submitted successfully.")

                # Assign done_on_behalf_of_user_id to the intended user
                if not done_on_behalf_of_user_id:
                    done_on_behalf_of_user_id = room.user_id

                # Create a notification if done on behalf of another user
                if done_on_behalf_of_user_id and done_on_behalf_of_user_id != user_id:
                    on_behalf_user = User.query.get(done_on_behalf_of_user_id)
                    if on_behalf_user:
                        print(f"Creating notification for done_on_behalf_of_user_id: {done_on_behalf_of_user_id}")
                        try:
                            message = f"An inspection was completed on your behalf by user {user_id}."
                            notification = Notification(
                                user_id=done_on_behalf_of_user_id,  # Recipient
                                message=message,
                                done_by_user_id=user_id,             # User who performed the task
                                done_on_behalf_of_user_id=done_on_behalf_of_user_id
                            )
                            db.session.add(notification)
                            db.session.commit()
                            print(f"Notification created for user {done_on_behalf_of_user_id}")
                        except Exception as e:
                            db.session.rollback()
                            print(f"Error creating notification: {e}")
                    else:
                        print(f"Invalid done_on_behalf_of_user_id: {done_on_behalf_of_user_id} - Notification not created.")

                # Update the monthly score summary after the task
                update_monthly_score_summary(
                    office_id=room.office_id,
                    user_id=user.id,
                    zone_name=zone_name,
                    year=new_task.date_submitted.year,
                    month=new_task.date_submitted.month
                )

                return jsonify({"message": "Task submitted successfully", "task_id": new_task.id}), 201

            except Exception as db_error:
                db.session.rollback()
                print(f"Database error: {db_error}")
                return jsonify({"message": "Failed to submit task", "error": str(db_error)}), 500
            finally:
                db.session.close()

        except Exception as e:
            print(f"Error submitting task: {e}")
            return jsonify({"message": "Failed to submit task", "error": str(e)}), 500








    @app.route('/api/rooms/<int:room_id>/report', methods=['GET'])
    def get_room_report(room_id):
        user_id = request.args.get('user_id')  # Get user_id from query parameter

        # Fetch the most recent task submission for the room and user, if user_id is provided
        if user_id:
            task = TaskSubmission.query.filter_by(room_id=room_id, user_id=user_id).order_by(TaskSubmission.date_submitted.desc()).first()
        else:
            task = TaskSubmission.query.filter_by(room_id=room_id).order_by(TaskSubmission.date_submitted.desc()).first()

        if not task:
            return jsonify({"message": "No task submission found for this room"}), 404

        # Decode the area_scores from JSON
        area_scores = json.loads(task.area_scores) if task.area_scores else {}

        return jsonify({
            "room_name": task.room.name,
            "room_score": task.room_score,
            "area_scores": area_scores,  # Include area scores in the response
            "zone_name": task.zone_name,
            "user_id": task.user_id,  # Include user_id for context
            "date_submitted": task.date_submitted.isoformat()  # Include submission date
        }), 200



    @app.route('/api/rooms/<int:room_id>/tasks', methods=['GET'])
    def get_tasks_by_room(room_id):
        user_id = request.args.get('user_id')  # Get user_id from query parameter

        # Fetch all task submissions for the room, filtered by user if provided
        if user_id:
            tasks = TaskSubmission.query.filter_by(room_id=room_id, user_id=user_id).all()
        else:
            tasks = TaskSubmission.query.filter_by(room_id=room_id).all()

        if not tasks:
            return jsonify({"message": "No tasks found for this room"}), 404

        tasks_data = []
        for task in tasks:
            tasks_data.append({
                "task_type": task.task_type,
                "date_submitted": task.date_submitted.isoformat(),  # Convert datetime to ISO format string
                "room_score": task.room_score,
                "area_scores": json.loads(task.area_scores) if task.area_scores else {},
                "zone_name": task.zone_name,
                "latitude": task.latitude,
                "longitude": task.longitude,
                "user_id": task.user_id  # Include user_id for context
            })

        return jsonify({"tasks": tasks_data}), 200


    @app.route('/api/users/<int:user_id>/offices', methods=['GET'])
    def get_assigned_offices(user_id):
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Fetch all offices associated with this user via the many-to-many relationship
        assigned_offices = user.offices

        if not assigned_offices:
            return jsonify({"message": "No offices assigned to this user"}), 200

        offices_data = []
        for office in assigned_offices:
            # Count the number of rooms in each office
            room_count = Room.query.filter_by(office_id=office.id).count()
            offices_data.append({
                'id': office.id,
                'name': office.name,
                'sector': office.sector,  # Include sector in the response
                'room_count': room_count,  # Add room count to the response
            })

        return jsonify({"offices": offices_data}), 200




    # Updated route to create office and room(s) and assign them to a user and zone
    from sqlalchemy.exc import IntegrityError

    @app.route('/api/admin/create_office_and_room', methods=['POST'])
    def create_office_and_room():
        data = request.get_json()
        office_name = data.get('office_name')
        user_ids = data.get('user_ids')  # Updated to accept multiple user IDs
        sector = data.get('sector')  # Get sector from the request

        # Validate the required parameters (room_names and zone no longer required)
        if not all([office_name, user_ids, sector]):
            return jsonify({"message": "Missing required fields."}), 400

        # Check if an office with the given name already exists
        existing_office = Office.query.filter_by(name=office_name).first()
        if existing_office:
            return jsonify({"message": f"Office with name '{office_name}' already exists."}), 409  # 409 Conflict

        try:
            # Fetch all users based on provided user_ids
            users = User.query.filter(User.id.in_(user_ids)).all()
            if not users:
                return jsonify({"message": "One or more users not found"}), 404

            # Create the new office with sector and associate users
            new_office = Office(name=office_name, sector=sector)
            new_office.users.extend(users)  # Associate multiple users to the office
            db.session.add(new_office)
            db.session.commit()  # Commit the office creation

            return jsonify({
                "message": "Office created successfully",
                "office_id": new_office.id
            }), 201

        except IntegrityError as e:
            db.session.rollback()
            # Check if the error is due to a unique constraint on office name or another constraint
            error_message = "An IntegrityError occurred when creating the office."
            if "duplicate key" in str(e.orig):
                error_message = f"Office with name '{office_name}' already exists."
            
            print(f"IntegrityError during office creation: {e}")
            return jsonify({"message": error_message, "error": str(e)}), 500

        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error during office creation: {e}")
            return jsonify({"message": "An unexpected error occurred", "error": str(e)}), 500







    @app.route('/api/users/<int:user_id>/offices/<int:office_id>/rooms/<string:zone>', methods=['GET'])
    def get_rooms_by_office_and_zone(user_id, office_id, zone):
        try:
            # Validate if the user exists
            user = User.query.get(user_id)
            if not user:
                return jsonify({"message": "User not found"}), 404

            # Fetch rooms that belong to the specific office, zone, and are assigned to the specific user
            rooms = (
                db.session.query(Room)
                .filter(
                    Room.office_id == office_id,
                    Room.zone == zone,
                    Room.user_id == user_id  # Ensure the room is assigned to this specific user
                )
                .all()
            )

            # Check if rooms are found
            if not rooms:
                return jsonify({"message": "No rooms found for this user in the specified office and zone"}), 404

            # Prepare the response data
            rooms_data = [{'id': room.id, 'name': room.name, 'zone': room.zone} for room in rooms]

            return jsonify({"rooms": rooms_data}), 200
        
        except Exception as e:
            # Log the error and return a 500 response
            print(f"Error fetching rooms: {e}")
            return jsonify({"message": "An error occurred while fetching rooms", "error": str(e)}), 500


    

    
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
        db.session.commit()

        # Send the new password to the user via email
        subject = "Password Reset Notification"
        content = f"""Hello {user.first_name},

        Your password has been successfully reset. Here are your new login credentials:

        Username: {user.username}
        New Password: {new_password}

        You will be required to change your password after logging in.

        Best regards,
        The Spaklean Team
        """

        # Assuming send_mailjet_email takes (recipient_email, subject, content)
        send_mailjet_email(user.username, subject, content)  # Modify 'user.username' if it's the email

        return jsonify({"message": "Password reset successfully, and email sent."}), 200

    
    
    from urllib.parse import unquote

    from sqlalchemy import extract  # Import extract for month/year filtering

    @app.route('/api/zones/<string:zone_name>/score', methods=['GET'])
    def get_zone_score(zone_name):
        zone_name = unquote(zone_name)
        office_id = request.args.get('office_id')
        user_id = request.args.get('user_id')
        month = request.args.get('month', type=int) or datetime.now().month
        year = request.args.get('year', type=int) or datetime.now().year

        if not office_id or not user_id:
            return jsonify({"message": "office_id and user_id are required"}), 400

        rooms = Room.query.filter_by(zone=zone_name, office_id=office_id, user_id=user_id).all()
        if not rooms:
            return jsonify({"zone_name": zone_name, "zone_score": "N/A"}), 200

        total_room_score = 0
        room_count = 0

        for room in rooms:
            query = TaskSubmission.query.filter_by(room_id=room.id, user_id=user_id)
            query = query.filter(
                extract('month', TaskSubmission.date_submitted) == month,
                extract('year', TaskSubmission.date_submitted) == year
            )
            tasks = query.all()

            for task in tasks:
                if task.room_score is not None:
                    total_room_score += task.room_score
                    room_count += 1

        if room_count == 0:
            return jsonify({"zone_name": zone_name, "zone_score": "N/A"}), 200

        # Calculate the zone score for the month
        zone_score = total_room_score / room_count

        # Update or insert monthly score summary
        monthly_summary = MonthlyScoreSummary.query.filter_by(
            month=month, year=year, office_id=office_id, user_id=user_id, zone_name=zone_name
        ).first()

        if not monthly_summary:
            monthly_summary = MonthlyScoreSummary(
                month=month, year=year, office_id=office_id, user_id=user_id, zone_name=zone_name, total_zone_score=zone_score
            )
            db.session.add(monthly_summary)
        else:
            monthly_summary.total_zone_score = zone_score

        db.session.commit()

        return jsonify({"zone_name": zone_name, "zone_score": round(zone_score, 2)}), 200







    

    #from sqlalchemy import extract  # Import extract for month/year filtering

    @app.route('/api/facility/score', methods=['GET'])
    def get_total_facility_score():
        office_id = request.args.get('office_id')
        user_id = request.args.get('user_id')
        month = request.args.get('month', type=int) or datetime.now().month
        year = request.args.get('year', type=int) or datetime.now().year

        if not office_id or not user_id:
            return jsonify({"message": "office_id and user_id are required"}), 400

        zones = db.session.query(Room.zone).filter_by(office_id=office_id, user_id=user_id).distinct().all()
        if not zones:
            return jsonify({"total_facility_score": "N/A"}), 200

        total_zone_score = 0
        zone_count = 0

        for zone in zones:
            zone_name = zone[0]
            rooms = Room.query.filter_by(zone=zone_name, office_id=office_id, user_id=user_id).all()
            total_room_score = 0
            room_count = 0

            for room in rooms:
                query = TaskSubmission.query.filter_by(room_id=room.id, user_id=user_id)
                query = query.filter(
                    extract('month', TaskSubmission.date_submitted) == month,
                    extract('year', TaskSubmission.date_submitted) == year
                )
                tasks = query.all()

                for task in tasks:
                    if task.room_score is not None:
                        total_room_score += task.room_score
                        room_count += 1

            if room_count > 0:
                zone_score = total_room_score / room_count
                total_zone_score += zone_score
                zone_count += 1

        if zone_count == 0:
            return jsonify({"total_facility_score": "N/A"}), 200

        total_facility_score = total_zone_score / zone_count

        # Update or insert into monthly summary table
        monthly_summary = MonthlyScoreSummary.query.filter_by(
            month=month, year=year, office_id=office_id, user_id=user_id, zone_name=None
        ).first()

        if not monthly_summary:
            monthly_summary = MonthlyScoreSummary(
                month=month, year=year, office_id=office_id, user_id=user_id, total_facility_score=total_facility_score
            )
            db.session.add(monthly_summary)
        else:
            monthly_summary.total_facility_score = total_facility_score

        db.session.commit()

        return jsonify({"total_facility_score": round(total_facility_score, 2)}), 200



    

    # @app.route('/api/attendance', methods=['POST'])
    # def record_attendance():
    #     data = request.get_json()
    #     user_id = data.get('user_id')
    #     office_id = data.get('office_id')
    #     check_in_time = data.get('check_in_time')
    #     check_in_lat = data.get('check_in_lat')
    #     check_in_long = data.get('check_in_long')
    #     check_out_time = data.get('check_out_time')
    #     check_out_lat = data.get('check_out_lat')
    #     check_out_long = data.get('check_out_long')

    #     # Add validation for required fields
    #     if not user_id or not office_id:
    #         return jsonify({"message": "Missing required fields"}), 400

    #     try:
    #         # Save attendance to database
    #         attendance = Attendance(
    #             user_id=user_id,
    #             office_id=office_id,
    #             check_in_time=check_in_time,
    #             check_in_lat=check_in_lat,
    #             check_in_long=check_in_long,
    #             check_out_time=check_out_time,
    #             check_out_lat=check_out_lat,
    #             check_out_long=check_out_long,
    #         )
    #         db.session.add(attendance)
    #         db.session.commit()
    #         return jsonify({"message": "Attendance recorded successfully"}), 201
    #     except Exception as e:
    #         return jsonify({"message": f"Error recording attendance: {str(e)}"}), 500
        

        
    
    


    # Route to check attendance status for a user and office
    @app.route('/api/attendance/status', methods=['GET'])
    def get_attendance_status():
        user_id = request.args.get('user_id')
        office_id = request.args.get('office_id')

        if not user_id or not office_id:
            return jsonify({"message": "User ID and Office ID are required"}), 400

        today = date.today()

        # Fetch all check-in/out records for today
        attendance_today = Attendance.query.filter_by(user_id=user_id, office_id=office_id) \
            .filter(db.func.date(Attendance.check_in_time) == today) \
            .order_by(Attendance.check_in_time.asc()) \
            .all()

        if attendance_today:
            attendance_history = Attendance.query.filter_by(user_id=user_id, office_id=office_id).all()
            history_data = [
                {
                    'check_in_time': record.check_in_time.isoformat() if record.check_in_time else None,
                    'check_out_time': record.check_out_time.isoformat() if record.check_out_time else None,
                    'check_in_lat': record.check_in_lat,
                    'check_in_long': record.check_in_long,
                    'check_out_lat': record.check_out_lat,
                    'check_out_long': record.check_out_long
                } for record in attendance_history
            ]
            return jsonify({
                "attendance_today": [
                    {
                        "check_in_time": record.check_in_time.isoformat() if record.check_in_time else None,
                        "check_in_lat": record.check_in_lat,
                        "check_in_long": record.check_in_long,
                        "check_out_time": record.check_out_time.isoformat() if record.check_out_time else None,
                        "check_out_lat": record.check_out_lat,
                        "check_out_long": record.check_out_long,
                    }
                    for record in attendance_today
                ],
                "attendance_history": history_data
            }), 200

        return jsonify({"message": "No attendance record found for today"}), 404

    # Route to check-in
    @app.route('/api/attendance/checkin', methods=['POST'])
    def check_in():
        data = request.get_json()

        user_id = data.get('user_id')
        office_id = data.get('office_id')
        check_in_time = data.get('check_in_time')
        check_in_lat = data.get('check_in_lat')
        check_in_long = data.get('check_in_long')

        if not user_id or not office_id or not check_in_time:
            return jsonify({"message": "Missing required fields"}), 400

        try:
            # Save attendance to the database (new session)
            attendance = Attendance(
                user_id=user_id,
                office_id=office_id,
                check_in_time=datetime.fromisoformat(check_in_time),
                check_in_lat=check_in_lat,
                check_in_long=check_in_long
            )
            db.session.add(attendance)
            db.session.commit()

            return jsonify({"message": "Check-in recorded successfully"}), 201
        except Exception as e:
            return jsonify({"message": f"Error recording check-in: {str(e)}"}), 500

    # Route to check-out
    @app.route('/api/attendance/checkout', methods=['POST'])
    def check_out():
        data = request.get_json()
        user_id = data.get('user_id')
        office_id = data.get('office_id')
        check_out_time = data.get('check_out_time')
        check_out_lat = data.get('check_out_lat')
        check_out_long = data.get('check_out_long')

        if not user_id or not office_id or not check_out_time:
            return jsonify({"message": "Missing required fields"}), 400

        today = date.today()

        try:
            # Find the latest check-in without a check-out for today
            attendance = Attendance.query.filter_by(user_id=user_id, office_id=office_id) \
                .filter(db.func.date(Attendance.check_in_time) == today) \
                .filter(Attendance.check_out_time.is_(None)) \
                .order_by(Attendance.check_in_time.desc()) \
                .first()

            if attendance:
                # Update the check-out information
                attendance.check_out_time = datetime.fromisoformat(check_out_time)
                attendance.check_out_lat = check_out_lat
                attendance.check_out_long = check_out_long
                db.session.commit()
                return jsonify({"message": "Check-out recorded successfully"}), 201
            else:
                return jsonify({"message": "No active check-in found for today or already checked out"}), 400

        except Exception as e:
            return jsonify({"message": f"Error recording check-out: {str(e)}"}), 500

    # Route to get attendance history for a user and office
    @app.route('/api/attendance/history', methods=['GET'])
    def get_attendance_history():
        user_id = request.args.get('user_id')
        office_id = request.args.get('office_id')

        if not user_id or not office_id:
            return jsonify({"message": "User ID and Office ID are required"}), 400

        try:
            # Fetch all attendance records for the user and office
            attendance_history = Attendance.query.filter_by(user_id=user_id, office_id=office_id) \
                .order_by(Attendance.check_in_time.asc()) \
                .all()

            if attendance_history:
                history_data = [
                    {
                        'check_in_time': record.check_in_time.isoformat() if record.check_in_time else None,
                        'check_out_time': record.check_out_time.isoformat() if record.check_out_time else None,
                        'check_in_lat': record.check_in_lat,
                        'check_in_long': record.check_in_long,
                        'check_out_lat': record.check_out_lat,
                        'check_out_long': record.check_out_long
                    } for record in attendance_history
                ]
                return jsonify({"history": history_data}), 200
            else:
                return jsonify({"message": "No attendance history found"}), 404

        except Exception as e:
            return jsonify({"message": f"Error fetching attendance history: {str(e)}"}), 500




        


    # from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
    
    

    # # Serializer for generating and validating tokens
    # serializer = URLSafeTimedSerializer('your_secret_key')  # Replace with a secure key

    # @app.route('/api/auth/forgot_password', methods=['POST'])
    # def forgot_password():
    #     data = request.get_json()
    #     email = data.get('email')

    #     if not email:
    #         return jsonify({"message": "Email is required"}), 400

    #     # Check if the user exists
    #     user = User.query.filter_by(username=email).first()  # Assuming username is the email
    #     if not user:
    #         return jsonify({"message": "No user found with this email"}), 404

    #     # Generate a token valid for 1 hour
    #     token = serializer.dumps(email, salt='password-reset-salt')

    #     # Generate the password reset URL (url_for generates a URL for the reset_password route)
    #     reset_url = url_for('reset_password', token=token, _external=True)

    #     # Send the reset password email
    #     subject = "Password Reset Request"
    #     content = f"""Hello {user.username},

    # You requested to reset your password. Click the link below to reset it:
    # {reset_url}

    # If you did not request this, please ignore this email.

    # Best regards,
    # Spaklean Team
    # """
    #     send_mailjet_email(user.username, subject, content)

    #     return jsonify({"message": "Password reset email sent"}), 200
    

    # @app.route('/api/auth/reset_password_with_token/<token>', methods=['POST'])
    # def reset_password_with_token(token):
    #     try:
    #         # Validate the token (expires after 1 hour)
    #         email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    #     except SignatureExpired:
    #         return jsonify({"message": "The reset link has expired."}), 400
    #     except BadSignature:
    #         return jsonify({"message": "Invalid or expired reset token."}), 400

    #     # Get the new password from the request
    #     data = request.get_json()
    #     new_password = data.get('new_password')

    #     if not new_password:
    #         return jsonify({"message": "New password is required"}), 400

    #     # Find the user by email
    #     user = User.query.filter_by(username=email).first()
    #     if not user:
    #         return jsonify({"message": "User not found"}), 404

    #     # Hash the new password and update the user
    #     hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    #     user.password_hash = hashed_password
    #     db.session.commit()

    #     return jsonify({"message": "Password has been reset successfully."}), 200



   

# Helper function to generate a random temporary password
    def generate_temp_password(length=10):
        letters_and_digits = string.ascii_letters + string.digits
        return ''.join(random.choice(letters_and_digits) for i in range(length))

    # Forgot Password Route
    @app.route('/api/auth/forgot_password', methods=['POST'])
    def forgot_password():
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"message": "Email is required"}), 400

        # Check if the user exists (assuming username is the email)
        user = User.query.filter_by(username=email).first()
        if not user:
            return jsonify({"message": "No user found with this email"}), 404

        # Generate a temporary password
        temp_password = generate_temp_password()

        # Hash the temporary password and update user's password in the database
        hashed_temp_password = bcrypt.generate_password_hash(temp_password).decode('utf-8')
        user.password_hash = hashed_temp_password

        # Mark user as requiring password change on next login
        user.password_change_required = True
        db.session.commit()

        # Send the temporary password to the user's email
        subject = "Temporary Password for Spaklean"
        content = f"""Hello {user.first_name},

        A request was made to reset your password. Here is your temporary login password:

        Temporary Password: {temp_password}

        You will be required to change your password after logging in.

        If you did not request this, please contact support.

        Best regards,
        The Spaklean Team
        """

        # Assuming send_mailjet_email takes (recipient_email, subject, content)
        send_mailjet_email(user.username, subject, content)  # Modify 'user.username' if it's the email

        return jsonify({"message": "Temporary password sent to your email"}), 200


    @app.route('/api/admin/add_more_rooms', methods=['POST'])
    def add_more_rooms():
        data = request.get_json()
        user_id = data.get('user_id')
        office_id = data.get('office_id')
        room_names = data.get('room_names')  # Expecting a list of room names
        zone = data.get('zone')  # Expecting a zone

        if not all([user_id, office_id, room_names, zone]):
            return jsonify({"message": "User ID, Office ID, Room Names, and Zone are required."}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found."}), 404

        office = Office.query.get(office_id)
        if not office:
            return jsonify({"message": "Office not found."}), 404

        # Add rooms to the existing office
        room_ids = []
        for room_name in room_names:
            new_room = Room(name=room_name, zone=zone, office_id=office_id, user_id=user_id)
            db.session.add(new_room)
            db.session.commit()
            room_ids.append(new_room.id)

        return jsonify({"message": "Rooms added successfully", "room_ids": room_ids}), 201

    

    # Add this route in your Flask application file

    @app.route('/api/admin/assign_users_to_office', methods=['POST'])
    def assign_users_to_office():
        data = request.get_json()
        office_id = data.get('office_id')
        user_ids = data.get('user_ids')

        # Validate the inputs
        if not office_id or not user_ids or not isinstance(user_ids, list):
            return jsonify({"message": "Office ID and list of User IDs are required."}), 400

        try:
            # Fetch the office by ID
            office = Office.query.get(office_id)
            if not office:
                return jsonify({"message": "Office not found."}), 404

            # Fetch all users based on the provided user IDs
            users = User.query.filter(User.id.in_(user_ids)).all()
            if not users:
                return jsonify({"message": "One or more users not found."}), 404

            # Associate the users with the office
            office.users.extend(users)

            # Commit the changes to the database
            db.session.commit()

            return jsonify({"message": "Users assigned to office successfully."}), 200

        except Exception as e:
            # Log the error if any
            return jsonify({"message": "An error occurred while assigning users.", "error": str(e)}), 500
        

    @app.route('/api/admin/offices', methods=['GET'])
    def get_all_offices():
        try:
            # Fetch all offices from the database
            offices = Office.query.all()
            
            # Create a list of office data
            offices_data = [
                {
                    'id': office.id,
                    'name': office.name,
                    'sector': office.sector,  # Assuming sector exists in the Office model
                }
                for office in offices
            ]
            
            # Return the list of offices
            return jsonify({"offices": offices_data}), 200
        
        except Exception as e:
            # Log and handle any errors that occur
            print(f"Error fetching offices: {e}")
            return jsonify({"message": "Failed to load offices", "error": str(e)}), 500
        

    @app.route('/api/offices/<int:office_id>/company_score', methods=['GET'])
    def get_company_score(office_id):
        try:
            # Fetch all users associated with the office
            users = User.query.filter_by(office_id=office_id).all()
            
            if not users:
                return jsonify({"message": "No users found for this office"}), 404
            
            # Collect room scores from all tasks related to users in this office
            total_score = 0
            task_count = 0
            
            for user in users:
                tasks = TaskSubmission.query.filter_by(user_id=user.id).all()
                for task in tasks:
                    total_score += task.room_score
                    task_count += 1
            
            # Calculate the average (company) score
            company_score = (total_score / task_count) if task_count > 0 else 0.0
            
            return jsonify({
                "office_id": office_id,
                "company_score": round(company_score, 2)  # Rounded to 2 decimal places
            }), 200
            
        except Exception as e:
            print(f"Error fetching company score: {e}")
            return jsonify({"message": "Failed to fetch company score", "error": str(e)}), 500
        

    from sqlalchemy import func

    @app.route('/api/score_summary', methods=['GET'])
    def score_summary():
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400

        # Fetch the user and ensure they exist
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Find the user's office and sector via the user_office relationship
        office = (
            db.session.query(Office)
            .join(user_office, Office.id == user_office.c.office_id)
            .filter(user_office.c.user_id == user_id)
            .first()
        )

        if not office:
            return jsonify({"error": "No office found for the user"}), 404

        sector = office.sector
        office_id = office.id

        # Define zones
        zones = [
            'Low Traffic Areas (Yellow Zone)',
            'Heavy Traffic Areas (Orange Zone)',
            'Food Service Areas (Green Zone)',
            'High Microbial Areas (Red Zone)',
            'Outdoors & Exteriors (Black Zone)'
        ]

        score_summary = {}

        for zone in zones:
            # Calculate user's average score for this zone
            user_zone_score = db.session.query(func.avg(TaskSubmission.room_score))\
                .filter(TaskSubmission.user_id == user_id, TaskSubmission.zone_name == zone)\
                .scalar()

            # Calculate the company's average score for this zone
            company_zone_score = db.session.query(func.avg(TaskSubmission.room_score))\
                .join(user_office, TaskSubmission.user_id == user_office.c.user_id)\
                .filter(user_office.c.office_id == office_id, TaskSubmission.zone_name == zone)\
                .scalar()

            # Calculate the sector's average score for this zone
            sector_zone_score = db.session.query(func.avg(TaskSubmission.room_score))\
                .join(user_office, TaskSubmission.user_id == user_office.c.user_id)\
                .join(Office, Office.id == user_office.c.office_id)\
                .filter(Office.sector == sector, TaskSubmission.zone_name == zone)\
                .scalar()

            # Store scores in the summary dictionary, handle None results by using 'N/A'
            score_summary[zone] = {
                "yourScore": round(user_zone_score, 2) if user_zone_score is not None else "N/A",
                "companyScore": round(company_zone_score, 2) if company_zone_score is not None else "N/A",
                "sectorScore": round(sector_zone_score, 2) if sector_zone_score is not None else "N/A",
            }

        return jsonify(score_summary), 200
    
        # Define the helper function
    def update_monthly_score_summary(office_id, user_id, zone_name, year, month):
        # Calculate total zone score for the given month
        total_zone_score = (
            db.session.query(func.avg(TaskSubmission.room_score))
            .join(Room, TaskSubmission.room_id == Room.id)
            .filter(
                TaskSubmission.user_id == user_id,
                Room.office_id == office_id,
                TaskSubmission.zone_name == zone_name,
                func.extract('year', TaskSubmission.date_submitted) == year,
                func.extract('month', TaskSubmission.date_submitted) == month
            )
            .scalar()
        )
        
        # Calculate total facility score for the month across all zones
        total_facility_score = (
            db.session.query(func.avg(TaskSubmission.room_score))
            .join(Room, TaskSubmission.room_id == Room.id)
            .filter(
                TaskSubmission.user_id == user_id,
                Room.office_id == office_id,
                func.extract('year', TaskSubmission.date_submitted) == year,
                func.extract('month', TaskSubmission.date_submitted) == month
            )
            .scalar()
        )

        # Check if there's an existing record in monthly_score_summary for the month, year, user, office, and zone
        summary_record = MonthlyScoreSummary.query.filter_by(
            office_id=office_id,
            user_id=user_id,
            zone_name=zone_name,
            year=year,
            month=month
        ).first()
        
        if summary_record:
            # Update the existing record
            summary_record.total_zone_score = total_zone_score
            summary_record.total_facility_score = total_facility_score
        else:
            # Insert a new record
            new_summary = MonthlyScoreSummary(
                office_id=office_id,
                user_id=user_id,
                zone_name=zone_name,
                year=year,
                month=month,
                total_zone_score=total_zone_score,
                total_facility_score=total_facility_score
            )
            db.session.add(new_summary)

        db.session.commit()


    @app.route('/api/admin/users', methods=['GET'])
    def get_users():
        users = User.query.all()
        users_data = []

        for user in users:
            # Original data structure
            user_data = {
                'id': user.id,
                'username': user.username
            }
            
            # New fields added
            user_data['role'] = user.role  # Include user role
            user_data['offices'] = [
                {
                    'id': office.id,
                    'name': office.name,
                    'sector': office.sector  # Include office sector
                }
                for office in user.offices
            ]
            
            # Append the user_data dictionary with additional fields
            users_data.append(user_data)

        return jsonify({"users": users_data}), 200
    

    @app.route('/api/users/<int:user_id>/notifications', methods=['GET'])
    def get_notifications(user_id):
        # Fetch the user to confirm existence
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Check if the client only wants unread notifications
        only_unread = request.args.get('only_unread', 'false').lower() == 'true'
        
        # Prepare the query for notifications based on read/unread status
        notifications_query = Notification.query.filter_by(user_id=user_id)
        if only_unread:
            notifications_query = notifications_query.filter_by(is_read=False)

        # Retrieve notifications, ensuring they are ordered by the latest timestamp
        notifications = notifications_query.order_by(Notification.timestamp.desc()).all()
        
        # Serialize notifications, including the is_read status
        notifications_data = [
            {
                "id": notification.id,
                "message": notification.message,
                "timestamp": notification.timestamp.isoformat(),
                "is_read": notification.is_read,  # Ensure this reflects the actual read status
                "done_by_user_id": notification.done_by_user_id,
                "done_on_behalf_of_user_id": notification.done_on_behalf_of_user_id
            }
            for notification in notifications
        ]
        return jsonify({"notifications": notifications_data}), 200




    @app.route('/api/users/<int:user_id>/notifications/mark_all_as_read', methods=['POST'])
    def mark_all_notifications_as_read(user_id):
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        notifications = Notification.query.filter_by(user_id=user_id, is_read=False).all()
        for notification in notifications:
            notification.is_read = True

        db.session.commit()
        return jsonify({"message": "All notifications marked as read"}), 200
    
    @app.route('/api/users/<int:user_id>/notifications/<int:notification_id>/mark_as_read', methods=['POST'])
    def mark_notification_as_read(user_id, notification_id):
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Find the specific notification for the user
        notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
        if not notification:
            return jsonify({"message": "Notification not found"}), 404

        # Update the notification's read status
        notification.is_read = True
        db.session.commit()

        return jsonify({"message": "Notification marked as read"}), 200

    

    @app.route('/api/users/<int:user_id>/details', methods=['GET'])
    def get_user_details(user_id):
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'middle_name': user.middle_name,
            'last_name': user.last_name,
            'email': user.username  # Assuming username is the email
        }
        return jsonify(user_data), 200








    return app

# Expose the app object for Gunicorn
app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
