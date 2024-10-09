from flask import Blueprint, request, jsonify
from app import db, bcrypt
from models import User
from flask_jwt_extended import create_access_token

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        # Ensure all required fields are provided
        if not data or 'username' not in data or 'password' not in data or 'role' not in data:
            return jsonify({"error": "Missing required fields: username, password, and role"}), 400

        username = data['username']
        password = data['password']
        role = data['role']

        # Check if the user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "User already exists"}), 400

        # Hash the password and create a new user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=password_hash, role=role)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": "An error occurred during registration", "message": str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        # Ensure all required fields are provided
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Missing required fields: username and password"}), 400

        username = data['username']
        password = data['password']

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        # Check if user exists and if the password matches
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Create a JWT token with the username and role as identity
            access_token = create_access_token(identity={'username': user.username, 'role': user.role})
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": "An error occurred during login", "message": str(e)}), 500
