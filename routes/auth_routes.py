from flask import Blueprint, request, jsonify, current_app
from models import User
from flask_jwt_extended import create_access_token

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    role = data['role']

    # Access db and bcrypt through current_app
    db = current_app.extensions['sqlalchemy'].db
    bcrypt = current_app.extensions['bcrypt']

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=password_hash, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Access db and bcrypt through current_app
    db = current_app.extensions['sqlalchemy'].db
    bcrypt = current_app.extensions['bcrypt']

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200

    return jsonify({"message": "Invalid credentials"}), 401
