from flask import Blueprint, request, jsonify
from app import db, bcrypt  # Ensure bcrypt is imported
from models import Office, Room, User

admin_bp = Blueprint('admin', __name__)

# Route to create an office
@admin_bp.route('/create_office', methods=['POST'])
def create_office():
    data = request.get_json()

    # Simple validation
    if 'name' not in data:
        return jsonify({"error": "Office name is required"}), 400

    name = data['name']
    
    # Create and save the new office
    new_office = Office(name=name)
    db.session.add(new_office)
    db.session.commit()

    return jsonify({"message": "Office created successfully!"}), 201

# Route to create a room
@admin_bp.route('/create_room', methods=['POST'])
def create_room():
    data = request.get_json()

    # Simple validation
    if 'office_id' not in data or 'name' not in data:
        return jsonify({"error": "Both office_id and room name are required"}), 400

    office_id = data['office_id']
    name = data['name']
    
    # Create and save the new room
    new_room = Room(name=name, office_id=office_id)
    db.session.add(new_room)
    db.session.commit()

    return jsonify({"message": "Room created successfully!"}), 201

# Route to create test data (user, office, and room)
@admin_bp.route('/create_test_data', methods=['POST'])
def create_test_data():
    # Create a test user
    hashed_password = bcrypt.generate_password_hash('testpassword').decode('utf-8')
    test_user = User(username='testuser', password_hash=hashed_password, role='custodian')
    db.session.add(test_user)

    # Create a test office and assign it to the user
    office = Office(name="Main Office", user=test_user)
    db.session.add(office)

    # Create a test room in the office
    room = Room(name="Conference Room", office=office)
    db.session.add(room)

    # Commit all changes to the database
    db.session.commit()

    return jsonify({"message": "Test data created successfully!"}), 201
