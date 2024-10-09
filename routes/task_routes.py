from flask import Blueprint, request, jsonify
from app import db
from models import TaskSubmission
from flask_jwt_extended import jwt_required, get_jwt_identity

task_bp = Blueprint('tasks', __name__)

@task_bp.route('/submit', methods=['POST'])
@jwt_required()
def submit_task():
    data = request.get_json()
    task_type = data['task_type']
    latitude = data['latitude']
    longitude = data['longitude']

    user = get_jwt_identity()
    submission = TaskSubmission(task_type=task_type, latitude=latitude, longitude=longitude, user_id=user['id'])

    db.session.add(submission)
    db.session.commit()

    return jsonify({"message": "Task submitted successfully"}), 201
