# app.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from config import Config

# Initialize the Flask app
app = Flask(__name__)

# Load configuration
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
cors = CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# Import and register blueprints
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp  # Ensure this is imported
from routes.task_routes import task_bp

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(admin_bp, url_prefix='/api/admin')  # Ensure this is registered
app.register_blueprint(task_bp, url_prefix='/api/tasks')

# Run the application if this script is executed directly
if __name__ == '__main__':
    app.run(debug=True)
