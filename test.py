from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

with app.app_context():
    try:
        db.engine.connect()  # Try connecting to the database
        print("Connection to the MySQL database was successful.")
    except Exception as e:
        print(f"An error occurred: {e}")
