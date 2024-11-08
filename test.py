from flask import Config
from config import Config
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError



from sqlalchemy import create_engine

class Config:
    SECRET_KEY = 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://spaklean@localhost:xin.AD98oii@197.251.154.50/spaklean_spakleanappdb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

def test_connection():
    try:
        engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
        connection = engine.connect()
        print("Connection to the database was successful!")
        connection.close()
    except Exception as e:
        print(f"An error occurred while connecting to the database: {e}")

if __name__ == "__main__":
    test_connection()



