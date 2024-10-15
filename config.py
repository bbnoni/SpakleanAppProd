# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://spakleanappdb_user:Mw90MDXjPo1lSq2NZQPS4WpzcNLc9p96@dpg-cs3gqg88fa8c73dbto00-a.oregon-postgres.render.com/spakleanappdb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False





