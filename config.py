# # config.py
# import os

# class Config:
#     SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
#     SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://spakleanappdb_user:Mw90MDXjPo1lSq2NZQPS4WpzcNLc9p96@dpg-cs3gqg88fa8c73dbto00-a.oregon-postgres.render.com/spakleanappdb'
#     SQLALCHEMY_TRACK_MODIFICATIONS = False


# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    #SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://spaklean_noni2:xin.AD98oii@198.57.242.9/spaklean_spakleanappdb'
    #SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://spaklean_noni2:xin.AD98oii@198.57.242.9/spaklean_spakleanappdb'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://spaklean_noni3:xin.AD98oii@198.57.242.9/spaklean_spakleanappdb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True

    # Add connection pool settings here
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "pool_timeout": 30,
        "pool_size": 10,
        "max_overflow": 20
    }

    print("Connecting to database:", SQLALCHEMY_DATABASE_URI)


# I commented out posgres libraries at the requirements and updated the below config.py. 
# I also added the render IP or domain on cpanel    








