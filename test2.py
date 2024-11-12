import pymysql
from flask import Flask
from flask import pymysql
from flask_sqlalchemy import SQLAlchemy
from config import Config

try:
    connection = pymysql.connect(
        host='198.57.242.9',
        user='spaklean_noni3',
        password='xin.AD98oii',
        database='spaklean_spakleanappdb',
        connect_timeout=60
    )
    print("Connection successful")
except Exception as e:
    print("Connection failed:", e)
finally:
    if 'connection' in locals():
        connection.close()
