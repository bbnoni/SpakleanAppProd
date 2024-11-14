# import pymysql
# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# from config import Config

# try:
#     connection = pymysql.connect(
#         host='198.57.242.9',
#         user='spaklean_noni3',
#         password='xin.AD98oii',
#         database='spaklean_spakleanappdb',
#         connect_timeout=60
#     )
#     print("Connection successful")
# except Exception as e:
#     print("Connection failed:", e)
# finally:
#     if 'connection' in locals():
#         connection.close()


from sqlalchemy import create_engine

# Confirming the connection URL is correct
db_uri = 'mysql+pymysql://spaklean_noni2:xin%2EAD98oii%40@198.57.242.9/spaklean_spakleanappdb'
engine = create_engine(db_uri)

try:
    with engine.connect() as connection:
        print("Connection successful.")
except Exception as e:
    print("Connection failed:", e)


# from sqlalchemy import create_engine

# # Use 'mysql+mysqldb://' as the dialect with mysqlclient
# db_uri = 'mysql+mysqldb://spaklean_noni2:xin.AD98oii@198.57.242.9/spaklean_spakleanappdb'
# engine = create_engine(db_uri)

# try:
#     with engine.connect() as connection:
#         print("Connection successful.")
# except Exception as e:
#     print("Connection failed:", e)


