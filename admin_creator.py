import mysql.connector 
from argon2 import PasswordHasher 
import os 

from dotenv import load_dotenv 

load_dotenv()

ph = PasswordHasher()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

conn = mysql.connector.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD,
    database=DB_NAME
)

cur = conn.cursor()

cur.execute("INSERT INTO users (username, email, password, is_verified, is_admin, is_banned) VALUES (%s, %s, %s, %s, %s, %s)",("Support Karinka", "flowerskarinka@gmail.com", ph.hash(os.getenv("PASSWORD")), True, True, False))

conn.commit()
conn.close()