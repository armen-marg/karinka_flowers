import mysql.connector 
from argon2 import PasswordHasher 

ph = PasswordHasher()

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Hl3trt93!",
    database="karinka_db"
)

cur = conn.cursor()

cur.execute("INSERT INTO users (username, email, password, is_verified, is_admin, is_banned) VALUES (%s, %s, %s, %s, %s, %s)",("Support Karinka", "flowerskarinka@gmail.com", ph.hash("Hl3trt93!@!123Hl3trt93!Armen"), True, True, False))

conn.commit()
conn.close()