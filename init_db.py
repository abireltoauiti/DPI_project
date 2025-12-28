# init_db.py
import sqlite3
from werkzeug.security import generate_password_hash

def init_db():

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
        )
    ''')

    
    admin_username = "admin"
    admin_password = generate_password_hash("admin123")  
    admin_role = "admin"

    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (admin_username, admin_password, admin_role)
        )
        print("[INFO] Admin créé avec succès ")
    except sqlite3.IntegrityError:
        print("[INFO] Admin déjà existant ")

    conn.commit()
    conn.close()
    print("[INFO] Base de données initialisée avec succès ")

if __name__ == "__main__":
    init_db()
