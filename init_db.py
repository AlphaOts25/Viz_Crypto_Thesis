import sqlite3
from werkzeug.security import generate_password_hash

def initialize_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    print("Clearing old database structure...")
    # WARNING: This deletes the old tables so we can build the new ones.
    cursor.executescript('''
        DROP TABLE IF EXISTS progress;
        DROP TABLE IF EXISTS materials;
        DROP TABLE IF EXISTS modules;
        DROP TABLE IF EXISTS users;
    ''')

    print("Building new tables...")
    # 1. Create Users Table (Now includes email and role)
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. Create Modules Table
    cursor.execute('''
        CREATE TABLE modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT
        )
    ''')

    # 3. Create Materials Table (For the Admin)
    cursor.execute('''
        CREATE TABLE materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            module_id INTEGER NOT NULL,
            admin_id INTEGER NOT NULL,
            video_url TEXT,
            lesson_text TEXT,
            FOREIGN KEY (module_id) REFERENCES modules (id),
            FOREIGN KEY (admin_id) REFERENCES users (id)
        )
    ''')

    # 4. Create Progress Table (For the Student Pre/Post tests)
    cursor.execute('''
        CREATE TABLE progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            module_id INTEGER NOT NULL,
            pre_test_score INTEGER,
            post_test_score INTEGER,
            is_completed BOOLEAN DEFAULT 0,
            completed_at TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users (id),
            FOREIGN KEY (module_id) REFERENCES modules (id)
        )
    ''')

    print("Injecting default data...")
    # --- INSERT DEFAULT DATA ---

    # Add Admin User
    admin_pw = generate_password_hash('admin123')
    cursor.execute('''
        INSERT INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin@test.com', admin_pw, 'admin'))

    # Add a Test Student User
    student_pw = generate_password_hash('student123')
    cursor.execute('''
        INSERT INTO users (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
    ''', ('test_student', 'student@test.com', student_pw, 'student'))

    # Add the first 3 Cryptography Modules
    modules = [
        ('Encryption & Decryption', 'Introduction to plaintext, ciphertext, and core mechanics.'),
        ('Symmetric Encryption', 'Exploring shared keys, AES, and the key distribution problem.'),
        ('Key Exchange Problem', 'Understanding secure distribution, Eve, and Diffie-Hellman.')
    ]
    cursor.executemany('INSERT INTO modules (title, description) VALUES (?, ?)', modules)

    conn.commit()
    conn.close()
    
    print("--- SUCCESS! ---")
    print("Database successfully renewed!")
    print("1 Admin account: (admin / admin123)")
    print("1 Student account: (test_student / student123)")
    print("3 Cryptography Modules added.")

if __name__ == '__main__':
    initialize_database()