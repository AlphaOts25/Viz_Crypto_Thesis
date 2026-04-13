from pymongo import MongoClient
from werkzeug.security import generate_password_hash

# 1. Connect to your local MongoDB server
client = MongoClient('mongodb://localhost:27017/')

# Create (or connect to) a database called 'thesis_db'
db = client['thesis_db']

# Drop the users collection if it exists so we start with a clean slate
db.users.drop()

print("Setting up MongoDB database...")

# ---------------------------------------------------------
# 2. CREATE THE ADMIN (PROFESSOR)
# ---------------------------------------------------------
admin_data = {
    "username": "admin",
    "email": "admin@test.com",
    "password_hash": generate_password_hash('admin123'),
    "role": "admin"
}

# Insert the admin into the database
admin_result = db.users.insert_one(admin_data)

# MongoDB automatically generates a unique '_id' for every entry.
# We need to save this ID so we can link the student to this specific admin!
admin_id = admin_result.inserted_id
print(f"Created Admin with ID: {admin_id}")


# ---------------------------------------------------------
# 3. CREATE THE STUDENT
# ---------------------------------------------------------
student_data = {
    "username": "test_student",
    "email": "student@test.com",
    "password_hash": generate_password_hash('student123'),
    "role": "student",
    
    # Track individual quiz scores dynamically
    "quiz_scores": {
        "module1": 0,
        "module2": 0,
        "module3": 0
    },
    
    # Track the total score across the whole system
    "total_score": 0,
    
    # THE CONNECTION: Link this student to the admin we created above
    "professor_id": admin_id
}

# Insert the student into the database
db.users.insert_one(student_data)
print("Created Student account successfully!")

print("\n--- Setup Complete ---")
print("You can now view your 'thesis_db' in MongoDB Compass.")