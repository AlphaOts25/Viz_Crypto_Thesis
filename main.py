from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash    
import sqlite3
from bson.objectid import ObjectId
from pymongo import MongoClient
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
# IMPORTANT: In a real app, this should be a random string hidden in a .env file
app.secret_key = 'super_secret_thesis_key_change_this_later' 

#MONGO
client = MongoClient('mongodb://localhost:27017/')
db = client['thesis_db']


# --- Setup Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Tells Flask where to send users who aren't logged in

# Helper function to connect to the DB
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row # Lets us access columns by name
    return conn

# Create a User class that Flask-Login can understand
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = str(id)
        self.username = username
        self.role = role




# This tells Flask how to find a user in the DB based on their session ID
@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    
    if user_data:
        return User(id=user_data['_id'], username=user_data['username'], role=user_data['role'])
    return None

#----------LOGIN----------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 1. Grab the data from the form
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        professor_id = request.form.get('professor_id')

        # 2. Basic Validation
        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))

        # 3. Check if user already exists
        existing_user = db.users.find_one({
            "$or": [{"username": username}, {"email": email}]
        })
        
        if existing_user:
            flash('Username or Email already exists. Please choose another.')
            return redirect(url_for('register'))

        # 4. Build the new Student Document
        new_student = {
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": "student",
            "quiz_scores": {
                "module1": 0,
                "module2": 0,
                "module3": 0
            },
            "total_score": 0,
            # We convert the string from the dropdown back into a MongoDB ObjectId
            "professor_id": ObjectId(professor_id) 
        }

        # 5. Save to MongoDB!
        db.users.insert_one(new_student)
        flash('Account created successfully! You can now log in.')
        return redirect(url_for('login'))

    # If it's a GET request, fetch all admins so the student can select their professor
    admins = list(db.users.find({"role": "admin"}))
    return render_template('auth/register.html', admins=admins)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        submitted_username = request.form['username']
        submitted_password = request.form['password']

        # Look up the user in the MongoDB 'users' collection
        user = db.users.find_one({"username": submitted_username})

        if user and check_password_hash(user['password_hash'], submitted_password):
            user_obj = User(id=user['_id'], username=user['username'], role=user['role'])
            login_user(user_obj)
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.')
            return redirect(url_for('login'))

    return render_template('auth/login.html')


# ------------------------------ ADMIN -------------------------------------------------




@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # 1. Security Check: Kick them out if they aren't an admin!
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    # 2. Get Dashboard Stats using MongoDB commands!
    # Count how many total modules exist
    module_count = db.modules.count_documents({})
    
    # Count how many students are registered (this is much cleaner than SQL!)
    student_count = db.users.count_documents({"role": "student"})
    
    # Grab all the modules to display in the table
    modules = list(db.modules.find())

    # 3. Send the data to the HTML template
    return render_template('admin/dashboard.html', 
                           modules=modules, 
                           module_count=module_count, 
                           student_count=student_count)

@app.route('/admin/add_lesson', methods=['POST'])
@login_required
def add_lesson():
    # Security check!
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    lesson_code = request.form.get('lesson_code')
    title = request.form.get('title')
    
    # NEW 1: Grab the formatted text from the TinyMCE editor
    content = request.form.get('content')
    
    # Grab the FILE instead of a text URL
    video_file = request.files.get('video_file')

    # NEW 2: Add "content" to the data we are going to save to MongoDB
    update_data = {
        "title": title,
        "content": content
    }

    # If the admin actually selected a file...
    if video_file and video_file.filename != '':
        # 1. Clean the filename (removes spaces and weird characters)
        filename = secure_filename(video_file.filename)
        
        # 2. Save the physical MP4 file to your computer's static folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        video_file.save(file_path)
        
        # 3. Add the web-friendly path to our MongoDB update data
        update_data["video_url"] = f"/static/uploads/videos/{filename}"

    # UPSERT: Update the lesson if it exists, or create it if it doesn't
    db.modules.update_one(
        {"lesson_code": lesson_code},
        {"$set": update_data},
        upsert=True
    )
    
    flash(f'Successfully uploaded video and text for {title}!')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_lesson/<lesson_code>', methods=['POST'])
@login_required
def delete_lesson(lesson_code):
    # 1. Security Check
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    # 2. Find the lesson to see if there is an MP4 file we need to trash
    lesson = db.modules.find_one({"lesson_code": lesson_code})
    
    if lesson and lesson.get('video_url'):
        # Extract just the filename (e.g., "intro.mp4") from the URL
        filename = lesson['video_url'].split('/')[-1]
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Safely delete the physical file from the computer
        if os.path.exists(file_path):
            os.remove(file_path)

    # 3. Delete the text record from MongoDB
    db.modules.delete_one({"lesson_code": lesson_code})
    
    flash(f'Lesson {lesson_code} has been completely deleted.')
    return redirect(url_for('admin_dashboard'))

#---------------------------------------TEMPLATES--------------------------------------------

@app.route('/')
def home():
    # If the user is NOT logged in, kick them straight to the registration page!
    if not current_user.is_authenticated:
        return redirect(url_for('register'))
    
    # If they are logged in, show them the homepage
    return render_template('index.html')

@app.route('/module/<int:module_num>/lesson/<int:lesson_num>')
def view_lesson(module_num, lesson_num):
    # Dynamically build the lesson code (e.g., "module1_lesson2")
    target_code = f"module{module_num}_lesson{lesson_num}"

    current_lesson = db.modules.find_one({"lesson_code": target_code})


    file_map = {
        "module1_lesson1": "01_plaintext_vs_cyphertext.html",
        "module1_lesson2": "01_substitution.html",

        "module2_lesson1": "02_shared_key.html",
        "module2_lesson2": "02_aes_standard.html",
        "module2_lesson3": "02_key_distribution.html",

        "module3_lesson1": "03_secure_distribution.html",
        "module3_lesson2": "03_Middle.html",
        "module3_lesson3": "03_deffie.html"
    }
    
    filename = file_map.get(target_code)
    template_path = f"topics/module{module_num}/{filename}"
    
    return render_template(template_path, lesson_data=current_lesson)

#----------------Lesson 1--------------------------------

@app.route('/module1/intro')
def module1_intro():
    return render_template('topics/module1/01_intro.html')
    
@app.route('/module1/lesson1')
def module1_lesson1():
    return render_template('topics/module1/01_plaintext_vs_cyphertext.html')

@app.route('/module1/lesson2')
def module1_lesson2():
    return render_template('topics/module1/01_substitution.html')

#----------------Lesson 2--------------------------

@app.route('/module2/intro')
def module2_intro():
    return render_template('topics/module2/02_intro.html')

@app.route('/module2/lesson1')
def module2_lesson1():
    return render_template('topics/module2/02_shared_key.html')

@app.route('/module2/lesson2')
def module2_lesson2():
    return render_template('topics/module2/02_aes_standard.html')

@app.route('/module2/lesson3')
def module2_lesson3():
    return render_template('topics/module2/02_key_distribution.html')
#-----------------Lesson 3-------------------------

@app.route('/module3/intro')
def module3_intro():
    return render_template('topics/module3/03_intro.html')

@app.route('/module3/lesson1')
def module3_lesson1():
    return render_template('topics/module3/03_secure_distribution.html')

@app.route('/module3/lesson2')
def module3_lesson2():
    return render_template('topics/module3/03_Middle.html')

@app.route('/module3/lesson3')
def module3_lesson3():
    return render_template('topics/module3/03_deffie.html')
#-----------------------MAIN------------------------------------
UPLOAD_FOLDER = 'static/uploads/videos'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if __name__ == '__main__':
    app.run(debug=True)