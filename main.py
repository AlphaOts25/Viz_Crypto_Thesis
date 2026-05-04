from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash    
from bson.objectid import ObjectId
from pymongo import MongoClient
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import random
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)
# IMPORTANT: In a real app, this should be a random string hidden in a .env file
app.secret_key = 'super_secret_thesis_key_change_this_later' 

load_dotenv()

#MONGO
client = MongoClient(os.getenv("MONGO_URI"))
db = client['fatvdb']

# --- Setup Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Tells Flask where to send users who aren't logged in

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

"""
@app.route('/create_admin')
def create_admin():
    admin_user = {
        "username": "admin",
        "email": "admin@example.com",
        "password_hash": generate_password_hash("admin"),
        "role": "admin"
    }

    result = db.users.insert_one(admin_user)
    print(result.inserted_id)

    return "Admin created"
"""

#----------LOGIN----------------------------------------------
# ---------- LOGIN ----------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        professor_id = request.form.get('professor_id')

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('register'))

        existing_user = db.users.find_one({
            "$or": [{"username": username}, {"email": email}]
        })
        
        if existing_user:
            flash('Username or Email already exists.')
            return redirect(url_for('register'))

        new_student = {
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": "student",
            "quiz_scores": defaultdict(int),
            "total_score": 0,
            "professor_id": ObjectId(professor_id) 
        }

        db.users.insert_one(new_student)
        flash('Account created successfully!')
        return redirect(url_for('login'))

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

        user = db.users.find_one({"username": submitted_username})

        if user and check_password_hash(user['password_hash'], submitted_password):
            user_obj = User(id=user['_id'], username=user['username'], role=user['role'])
            login_user(user_obj)
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return render_template('auth/login.html')


# ------------------------------ ADMIN ------------------------------

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    module_count = db.modules.count_documents({})
    student_count = db.users.count_documents({"role": "student"})

    modules = list(db.modules.find())
    tests = list(db.tests.find())

    for m in modules:
        m["type"] = "lesson"

    for t in tests:
        t["type"] = "test"
        t["lesson_code"] = f"{t['type'].upper()}_TEST"
        t["title"] = f"{t['type'].capitalize()} Test"
        t["video_url"] = None

    curriculum = modules + tests

    return render_template(
        'admin/dashboard.html',
        modules=curriculum,
        module_count=module_count,
        student_count=student_count
    )


@app.route('/admin/add_lesson', methods=['POST'])
@login_required
def add_lesson():

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    lesson_code = request.form.get('lesson_code')
    title = request.form.get('title')
    content = request.form.get('content')
    video_file = request.files.get('video_file')

    update_data = {
        "title": title,
        "content": content
    }

    if video_file and video_file.filename != '':
        filename = secure_filename(video_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        video_file.save(file_path)
        update_data["video_url"] = f"/static/uploads/videos/{filename}"

    db.modules.update_one(
        {"lesson_code": lesson_code},
        {"$set": update_data},
        upsert=True
    )
    
    flash(f'Successfully uploaded video for {title}!')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_lesson/<lesson_code>', methods=['POST'])
@login_required
def delete_lesson(lesson_code):

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    lesson = db.modules.find_one({"lesson_code": lesson_code})

    if lesson and lesson.get('video_url'):
        filename = lesson['video_url'].split('/')[-1]
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if os.path.exists(file_path):
            os.remove(file_path)

    db.modules.delete_one({"lesson_code": lesson_code})

    return redirect(url_for('admin_dashboard'))


# ------------------------------ TESTS ------------------------------

def create_test(test_type):
    test = {
        "type": test_type,   # "pre" or "post"
        "title": f"{test_type.capitalize()} Test",
        "created_at": datetime.utcnow()
    }

    result = db.tests.insert_one(test)
    return result.inserted_id

@app.route('/add_test', methods=['POST'])
@login_required
def add_test():

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    test_type = request.form.get("type")

    test_id = db.tests.insert_one({
        "type": test_type
    }).inserted_id

    grouped = defaultdict(dict)

    for key, value in request.form.items():
        if key.startswith("questions"):
            parts = key.replace("]", "").split("[")
            grouped[parts[1]][parts[2]] = value

    for q in grouped.values():
        db.questions.insert_one({
            "test_id": test_id,
            "question_text": q.get("text"),
            "choices": {
                "a": q.get("a"),
                "b": q.get("b"),
                "c": q.get("c"),
                "d": q.get("d")
            },
            "correct_answer": q.get("correct")
        })

    return redirect(url_for('admin_dashboard'))


@app.route('/delete_test/<test_id>', methods=['POST'])
@login_required
def delete_test(test_id):

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    db.tests.delete_one({"_id": ObjectId(test_id)})
    db.questions.delete_many({"test_id": ObjectId(test_id)})

    return redirect(url_for('admin_dashboard'))


def get_test(test_type):
    test = db.tests.find_one({"type": test_type})
    if not test:
        return []

    questions = list(db.questions.find({"test_id": test["_id"]}))
    random.shuffle(questions)

    for q in questions:
        items = list(q["choices"].items())
        random.shuffle(items)

        new_choices = {}
        correct = q["correct_answer"]

        for i, (k, v) in enumerate(items):
            new_key = ["a","b","c","d"][i]
            new_choices[new_key] = v
            if k == correct:
                q["correct_answer"] = new_key

        q["choices"] = new_choices

    return questions

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
        "module2_lesson2": "02_key_distribution.html",
        "module2_lesson3": "02_deffie.html"
    }
    
    filename = file_map.get(target_code)
    template_path = f"topics/module{module_num}/{filename}"
    
    return render_template(template_path, lesson_data=current_lesson)
    
@app.route('/module/<int:module_num>/intro')
def module_intro(module_num):
    intro_map = {
        1: "01_intro.html",
        2: "02_intro.html",
    }

    filename = intro_map.get(module_num)

    if not filename:
        return "Module not found", 404

    return render_template(f'topics/module{module_num}/{filename}')

#-----------------------MAIN------------------------------------
UPLOAD_FOLDER = 'static/uploads/videos'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if __name__ == '__main__':
    app.run(debug=True)