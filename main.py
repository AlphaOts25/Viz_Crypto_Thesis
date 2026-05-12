from flask import Flask, render_template, request, redirect, url_for, flash, session
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
from flask_mail import Mail, Message

app = Flask(__name__)
# IMPORTANT: In a real app, this should be a random string hidden in a .env file
app.secret_key = 'super_secret_thesis_key_change_this_later' 

load_dotenv()

#MONGO
client = MongoClient(os.getenv("MONGO_URI"))
db = client['fatvdb']

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

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

#----------OTP---------------------------------------------

@app.route('/verifyOTP', methods=['GET', 'POST'])
def verifyOTP():
    if request.method == 'POST':

        entered_otp = request.form.get('otp')

        print("Entered:", entered_otp)
        print("Stored:", session.get('otp'))

        if entered_otp == session.get('otp'):

            pending = session.get('pending_user')

            db.users.insert_one({
                "username": pending["username"],
                "email": pending["email"],
                "password_hash": generate_password_hash(pending["password"]),
                "role": "student",
                "quiz_scores": defaultdict(int),
                "total_score": 0,
                "professor_id": ObjectId(pending["professor_id"])
            })

            session.pop('otp', None)
            session.pop('pending_user', None)

            flash('Account created successfully!')
            return redirect(url_for('login'))

        else:
            flash('Invalid OTP')

    return render_template('auth/verifyOTP.html')
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

        otp = str(random.randint(100000, 999999))

        session['otp'] = otp

        session['pending_user'] = {
            "username": username,
            "email": email,
            "password": password,
            "professor_id": professor_id
        }

        msg = Message(
            'Your OTP Code',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f'Your OTP is: {otp}'

        mail.send(msg)

        return redirect(url_for('verifyOTP'))

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
        student_count=student_count,
        show_sidebar=False
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

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    students = list(db.users.find({"role": "student"}))

    for student in students:
        pre_result = db.results.find_one(
            {"user_id": student["_id"], "test_type": "pre"},
            sort=[("timestamp", -1)]
        )

        post_result = db.results.find_one(
            {"user_id": student["_id"], "test_type": "post"},
            sort=[("timestamp", -1)]
        )

        student["pre_score"] = pre_result["score"] if pre_result else "Not taken"
        student["pre_total"] = pre_result["total"] if pre_result else ""

        student["post_score"] = post_result["score"] if post_result else "Not taken"
        student["post_total"] = post_result["total"] if post_result else ""

    return render_template(
        "admin/users.html",
        students=students,
        show_sidebar=False
    )
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

@app.route('/submit_test', methods=['POST'])
@login_required
def submit_test():
    test_type = request.form.get('test_type')
    test = db.tests.find_one({"type": test_type})
    
    if not test:
        return redirect(url_for('home'))
    
    # Calculate score
    score = 0
    questions = list(db.questions.find({"test_id": test["_id"]}))
    
    for idx, question in enumerate(questions):
        user_answer = request.form.get(f'question_{idx}')
        if user_answer == question['correct_answer']:
            score += 1
    
    # Store result
    db.results.insert_one({
        "user_id": ObjectId(current_user.id),
        "test_type": test_type,
        "score": score,
        "total": len(questions),
        "timestamp": datetime.utcnow()
    })
    
    flash(f'Test submitted! Your score: {score}/{len(questions)}')
    return redirect(url_for('home'))


@app.route('/delete_test/<test_id>', methods=['POST'])
@login_required
def delete_test(test_id):

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    from bson.objectid import ObjectId

    db.tests.delete_one({"_id": ObjectId(test_id)})
    db.questions.delete_many({"test_id": ObjectId(test_id)})

    return redirect(url_for('admin_dashboard'))


def get_test(test_type):
    test = db.tests.find_one({"type": test_type})
    if not test:
        return []

    questions = list(db.questions.find({"test_id": test["_id"]}))
    random.shuffle(questions)

    return questions

@app.route('/test/<test_type>')
@login_required
def take_test(test_type):
    questions = get_test(test_type)
    return render_template('test.html', questions=questions, type=test_type, show_sidebar=True)

#---------------------------------------TEMPLATES--------------------------------------------

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('register'))

    pre_test_exists = db.tests.find_one({"type": "pre"}) is not None
    post_test_exists = db.tests.find_one({"type": "post"}) is not None

    return render_template(
        'index.html',
        pre_test_exists=pre_test_exists,
        post_test_exists=post_test_exists,
        show_sidebar=True
    )

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
    
    return render_template(template_path, lesson_data=current_lesson, show_sidebar=True)
    
@app.route('/module/<int:module_num>/intro')
def module_intro(module_num):
    intro_map = {
        1: "01_intro.html",
        2: "02_intro.html",
    }

    filename = intro_map.get(module_num)

    if not filename:
        return "Module not found", 404

    return render_template(f'topics/module{module_num}/{filename}', show_sidebar=True)

#-----------------------MAIN------------------------------------
UPLOAD_FOLDER = 'static/uploads/videos'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if __name__ == '__main__':
    app.run(debug=True)
