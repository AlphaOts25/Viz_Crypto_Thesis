from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from bson.objectid import ObjectId
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import random, math
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("APP_SECRET_KEY is missing from .env")

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

#--------------------------------------cache blocker---------------------------------------
@app.after_request
def prevent_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.before_request
def refresh_session():
    session.permanent = True
    session.modified = True
#-------------------------------------------------------------------------

#MONGO
client = MongoClient(os.getenv("MONGO_URI"))
db = client['fatvdb']

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
app.config['SERIALIZER_SECRET_KEY'] = os.getenv("SERIALIZER_SECRET_KEY")
serializer = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])

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
                "professor_id": ObjectId(pending["professor_id"])
            })

            session.pop('otp', None)
            session.pop('pending_user', None)

            flash('Account created successfully!')
            return redirect(url_for('login'))

        else:
            flash('Invalid OTP')

    return render_template(
        'auth/verifyOTP.html',
        show_navbar=False,
        show_sidebar=False
    )
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
    return render_template(
        'auth/register.html',
        admins=admins,
        show_navbar=False,
        show_sidebar=False
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('home'))

    if request.method == 'POST':
        submitted_username = request.form['username']
        submitted_password = request.form['password']

        user = db.users.find_one({"username": submitted_username})

        if user and check_password_hash(user['password_hash'], submitted_password):
            user_obj = User(id=user['_id'], username=user['username'], role=user['role'])
            login_user(user_obj)
            session.permanent = True

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return render_template(
        'auth/login.html',
        show_navbar=False,
        show_sidebar=False
    )

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form.get('email')

        user = db.users.find_one({"email": email})

        if user:
            token = serializer.dumps(email, salt='password-reset-salt')

            reset_link = url_for(
                'resetpassword',
                token=token,
                _external=True
            )

            msg = Message(
                'Password Reset Request',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )

            msg.body = f"""
You requested to reset your password.

Click this link to reset it:
{reset_link}

This link will expire in 30 minutes.
"""

            mail.send(msg)

        flash('If the email exists, a password reset link has been sent.')
        return redirect(url_for('forgotpassword'))

    return render_template(
        'auth/forgotpassword.html',
        show_navbar=False,
        show_sidebar=False
    )

@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def resetpassword(token):
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=1800
        )
    except:
        flash('The reset link is invalid or expired.')
        return redirect(url_for('forgotpassword'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('resetpassword', token=token))

        db.users.update_one(
            {"email": email},
            {
                "$set": {
                    "password_hash": generate_password_hash(password)
                }
            }
        )

        flash('Password updated successfully. You can now log in.')
        return redirect(url_for('login'))

    return render_template(
        'auth/resetpassword.html',
        show_navbar=False,
        show_sidebar=False
    )
# ------------------------------ ADMIN ------------------------------

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    module_count = db.modules.count_documents({})
    student_count = db.users.count_documents({"role": "student"})

    tests = list(db.tests.find())

    for test in tests:
        test["display_type"] = "Pre-test" if test["type"] == "pre" else "Post-test"
        test["title"] = test["display_type"]
        test["id"] = str(test["_id"])

        questions = list(db.questions.find({"test_id": test["_id"]}))

        test["questions"] = []
        for q in questions:
            test["questions"].append({
                "text": q.get("question_text", ""),
                "a": q.get("choices", {}).get("a", ""),
                "b": q.get("choices", {}).get("b", ""),
                "c": q.get("choices", {}).get("c", ""),
                "d": q.get("choices", {}).get("d", ""),
                "correct": q.get("correct_answer", "")
            })

    curriculum = tests

    return render_template(
        'admin/dashboard.html',
        modules=curriculum,
        module_count=module_count,
        student_count=student_count,
        show_sidebar=False
    )

def calculate_test_statistics():
    students = list(db.users.find({"role": "student"}))
    paired_scores = []

    for student in students:
        pre = db.results.find_one(
            {"user_id": student["_id"], "test_type": "pre"},
            sort=[("timestamp", -1)]
        )

        post = db.results.find_one(
            {"user_id": student["_id"], "test_type": "post"},
            sort=[("timestamp", -1)]
        )

        if pre and post:
            paired_scores.append({
                "pre": pre["score"],
                "post": post["score"]
            })

    n = len(paired_scores)

    if n == 0:
        return {
            "mean_pre": 0,
            "mean_post": 0,
            "mean_gain": 0,
            "t_value": "N/A",
            "effect_size": "N/A",
            "effect_label": "N/A"
        }

    pre_scores = [s["pre"] for s in paired_scores]
    post_scores = [s["post"] for s in paired_scores]
    gains = [s["post"] - s["pre"] for s in paired_scores]

    mean_pre = sum(pre_scores) / n
    mean_post = sum(post_scores) / n
    mean_gain = sum(gains) / n

    if n < 2:
        t_value = "N/A"
        effect_size = "N/A"
        effect_label = "N/A"
    else:
        variance = sum((g - mean_gain) ** 2 for g in gains) / (n - 1)
        sd_gain = math.sqrt(variance)

        if sd_gain == 0:
            t_value = "N/A"
            effect_size = "N/A"
            effect_label = "N/A"
        else:
            t_value = mean_gain / (sd_gain / math.sqrt(n))
            effect_size = mean_gain / sd_gain

            abs_effect = abs(effect_size)

            if abs_effect < 0.2:
                effect_label = "Very small"
            elif abs_effect < 0.5:
                effect_label = "Small"
            elif abs_effect < 0.8:
                effect_label = "Moderate"
            else:
                effect_label = "Large"

    return {
        "mean_pre": round(mean_pre, 2),
        "mean_post": round(mean_post, 2),
        "mean_gain": round(mean_gain, 2),
        "t_value": round(t_value, 3) if isinstance(t_value, float) else t_value,
        "effect_size": round(effect_size, 3) if isinstance(effect_size, float) else effect_size,
        "effect_label": effect_label
    }


def calculate_question_statistics():
    stats = []

    tests = list(db.tests.find().sort("_id", 1))

    for test in tests:
        questions = list(db.questions.find({"test_id": test["_id"]}).sort("_id", 1))

        for index, question in enumerate(questions, start=1):
            correct_count = 0
            wrong_count = 0

            results = list(db.results.find({"test_type": test["type"]}))

            for result in results:
                for answer in result.get("answers", []):
                    if answer.get("question_id") == question["_id"]:
                        if answer.get("is_correct"):
                            correct_count += 1
                        else:
                            wrong_count += 1

            total = correct_count + wrong_count

            stats.append({
                "test_type": "Pre-test" if test["type"] == "pre" else "Post-test",
                "number": index,
                "question_text": question.get("question_text", ""),
                "correct_count": correct_count,
                "wrong_count": wrong_count,
                "correct_percentage": round((correct_count / total) * 100, 2) if total > 0 else 0,
                "wrong_percentage": round((wrong_count / total) * 100, 2) if total > 0 else 0
            })

    return stats

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
        student["pre_result_id"] = str(pre_result["_id"]) if pre_result else None

        student["post_score"] = post_result["score"] if post_result else "Not taken"
        student["post_total"] = post_result["total"] if post_result else ""
        student["post_result_id"] = str(post_result["_id"]) if post_result else None

    test_stats = calculate_test_statistics()
    question_stats = calculate_question_statistics()

    return render_template(
        "admin/users.html",
        students=students,
        test_stats=test_stats,
        question_stats=question_stats,
        show_sidebar=False
    )

@app.route('/admin/delete_result/<result_id>', methods=['POST'])
@login_required
def delete_result(result_id):
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    result = db.results.delete_one({"_id": ObjectId(result_id)})

    print("Deleting result_id:", result_id)
    print("Deleted count:", result.deleted_count)

    flash("Result deleted." if result.deleted_count == 1 else "Result not found.")

    return redirect(url_for('admin_users'))
# ------------------------------ TESTS ------------------------------

def create_test(test_type):
    test = {
        "type": test_type,   # "pre" or "post"
        "title": f"{test_type.capitalize()} Test",
        "created_at": datetime.now(timezone.utc)
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

@app.route('/edit_test/<test_id>', methods=['POST'])
@login_required
def edit_test(test_id):

    if current_user.role != 'admin':
        return redirect(url_for('home'))

    test_object_id = ObjectId(test_id)
    test_type = request.form.get("type")

    db.tests.update_one(
        {"_id": test_object_id},
        {"$set": {"type": test_type}}
    )

    db.questions.delete_many({"test_id": test_object_id})

    grouped = defaultdict(dict)

    for key, value in request.form.items():
        if key.startswith("questions"):
            parts = key.replace("]", "").split("[")
            grouped[parts[1]][parts[2]] = value

    for q in grouped.values():
        db.questions.insert_one({
            "test_id": test_object_id,
            "question_text": q.get("text"),
            "choices": {
                "a": q.get("a"),
                "b": q.get("b"),
                "c": q.get("c"),
                "d": q.get("d")
            },
            "correct_answer": q.get("correct")
        })

    flash("Test updated successfully.")
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
    answers = []

    questions = list(db.questions.find({"test_id": test["_id"]}))

    for idx, question in enumerate(questions):
        user_answer = request.form.get(f'question_{idx}')
        is_correct = user_answer == question['correct_answer']

        if is_correct:
            score += 1

        answers.append({
            "question_id": question["_id"],
            "user_answer": user_answer,
            "correct_answer": question["correct_answer"],
            "is_correct": is_correct
        })

    db.results.insert_one({
        "user_id": ObjectId(current_user.id),
        "test_type": test_type,
        "score": score,
        "total": len(questions),
        "answers": answers,
        "timestamp": datetime.now(timezone.utc)
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
    pre_taken, post_taken, modules_unlocked, post_unlocked = get_student_progress()

    if test_type == "post" and not post_unlocked:
        flash("You must finish all modules before taking the post-test.")
        return redirect(url_for('home'))

    questions = get_test(test_type)

    return render_template(
        'test.html',
        questions=questions,
        type=test_type,
        show_sidebar=False
    )

@app.route('/achievement')
@login_required
def achievement():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))

    user_id = ObjectId(current_user.id)

    pre_result = db.results.find_one(
        {"user_id": user_id, "test_type": "pre"},
        sort=[("timestamp", -1)]
    )

    post_result = db.results.find_one(
        {"user_id": user_id, "test_type": "post"},
        sort=[("timestamp", -1)]
    )

    post_taken = post_result is not None

    return render_template(
        "user/achievement.html",
        pre_result=pre_result,
        post_result=post_result,
        post_taken=post_taken,
        show_sidebar=False
    )
#---------------------------------------TEMPLATES--------------------------------------------
def get_student_progress():
    user_id = ObjectId(current_user.id)

    pre_taken = db.results.find_one({
        "user_id": user_id,
        "test_type": "pre"
    }) is not None

    post_taken = db.results.find_one({
        "user_id": user_id,
        "test_type": "post"
    }) is not None

    completed_lessons = db.module_progress.count_documents({
        "user_id": user_id
    })

    total_lessons = 5

    modules_unlocked = pre_taken
    post_unlocked = completed_lessons >= total_lessons

    return pre_taken, post_taken, modules_unlocked, post_unlocked

@app.route('/')
@login_required
def home():
    pre_test_exists = db.tests.find_one({"type": "pre"}) is not None
    post_test_exists = db.tests.find_one({"type": "post"}) is not None

    pre_taken, post_taken, modules_unlocked, post_unlocked = get_student_progress()

    return render_template(
        'user/dashboard.html',
        pre_test_exists=pre_test_exists,
        post_test_exists=post_test_exists,
        pre_taken=pre_taken,
        post_taken=post_taken,
        modules_unlocked=modules_unlocked,
        post_unlocked=post_unlocked,
        show_sidebar=False
    )

@app.route('/module/<int:module_num>/lesson/<int:lesson_num>')
@login_required
def view_lesson(module_num, lesson_num):
    pre_taken, post_taken, modules_unlocked, post_unlocked = get_student_progress()

    if not modules_unlocked:
        flash("You must answer the pre-test first.")
        return redirect(url_for('home'))

    target_code = f"module{module_num}_lesson{lesson_num}"

    db.module_progress.update_one(
        {
            "user_id": ObjectId(current_user.id),
            "lesson_code": target_code
        },
        {
            "$set": {
                "user_id": ObjectId(current_user.id),
                "lesson_code": target_code,
                "completed_at": datetime.now(timezone.utc)
            }
        },
        upsert=True
    )

    current_lesson = db.modules.find_one({"lesson_code": target_code})

    file_map = {
        "module1_lesson1": "01_plaintext_vs_cyphertext.html",
        "module1_lesson2": "01_substitution.html",
        "module2_lesson1": "02_shared_key.html",
        "module2_lesson2": "02_key_distribution.html",
        "module2_lesson3": "02_deffie.html"
    }

    filename = file_map.get(target_code)

    if not filename:
        return "Lesson not found", 404

    template_path = f"topics/module{module_num}/{filename}"

    return render_template(
        template_path,
        lesson_data=current_lesson,
        show_sidebar=True,
        pre_test_exists=db.tests.find_one({"type": "pre"}) is not None,
        post_test_exists=db.tests.find_one({"type": "post"}) is not None
    )
    
@app.route('/module/<int:module_num>/intro')
@login_required
def module_intro(module_num):
    pre_taken, post_taken, modules_unlocked, post_unlocked = get_student_progress()

    if not modules_unlocked:
        flash("You must answer the pre-test first.")
        return redirect(url_for('home'))

    intro_map = {
        1: "01_intro.html",
        2: "02_intro.html",
    }

    filename = intro_map.get(module_num)

    if not filename:
        return "Module not found", 404

    return render_template(
        f'topics/module{module_num}/{filename}',
        show_sidebar=True,
        pre_test_exists=db.tests.find_one({"type": "pre"}) is not None,
        post_test_exists=db.tests.find_one({"type": "post"}) is not None
    )

#-----------------------MAIN------------------------------------
UPLOAD_FOLDER = 'static/uploads/videos'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
