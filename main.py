from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
import sqlite3

app = Flask(__name__)
# IMPORTANT: In a real app, this should be a random string hidden in a .env file
app.secret_key = 'super_secret_thesis_key_change_this_later' 

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
        self.id = id
        self.username = username
        self.role = role

# This tells Flask how to find a user in the DB based on their session ID
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], role=user_data['role'])
    return None

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user clicked the 'Log In' button
    if request.method == 'POST':
        # Notice how these match the 'name' attributes in your HTML exactly:
        submitted_username = request.form['username']
        submitted_password = request.form['password']
        
        # 1. Connect to the database
        conn = get_db_connection() # Assuming you have this helper function from earlier
        
        # 2. Look for the user by their username
        user = conn.execute('SELECT * FROM users WHERE username = ?', (submitted_username,)).fetchone()
        conn.close()
        
        # 3. Check if user exists AND if the password matches the hash
        if user and check_password_hash(user['password_hash'], submitted_password):
            
            # (If you are using Flask-Login, you would call login_user() here)

            user_obj = User(id=user['id'], username=user['username'], role=user['role'])
            login_user(user_obj)
            
            # Check their role to decide where to send them
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
                
        else:
            # This triggers the error message block in your HTML!
            flash('Invalid username or password. Please try again.')
            return redirect(url_for('login'))

    # If they just navigated to the page, show them the blank HTML form
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # 1. Security Check: Kick them out if they aren't an admin!
    if current_user.role != 'admin':
        return redirect(url_for('home'))

    # 2. Connect to the database
    conn = get_db_connection()
    
    # 3. Get Dashboard Stats
    # Count how many total modules exist
    module_count = conn.execute('SELECT COUNT(*) FROM modules').fetchone()[0]
    # Count how many students are registered
    student_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'student'").fetchone()[0]
    
    # 4. Grab all the modules to display in the table
    modules = conn.execute('SELECT * FROM modules').fetchall()
    
    conn.close()

    # 5. Send the data to the HTML template
    return render_template('admin/dashboard.html', 
                           modules=modules, 
                           module_count=module_count, 
                           student_count=student_count)

#TEMPLATES--------------------------------------------

@app.route('/module1/intro')
def module1_intro():
    return render_template('topics/01_intro.html')

@app.route('/module2/intro')
def module2_intro():
    return render_template('topics/02_intro.html')

@app.route('/module3/intro')
def module3_intro():
    return render_template('topics/03_intro.html')



if __name__ == '__main__':
    app.run(debug=True)