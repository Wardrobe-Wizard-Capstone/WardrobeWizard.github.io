from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import sqlite3
import bcrypt
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Initialize Flask-Login
login_manager = LoginManager(app)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'WardrobeWizard.reply@gmail.com'
app.config['MAIL_PASSWORD'] = 'tyva path goqn jxdq'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'  # Updated to a generic sender
mail = Mail(app)

# Connect to the SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('user_database.db', check_same_thread=False)
cursor = conn.cursor()

# Create the Users table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS Users (
        UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        Username TEXT NOT NULL,
        Email TEXT NOT NULL,
        PasswordHash TEXT NOT NULL,
        ResetToken TEXT,
        ResetTokenTimestamp TEXT
    )
''')
conn.commit()

print("Table 'Users' created successfully")

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

    def __str__(self):
        return self.username

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    cursor.execute('''
        SELECT UserID, Username FROM Users WHERE UserID = ?
    ''', (user_id,))
    user_data = cursor.fetchone()

    if user_data:
        user = User(user_data[0], user_data[1])
        return user
    return None

# Helper function to register a new user
def register_user(username, email, password):
    # Check if the email already exists
    cursor.execute('SELECT * FROM Users WHERE Email = ?', (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash('Email address is already associated with another account. Please use a different email.')
    else:
        # Generate a salt
        salt = bcrypt.gensalt()

        # Hash the password with the salt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Insert the user into the database
        cursor.execute('''
            INSERT INTO Users (Username, Email, PasswordHash)
            VALUES (?, ?, ?)
        ''', (username, email, password_hash))
        conn.commit()
        flash('Registration successful. You can now log in.')

        # Send registration email using the user's email as the sender
        msg = Message('Welcome to My App', recipients=[email])
        msg.body = 'Thank you for registering!'
        mail.send(msg)

# Helper function to send registration success email
def send_registration_email(email):
    msg = Message('Registration Successful', recipients=[email])
    msg.body = 'Thank you for registering with our service!'
    mail.send(msg)

# Helper function to check user credentials and perform login
def authenticate_user(username, password):
    cursor.execute('''
        SELECT UserID, PasswordHash FROM Users WHERE Username = ?
    ''', (username,))
    user_data = cursor.fetchone()

    if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[1]):
        user = User(user_data[0], user_data[1])
        login_user(user)
        return True
    return False

# Helper function to initiate password reset
def initiate_password_reset(username):
    reset_token = generate_reset_token()
    
    cursor.execute('''
        UPDATE Users
        SET ResetToken = ?, ResetTokenTimestamp = ?
        WHERE Username = ?
    ''', (reset_token, datetime.utcnow(), username))
    
    conn.commit()

# Helper function to send password reset email
def send_reset_email(username, reset_token, email):
    msg = Message('Password Reset Request', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', reset_token=reset_token, _external=True)}
    If you did not make this request then simply ignore this email and no changes will be made.
    '''
    mail.send(msg)
# Helper function to generate a reset token
def generate_reset_token():
    return secrets.token_urlsafe(32)

# Helper function to verify the reset token
def verify_reset_token(reset_token):
    cursor.execute('''
        SELECT * FROM Users WHERE ResetToken = ? AND ResetToken IS NOT NULL
    ''', (reset_token,))
    
    user_data = cursor.fetchone()
    
    if user_data:
        expiration_time = datetime.strptime(user_data[4], '%Y-%m-%d %H:%M:%S') + timedelta(seconds=3600)
        
        if datetime.utcnow() < expiration_time:
            return user_data
    
    return None

# Helper function to update the password after reset
def update_password(user_id, new_password):
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    
    cursor.execute('''
        UPDATE Users
        SET PasswordHash = ?, ResetToken = NULL, ResetTokenTimestamp = NULL
        WHERE UserID = ?
    ''', (password_hash, user_id))
    
    conn.commit()

@app.route('/reset_password/<reset_token>', methods=['GET', 'POST'])
def reset_password(reset_token):
    user = verify_reset_token(reset_token)
    
    if not user:
        flash('Invalid or expired reset token. Please try again.')
        return redirect(url_for('login_route'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            update_password(user[0], new_password)
            flash('Password reset successfully. You can now log in with your new password.')
            return redirect(url_for('login_route'))
        else:
            flash('Passwords do not match. Please try again.')
    
    return render_template('reset_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']

        cursor.execute('SELECT * FROM Users WHERE Username = ?', (username,))
        user_data = cursor.fetchone()

        if user_data:
            email = user_data[2]  # Assuming email is at index 2
            initiate_password_reset(username)
            flash('Password reset initiated. Check your email for instructions.')
            send_reset_email(username, user_data[4], email)
        else:
            flash('User not found. Please check your username.')

    return render_template('forgot_password.html')

# Example login route
@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_user(username, password):
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

# Example logout route
@app.route('/logout')
@login_required
def logout_route():
    logout_user()
    return redirect(url_for('home'))

# Example route requiring login
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Example route for the home page
@app.route('/')
def home():
    return render_template('index.html')

# Example route for the registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the username already exists
        cursor.execute('SELECT * FROM Users WHERE Username = ?', (username,))
        if cursor.fetchone():
            flash('Username already exists. Choose a different one.')
        else:
            register_user(username, email, password)

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)
