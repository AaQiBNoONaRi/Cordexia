import os
from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from flask_mail import Mail, Message
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER', 'sandbox.smtp.mailtrap.io'),
    MAIL_PORT=int(os.getenv('MAIL_PORT', 2525)),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True') == 'True',
    MAIL_USE_SSL=os.getenv('MAIL_USE_SSL', 'False') == 'False',
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com')
)

mail = Mail(app)

# Security configuration
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-fallback-key')

# Database setup
mongodb_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(mongodb_uri)
db = client['Cordexcia']
users_collection = db['users']

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/service-details')
def service():
    return render_template('service-details.html')

@app.route('/starter-page')
def starter():
    return render_template('starter-page.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_collection.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/signUp', methods=['GET', 'POST'])
def signUp():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if users_collection.find_one({'email': email}):
            flash('Email already registered!', 'danger')
            return redirect(url_for('signUp'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        users_collection.insert_one({
            'name': name,
            'email': email,
            'password': hashed_password
        })
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signUp.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        
        if email and not new_password:
            user = users_collection.find_one({'email': email})
            if user:
                session['reset_email'] = email
                verification_link = url_for('forgot_password', _external=True)
                send_verification_email(email, verification_link)
                flash('Email verified. Please set a new password.', 'success')
                return render_template('forgotPassword.html', show_reset_form=True)
            flash('Email not found.', 'danger')
        
        elif new_password:
            confirm_password = request.form.get('confirm_password')
            if new_password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('forgotPassword.html', show_reset_form=True)
            
            email = session.pop('reset_email', None)
            if email:
                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                users_collection.update_one(
                    {'email': email},
                    {'$set': {'password': hashed_password}}
                )
                flash('Password reset successful.', 'success')
                return redirect(url_for('login'))
            flash('Unauthorized access.', 'danger')
    
    return render_template('forgotPassword.html')

def send_verification_email(to_email, verification_link):
    msg = Message('Password Reset', recipients=[to_email])
    msg.body = f'Click to reset your password: {verification_link}'
    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Email error: {str(e)}")

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500