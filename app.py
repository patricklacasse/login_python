from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
from functools import wraps
import secrets
from flask_mail import Mail, Message
import uuid
import os

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'youremail@gmail.com'
app.config['MAIL_PASSWORD'] = 'password'
mail = Mail(app)
app.secret_key = '24db90b0a2ad429ea2bf5f204285b15b'


def generate_salt():
    return secrets.token_hex(16)  

def hash_password(password, salt):
    salted_password = password + salt
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password

def get_db_connection():
    conn = sqlite3.connect('user.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        verification_token TEXT NOT NULL,
                        verified BOOLEAN NOT NULL
                    )''')
    conn.commit()
    cursor.close()
    return conn

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash('You need to log in first!', 'danger')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def generate_verification_token():
    token = uuid.uuid4().hex  
    return token

def send_verification_email(email, verification_token):
    verification_link = url_for('verify_email', token=verification_token, _external=True)
    msg = Message('Verify your email', sender='noreply-dbmaker@gmail.com', recipients=[email])
    msg.body = f'Click the following link to verify your email: {verification_link}'
    mail.send(msg)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/')
def landing():
    if 'logged_in' in session and session['logged_in']:
        user_email = session['username']
        user_email_prefix = user_email.split('@')[0]
        database_path = f"db/{user_email_prefix}.db"
    return render_template('landing.html', database_exists=False)




@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('main_menu'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (username,)).fetchone()
        conn.close()

        if user:
            stored_password_hash = user['password_hash']
            stored_salt = user['salt']
            hashed_password = hash_password(password, stored_salt)

            if stored_password_hash == hashed_password:
                session.modified = True
                session['logged_in'] = True
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('landing'))  
            else:
                flash('Invalid username or password', 'danger')
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        salt = generate_salt()  

        
        hashed_password = hash_password(password, salt)

        
        verification_token = generate_verification_token()  

        conn = get_db_connection()
        conn.execute('INSERT INTO users (email, password_hash, salt, verification_token, verified) VALUES (?, ?, ?, ?, ?)',
                     (email, hashed_password, salt, verification_token, False))
        conn.commit()
        conn.close()

        send_verification_email(email, verification_token)  

        flash('A verification email has been sent to your email address. Please verify your email to complete the registration.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE verification_token = ?', (token,)).fetchone()
    if user:
        conn.execute('UPDATE users SET verified = ? WHERE id = ?', (True, user['id']))
        conn.commit()
        conn.close()
        flash('Your email has been verified successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid verification token.', 'danger')
        return redirect(url_for('login'))

@app.route('/main_menu')
@require_login
def main_menu():
    return render_template('landing.html', username=session['username'])

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('landing'))
    

if __name__ == '__main__':
    app.run(debug=True)
