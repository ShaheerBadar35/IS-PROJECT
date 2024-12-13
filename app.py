from flask import Flask, render_template, request, redirect, url_for, flash, session
from logging.handlers import RotatingFileHandler
import hashlib
import sqlite3
import logging
import os
import datetime
import datetime
from flask import request
from flask_mail import Mail, Message
import random
import string

app = Flask(__name__)
app.secret_key = 'your_secret_key'

#--------Setting Up mail for MFA in Flask----------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'maryamshahid314@gmail.com'  
app.config['MAIL_PASSWORD'] = 'W@termelon614'  
app.config['MAIL_DEFAULT_SENDER'] = 'maryamshahid314@gmail.com'  

mail = Mail(app)

DATABASE = 'ride_sharing.db'

#-------------Database connection------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

#-------------Database creation------------
def init_db():
    conn = get_db_connection()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT CHECK(role IN ('passenger', 'driver')) NOT NULL,
                Sign_MD5 TEXT,
                contact TEXT UNIQUE,
                license TEXT UNIQUE
            );
            
            CREATE TABLE IF NOT EXISTS ride_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                passenger_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                driver_id INTEGER,
                FOREIGN KEY (passenger_id) REFERENCES users (id),
                FOREIGN KEY (driver_id) REFERENCES users (id)
            );
        """)
    conn.close()

#--------------For logging User Login Details-------------
logs_dir = 'logs'
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(os.path.join(logs_dir, 'server.txt'), maxBytes=1000000, backupCount=1)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.DEBUG)
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.DEBUG) 

def log_user_login(email, user_type):
    try:
        log_text = f"Logged in: {email}, Type: {user_type}, Connection: {request.remote_addr}, Time: {datetime.datetime.now()}\n"
        app.logger.info(log_text)
    except Exception as e:
        app.logger.error(f"Logging Error!: {e}")

#--------------Password Hashing and Signature creation--------------
def cal_md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

#-------------OTP in mail for multi-factor authentication------------
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp(email, otp):
    try:
        msg = Message("Your OTP for Login", recipients=[email])
        msg.body = f"Your one-time password (OTP) is: {otp}"
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"Failed to send OTP: {e}")

#-----------------Routing to Different Screens----------------
@app.route('/')
def index():
    return render_template('base.html')

#----------------------User Registration-------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        contact = request.form.get('contact')
        license_number = request.form.get('license')

        #--------hashing pw, driver license and creating signatures--------
        conn = get_db_connection()
        try:
            mail_prefix = email.split('@')[0]
            hashed_password = cal_md5_hash(password)
            Signature_md5 = cal_md5_hash(mail_prefix + password + role)
            
            license_hash = cal_md5_hash(license_number) if license_number else None
            
            with conn:
                conn.execute(
                    "INSERT INTO users (name, email, password, role, Sign_MD5, contact, license) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, email, hashed_password, role, Signature_md5, contact, license_hash)
                )
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Either Email, Contact, Drivers License already registered!', 'error')
        finally:
            conn.close()
    return render_template('register.html', centered=True)

#--------------------User Login----------------
failed_attempts = {}
user_otps = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email not in failed_attempts:
            failed_attempts[email] = 0

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        #--------authenticating users through stored signatues---------
        if user:
            if user['password'] == cal_md5_hash(password):  
                mail_prefix = email.split('@')[0]
                generated_signature = cal_md5_hash(mail_prefix + password + user['role'])

                if generated_signature == user['Sign_MD5']:  
                    
                    failed_attempts[email] = 0

                    session['user_id'] = user['id']
                    session['role'] = user['role']
                    flash('Login successful!', 'success')

                    log_user_login(email, user['role'])

                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid signature!', 'error')
            else:
                flash('Invalid credentials!', 'error')
        else:
            flash('User not found!', 'error')

        failed_attempts[email] += 1

        #----------if login failed attempts > 3---------------
        if failed_attempts[email] >= 3:
            otp = generate_otp()
            user_otps[email] = otp  
            print("OTP--------",otp)
            send_otp(email, otp)   
            flash('Too many failed attempts. OTP has been sent to your email.', 'error')
            return redirect(url_for('verify_otp', email=email))

    return render_template('login.html', centered=True)

#---------------OTP Verification-------------------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')

    if request.method == 'POST':
        otp = request.form['otp']

        if email in user_otps and user_otps[email] == otp:
            
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            conn.close()

            if user:
                session['user_id'] = user['id']
                session['role'] = user['role']

            del user_otps[email]  
            failed_attempts[email] = 0  

            flash('OTP verified successfully! You are now logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP!', 'error')

    return render_template('verify_otp.html', email=email, centered=True)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] == 'passenger':
        return redirect(url_for('passenger_dashboard'))
    elif session['role'] == 'driver':
        return redirect(url_for('driver_dashboard'))

#--------------------Passenger dashboard---------------------
@app.route('/passenger', methods=['GET', 'POST'])
def passenger_dashboard():
    if 'user_id' not in session or session['role'] != 'passenger':
        return redirect(url_for('login'))

    conn = get_db_connection()

    if request.method == 'POST':
        source = request.form['source']
        destination = request.form['destination']
        conn.execute(
            "INSERT INTO ride_requests (passenger_id, source, destination) VALUES (?, ?, ?)",
            (session['user_id'], source, destination)
        )
        conn.commit()
        flash('Ride request posted!', 'success')

    ride_requests = conn.execute(
        "SELECT * FROM ride_requests WHERE passenger_id = ? AND status = 'active'", 
        (session['user_id'],)
    ).fetchall()

    accepted_rides = conn.execute(
        "SELECT r.*, d.name as driver_name, d.contact as driver_contact, d.license as driver_license "
        "FROM ride_requests r JOIN users d ON r.driver_id = d.id "
        "WHERE r.passenger_id = ? AND r.status = 'booked'",
        (session['user_id'],)
    ).fetchall()
    
    conn.close()

    return render_template('passenger.html', ride_requests=ride_requests, accepted_rides=accepted_rides, centered=False)

#-------------------Driver dashboard to view and accept request rides------------
@app.route('/driver', methods=['GET', 'POST'])
def driver_dashboard():
    if 'user_id' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    conn = get_db_connection()
    ride_requests = conn.execute(
        "SELECT r.*, r.passenger_id FROM ride_requests r WHERE r.status = 'active'"
    ).fetchall()
    conn.close()

    return render_template('driver.html', ride_requests=ride_requests, centered=False)
 
#----------------ZKP Driver License Verification Implementation from Research Paper-------------
@app.route('/verify_license/<int:ride_id>', methods=['GET', 'POST'])
def verify_license(ride_id):
    if 'user_id' not in session or session['role'] != 'driver':
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT license FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()

    if request.method == 'POST':
        license_number = request.form['license']

        hashed_license = cal_md5_hash(license_number)
        if hashed_license == user['license']:
           
            conn = get_db_connection()
            conn.execute(
                "UPDATE ride_requests SET status = 'booked', driver_id = ? WHERE id = ?",
                (session['user_id'], ride_id)
            )
            conn.commit()
            conn.close()

            flash('Ride request accepted successfully!', 'success')
            return redirect(url_for('driver_dashboard'))
        else:
            flash('License verification failed! Ride request not accepted.', 'error')

    return render_template('verify_license.html', ride_id=ride_id, centered=True)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

#--------------main to run the flask app------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)

