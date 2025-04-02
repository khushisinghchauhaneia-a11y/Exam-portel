# app.py
import base64
import random
import re
import uuid
from datetime import datetime, timedelta
from threading import Timer
from authlib.integrations.flask_client import OAuth
import os
import json
import secrets
import pandas as pd
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Markup
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Load configuration from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///exam.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
oauth = OAuth(app)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Google OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GOOGLE_DISCOVERY_URL'] = os.getenv('GOOGLE_DISCOVERY_URL',
                                               'https://accounts.google.com/.well-known/openid-configuration')

# Anti-cheating configurations
app.config['MAX_TAB_SWITCHES'] = int(os.getenv('MAX_TAB_SWITCHES', 3))
app.config['ENABLE_SCREENSHOTS'] = os.getenv('ENABLE_SCREENSHOTS', 'True') == 'True'
app.config['SCREENSHOT_INTERVAL'] = int(os.getenv('SCREENSHOT_INTERVAL', 60))
app.config['PROCTORING_FOLDER'] = 'static/proctoring'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Ensure upload folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCTORING_FOLDER'], exist_ok=True)

# Set up Google OAuth
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile'
    }
)


# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(20), nullable=True, default='male-1')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # New columns for password reset
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)

    # Student specific fields
    name = db.Column(db.String(100), nullable=True)
    stream = db.Column(db.String(100), nullable=True)
    contact = db.Column(db.String(20), nullable=True)
    exams = db.relationship('StudentExam', backref='student', lazy=True)

    # ... rest of the existing methods remain the same
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Add helper method to check if user is super admin
    def is_super_admin(self):
        return self.role == 'super_admin'


# Rest of the model classes remain the same
class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    duration = db.Column(db.Integer, nullable=False)  # In minutes
    is_active = db.Column(db.Boolean, default=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    show_results = db.Column(db.Boolean, default=False)
    randomize_questions = db.Column(db.Boolean, default=True)  # New field to randomize questions
    proctoring_enabled = db.Column(db.Boolean, default=True)  # New field to enable proctoring
    max_tab_switches = db.Column(db.Integer, default=3)  # Max tab switches allowed
    questions = db.relationship('Question', backref='exam', lazy=True, cascade='all, delete-orphan')
    student_exams = db.relationship('StudentExam', backref='exam', lazy=True, cascade='all, delete-orphan')


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=True)
    question_image = db.Column(db.String(255), nullable=True)
    option_a = db.Column(db.Text, nullable=False)
    option_b = db.Column(db.Text, nullable=False)
    option_c = db.Column(db.Text, nullable=False)
    option_d = db.Column(db.Text, nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)
    student_answers = db.relationship('StudentAnswer', backref='question', lazy=True, cascade='all, delete-orphan')


class StudentExam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    score = db.Column(db.Integer, default=0)
    question_order = db.Column(db.Text, nullable=True)  # Store randomized question order as JSON
    tab_switches = db.Column(db.Integer, default=0)  # Count of tab switches
    fullscreen_exits = db.Column(db.Integer, default=0)  # Count of fullscreen exits
    answers = db.relationship('StudentAnswer', backref='student_exam', lazy=True, cascade='all, delete-orphan')


class StudentAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_exam_id = db.Column(db.Integer, db.ForeignKey('student_exam.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_option = db.Column(db.String(1), nullable=True)
    is_correct = db.Column(db.Boolean, default=False)


# New model to track exam proctoring events
class ProctoringEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_exam_id = db.Column(db.Integer, db.ForeignKey('student_exam.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # tab_switch, fullscreen_exit, copy_attempt, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)  # Additional event details
    screenshot_path = db.Column(db.String(255), nullable=True)  # Path to the screenshot if captured


# All helper functions and routes remain the same
# ... [rest of your functions and routes stay unchanged]

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def send_verification_email(user):
    token = str(uuid.uuid4())
    user.verification_token = token
    db.session.commit()

    verification_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Email Verification', recipients=[user.email])
    msg.body = f'Please click the link to verify your email: {verification_url}'
    mail.send(msg)


def end_exam_timer(exam_id):
    with app.app_context():
        exam = Exam.query.get(exam_id)
        if exam and exam.is_active:
            exam.is_active = False
            exam.end_time = datetime.utcnow()

            # Auto-submit for all students who haven't completed the exam
            student_exams = StudentExam.query.filter_by(exam_id=exam_id, is_completed=False).all()
            for student_exam in student_exams:
                student_exam.is_completed = True
                student_exam.end_time = datetime.utcnow()
                calculate_score(student_exam)

            db.session.commit()
            print(f"Exam {exam_id} has ended automatically.")


def calculate_score(student_exam):
    correct_answers = 0
    total_questions = len(student_exam.exam.questions)

    for answer in student_exam.answers:
        if answer.is_correct:
            correct_answers += 1

    student_exam.score = (correct_answers / total_questions * 100) if total_questions > 0 else 0
    db.session.commit()


def log_proctoring_event(student_exam_id, event_type, details=None, screenshot=None):
    """Log a proctoring event with optional screenshot"""
    screenshot_path = None

    # Save screenshot if provided
    if screenshot:
        try:
            # Remove header from base64 data
            if ',' in screenshot:
                screenshot = screenshot.split(',')[1]

            image_data = base64.b64decode(screenshot)
            filename = f"{student_exam_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{event_type}.jpg"
            filepath = os.path.join(app.config['PROCTORING_FOLDER'], filename)

            with open(filepath, 'wb') as f:
                f.write(image_data)

            screenshot_path = filename
        except Exception as e:
            print(f"Error saving screenshot: {e}")

    # Create and save event
    event = ProctoringEvent(
        student_exam_id=student_exam_id,
        event_type=event_type,
        details=details,
        screenshot_path=screenshot_path
    )

    db.session.add(event)
    db.session.commit()

    return event


def get_question_order(exam_id, student_exam_id=None):
    """Generate or retrieve randomized question order for a student's exam"""
    if student_exam_id:
        student_exam = StudentExam.query.get(student_exam_id)
        if student_exam and student_exam.question_order:
            return json.loads(student_exam.question_order)

    # Get all question IDs for this exam
    questions = Question.query.filter_by(exam_id=exam_id).all()
    question_ids = [q.id for q in questions]

    # Randomize order
    random.shuffle(question_ids)

    return question_ids


def avatar_svg(avatar_type):
    if not avatar_type:
        return Markup('<i class="bi bi-person-circle" style="font-size: 4rem; color: #0d6efd;"></i>')

    # Dictionary of avatar SVG templates
    avatar_templates = {
        'male-1': '''
            <svg class="avatar-svg" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <circle cx="50" cy="50" r="50" fill="#e6e6e6"/>
                <circle cx="50" cy="42" r="20" fill="#a6223c"/>
                <path d="M25 85 Q50 65 75 85" stroke="#a6223c" stroke-width="2" fill="none"/>
                <circle cx="42" cy="40" r="3" fill="#ffffff"/>
                <circle cx="58" cy="40" r="3" fill="#ffffff"/>
                <path d="M35 60 Q50 70 65 60" stroke="#333333" stroke-width="2" fill="none"/>
                <path d="M20 30 Q30 20 40 28" stroke="#333333" stroke-width="2" fill="none"/>
                <path d="M80 30 Q70 20 60 28" stroke="#333333" stroke-width="2" fill="none"/>
            </svg>
        ''',
        'male-2': '''
            <svg class="avatar-svg" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <circle cx="50" cy="50" r="50" fill="#e6e6e6"/>
                <rect x="30" y="20" width="40" height="30" rx="15" fill="#85192f"/>
                <circle cx="50" cy="45" r="20" fill="#c3aea2"/>
                <circle cx="42" cy="40" r="3" fill="#333333"/>
                <circle cx="58" cy="40" r="3" fill="#333333"/>
                <rect x="35" y="50" width="30" height="2" rx="1" fill="#333333"/>
                <path d="M25 85 Q50 75 75 85" stroke="#85192f" stroke-width="2" fill="none"/>
            </svg>
        ''',
        'female-1': '''
            <svg class="avatar-svg" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <circle cx="50" cy="50" r="50" fill="#e6e6e6"/>
                <path d="M25 35 Q50 10 75 35 L75 50 Q50 65 25 50 Z" fill="#c73e58"/>
                <circle cx="50" cy="45" r="20" fill="#f4d5dc"/>
                <circle cx="42" cy="40" r="3" fill="#333333"/>
                <circle cx="58" cy="40" r="3" fill="#333333"/>
                <path d="M42 52 Q50 58 58 52" stroke="#333333" stroke-width="2" fill="none"/>
                <path d="M25 85 Q50 65 75 85" stroke="#c73e58" stroke-width="2" fill="none"/>
            </svg>
        ''',
        'female-2': '''
            <svg class="avatar-svg" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <circle cx="50" cy="50" r="50" fill="#e6e6e6"/>
                <path d="M20 55 Q50 15 80 55 L75 70 Q50 85 25 70 Z" fill="#a6223c"/>
                <circle cx="50" cy="45" r="18" fill="#ffe0b2"/>
                <circle cx="42" cy="40" r="3" fill="#333333"/>
                <circle cx="58" cy="40" r="3" fill="#333333"/>
                <path d="M40 52 Q50 60 60 52" stroke="#333333" stroke-width="2" fill="none"/>
                <path d="M30 35 L35 30" stroke="#333333" stroke-width="2" fill="none"/>
                <path d="M70 35 L65 30" stroke="#333333" stroke-width="2" fill="none"/>
            </svg>
        '''
    }

    # Return the appropriate SVG template or a default one if not found
    svg_template = avatar_templates.get(avatar_type, avatar_templates['male-1'])
    return Markup(svg_template.strip())


# Register the function directly with Jinja2
app.jinja_env.globals['avatar_svg'] = avatar_svg


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'super_admin':
            return redirect(url_for('super_admin_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if not user.is_verified and user.role == 'student':
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))

            login_user(user)
            next_page = request.args.get('next')

            if user.role == 'super_admin':
                return redirect(next_page or url_for('super_admin_dashboard'))
            elif user.role == 'admin':
                return redirect(next_page or url_for('admin_dashboard'))
            else:
                return redirect(next_page or url_for('student_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/google-auth')
def google_auth():
    # Redirect to Google's OAuth 2.0 server
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/google-callback')
def google_callback():
    try:
        # Get authorization code Google sent back
        token = google.authorize_access_token()

        # Get the user's profile information
        # Use the complete URL for the userinfo endpoint
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()

        # Extract user data
        email = user_info.get('email')

        if not email:
            flash('Could not get email from Google account.', 'danger')
            return redirect(url_for('login'))

        # Check if user exists in our database
        user = User.query.filter_by(email=email).first()

        if not user:
            # Create a new user if not exists
            user = User(
                email=email,
                role='student',
                is_verified=True  # Google verified the email
            )

            # Generate a random password (user won't use this)
            random_password = secrets.token_urlsafe(12)
            user.set_password(random_password)

            db.session.add(user)
            db.session.commit()

        # Log in the user
        login_user(user)

        # Redirect based on user role
        if user.role == 'super_admin':
            return redirect(url_for('super_admin_dashboard'))
        elif user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            # If student profile is incomplete, redirect to complete profile
            if not user.name or not user.stream or not user.contact:
                return redirect(url_for('complete_profile'))
            return redirect(url_for('student_dashboard'))

    except Exception as e:
        # Log the error and show a friendly message
        print(f"Google auth error: {str(e)}")
        flash('An error occurred during Google authentication.', 'danger')
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        user = User(email=email, role='student')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Send verification email
        send_verification_email(user)

        flash('Registration successful. Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()

    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Your email has been verified! You can now login.', 'success')
    else:
        flash('Invalid or expired verification link.', 'danger')

    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Super Admin Routes
@app.route('/super-admin/dashboard')
@login_required
def super_admin_dashboard():
    if not current_user.is_super_admin():
        flash('Access denied. This area is only for super administrators.', 'danger')
        return redirect(url_for('index'))
    
    # Get all users registered on the platform
    all_users = User.query.all()
    
    # Get all exams in the system
    all_exams = Exam.query.all()
    
    # Get user stats for graphs
    user_stats = {
        'total_users': User.query.count(),
        'students': User.query.filter_by(role='student').count(),
        'admins': User.query.filter_by(role='admin').count(),
        'verified_users': User.query.filter_by(is_verified=True).count(),
        'unverified_users': User.query.filter_by(is_verified=False).count()
    }
    
    # Get exam stats for graphs
    exam_stats = {
        'total_exams': Exam.query.count(),
        'active_exams': Exam.query.filter_by(is_active=True).count(),
        'inactive_exams': Exam.query.filter_by(is_active=False).count(),
        'completed_exams': StudentExam.query.filter_by(is_completed=True).count()
    }
    
    # Get stream statistics
    streams = db.session.query(User.stream, db.func.count(User.id)).filter(User.stream != None).group_by(User.stream).all()
    stream_data = {stream: count for stream, count in streams}
    
    return render_template('super_admin/dashboard.html', 
                          users=all_users, 
                          exams=all_exams, 
                          user_stats=user_stats,
                          exam_stats=exam_stats,
                          stream_data=stream_data,
                          now=datetime.utcnow)

# Route for super admin to view and manage users
@app.route('/super-admin/users')
@login_required
def manage_users():
    if not current_user.is_super_admin():
        flash('Access denied. This area is only for super administrators.', 'danger')
        return redirect(url_for('index'))

    # Get user statistics
    user_stats = {
        'total_users': User.query.count(),
        'students': User.query.filter_by(role='student').count(),
        'admins': User.query.filter_by(role='admin').count(),
        'super_admins': User.query.filter_by(role='super_admin').count()
    }

    # Get stream data for the stream filter dropdown
    streams = db.session.query(User.stream, db.func.count(User.id)) \
        .filter(User.stream != None) \
        .group_by(User.stream).all()
    stream_data = {stream: count for stream, count in streams}

    # Implement pagination (optional, but recommended)
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of users per page

    # Apply filters
    query = User.query

    # Role filter
    role = request.args.get('role')
    if role and role != 'all':
        query = query.filter_by(role=role)

    # Stream filter
    stream = request.args.get('stream')
    if stream and stream != 'all':
        query = query.filter_by(stream=stream)

    # Verification filter
    verification = request.args.get('verification')
    if verification == 'verified':
        query = query.filter_by(is_verified=True)
    elif verification == 'unverified':
        query = query.filter_by(is_verified=False)

    # Search filter
    search = request.args.get('search')
    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )

    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items

    return render_template('super_admin/manage_users.html',
                           users=users,
                           user_stats=user_stats,
                           stream_data=stream_data,
                           page=page,
                           per_page=per_page,
                           total_pages=pagination.pages)


@app.route('/super-admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_super_admin():
        flash('Access denied. This area is only for super administrators.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)

    # Get stream data for the stream dropdown
    streams = db.session.query(User.stream, db.func.count(User.id)) \
        .filter(User.stream != None) \
        .group_by(User.stream).all()
    stream_data = {stream: count for stream, count in streams}

    # Get all exams for the reports modal
    exams = Exam.query.all()

    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        user.is_verified = 'is_verified' in request.form
        user.stream = request.form.get('stream')
        user.contact = request.form.get('contact')
        user.avatar = request.form.get('avatar')

        # Update password if provided
        new_password = request.form.get('new_password')
        if new_password:
            user.set_password(new_password)

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('super_admin/edit_user.html',
                           user=user,
                           stream_data=stream_data,
                           exams=exams)
# Modified generate_report route to restrict access to super admin only
@app.route('/super-admin/generate-report', methods=['POST'])
@login_required
def generate_report():
    if not current_user.is_super_admin():
        flash('Access denied. This feature is only available to super administrators.', 'danger')
        return redirect(url_for('index'))

    # Get report parameters from the form
    report_type = request.form.get('report_type')
    exam_id = request.form.get('exam_id')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    report_format = request.form.get('report_format', 'excel')

    # Initialize data for the report
    data = []
    columns = []
    filename = "report"

    # Generate different reports based on the type
    if report_type == 'exams':
        # Handle exam performance report
        if exam_id:
            # Get data for a specific exam
            exam = Exam.query.get_or_404(exam_id)
            student_exams = StudentExam.query.filter_by(exam_id=exam_id).all()

            columns = ['Student Name', 'Email', 'Contact', 'Stream', 'Score', 'Start Time', 'End Time', 'Completed',
                       'Tab Switches', 'Fullscreen Exits']

            for student_exam in student_exams:
                student = User.query.get(student_exam.student_id)
                data.append([
                    student.name,
                    student.email,
                    student.contact,
                    student.stream,
                    f"{student_exam.score:.2f}%",
                    student_exam.start_time.strftime('%Y-%m-%d %H:%M:%S') if student_exam.start_time else '',
                    student_exam.end_time.strftime('%Y-%m-%d %H:%M:%S') if student_exam.end_time else '',
                    'Yes' if student_exam.is_completed else 'No',
                    student_exam.tab_switches,
                    student_exam.fullscreen_exits
                ])

            filename = f"exam_{exam.title}_report"
        else:
            # Get data for all exams
            exams = Exam.query.all()  # Super admin can see all exams, not just their own

            columns = ['Exam Title', 'Created By', 'Description', 'Duration', 'Created', 'Status', 'Student Count', 'Avg Score']

            for exam in exams:
                creator = User.query.get(exam.created_by)
                student_exams = StudentExam.query.filter_by(exam_id=exam.id).all()
                avg_score = sum(se.score for se in student_exams) / len(student_exams) if student_exams else 0

                status = 'Active' if exam.is_active else ('Completed' if exam.end_time else 'Not Started')

                data.append([
                    exam.title,
                    creator.email if creator else 'Unknown',
                    exam.description[:50] + '...' if exam.description and len(exam.description) > 50 else (
                                exam.description or ''),
                    f"{exam.duration} mins",
                    exam.created_at.strftime('%Y-%m-%d'),
                    status,
                    len(student_exams),
                    f"{avg_score:.2f}%"
                ])

            filename = "all_exams_report"

    elif report_type == 'students':
        # Handle student performance report
        student_search = request.form.get('student_search')
        stream = request.form.get('stream')

        # Base query for student exams
        query = StudentExam.query.join(User).join(Exam)

        # Apply filters
        if student_search:
            query = query.filter(User.name.like(f'%{student_search}%') | User.email.like(f'%{student_search}%'))
        if stream:
            query = query.filter(User.stream == stream)
        if exam_id:
            query = query.filter(StudentExam.exam_id == exam_id)

        student_exams = query.all()

        columns = ['Student Name', 'Email', 'Contact', 'Stream', 'Exam Title', 'Score', 'Completion Time', 'Status']

        for student_exam in student_exams:
            student = User.query.get(student_exam.student_id)
            exam = Exam.query.get(student_exam.exam_id)

            completion_time = ""
            if student_exam.start_time and student_exam.end_time:
                time_diff = student_exam.end_time - student_exam.start_time
                completion_time = f"{time_diff.total_seconds() / 60:.1f} mins"

            data.append([
                student.name,
                student.email,
                student.contact,
                student.stream,
                exam.title,
                f"{student_exam.score:.2f}%",
                completion_time,
                'Completed' if student_exam.is_completed else 'In Progress'
            ])

        filename = "student_performance_report"

    elif report_type == 'users':
        # New report type for user management (exclusive to super admin)
        role_filter = request.form.get('role_filter')
        
        # Base query
        query = User.query
        
        # Apply role filter if present
        if role_filter and role_filter != 'all':
            query = query.filter(User.role == role_filter)
            
        users = query.all()
        
        columns = ['ID', 'Name', 'Email', 'Role', 'Verified', 'Stream', 'Contact', 'Exams Taken', 'Avg Score']
        
        for user in users:
            # Get exams taken by student
            student_exams = StudentExam.query.filter_by(student_id=user.id).all() if user.role == 'student' else []
            avg_score = sum(se.score for se in student_exams) / len(student_exams) if student_exams else 0
            
            # Get exams created by admin
            admin_exams = Exam.query.filter_by(created_by=user.id).count() if user.role in ['admin', 'super_admin'] else 0
            
            data.append([
                user.id,
                user.name or 'Not Set',
                user.email,
                user.role,
                'Yes' if user.is_verified else 'No',
                user.stream or 'Not Set',
                user.contact or 'Not Set',
                len(student_exams) if user.role == 'student' else admin_exams,
                f"{avg_score:.2f}%" if user.role == 'student' else 'N/A'
            ])
            
        filename = "user_management_report"

    elif report_type == 'proctoring':
        # Handle proctoring events report
        event_types = request.form.getlist('event_types')

        query = ProctoringEvent.query.join(StudentExam).join(User)

        if exam_id:
            query = query.filter(StudentExam.exam_id == exam_id)
        if event_types:
            query = query.filter(ProctoringEvent.event_type.in_(event_types))

        events = query.order_by(ProctoringEvent.timestamp.desc()).all()

        columns = ['Student Name', 'Email', 'Exam', 'Event Type', 'Timestamp', 'Details']

        for event in events:
            student_exam = StudentExam.query.get(event.student_exam_id)
            student = User.query.get(student_exam.student_id)
            exam = Exam.query.get(student_exam.exam_id)

            data.append([
                student.name,
                student.email,
                exam.title,
                event.event_type,
                event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                event.details
            ])

        filename = "proctoring_events_report"

    # Create DataFrame and generate Excel file
    df = pd.DataFrame(data, columns=columns)

    # Create a bytes buffer for the Excel file
    output = io.BytesIO()

    # Use pandas to write to the buffer
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Report', index=False)

        # Access the workbook and the worksheet
        workbook = writer.book
        worksheet = writer.sheets['Report']

        # Create cell formats
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#4F81BD',
            'font_color': 'white',
            'border': 1,
            'align': 'center'
        })

        # Format for alternating rows
        alt_row_format = workbook.add_format({
            'fg_color': '#F2F2F2',
            'border': 1
        })

        # Regular row format
        row_format = workbook.add_format({
            'border': 1
        })

        # Format for numeric values
        number_format = workbook.add_format({
            'align': 'right',
            'border': 1
        })

        # Format for percentages
        percent_format = workbook.add_format({
            'num_format': '0.00%',
            'align': 'right',
            'border': 1
        })

        # Format for dates and times
        date_format = workbook.add_format({
            'num_format': 'yyyy-mm-dd hh:mm:ss',
            'align': 'center',
            'border': 1
        })

        # Write the column headers with the defined format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

            # Set appropriate column widths based on content type
            if 'Name' in value or 'Title' in value or 'Description' in value:
                worksheet.set_column(col_num, col_num, 25)  # Wider for text fields
            elif 'Email' in value:
                worksheet.set_column(col_num, col_num, 30)  # Wider for emails
            elif 'Contact' in value:
                worksheet.set_column(col_num, col_num, 15)  # Reasonable for phone numbers
            elif 'Time' in value or 'Date' in value:
                worksheet.set_column(col_num, col_num, 20)  # For timestamps
            else:
                worksheet.set_column(col_num, col_num, 12)  # Default width

        # Apply cell formats to data rows
        for row_num in range(1, len(df) + 1):
            # Apply alternating row colors
            row_fmt = alt_row_format if row_num % 2 == 0 else row_format

            for col_num, value in enumerate(df.iloc[row_num - 1]):
                cell_format = row_fmt

                # Apply specific formats based on column content
                if 'Score' in df.columns[col_num] and '%' in str(value):
                    # Convert string percentage to float and write with percentage format
                    try:
                        clean_value = float(value.replace('%', '')) / 100
                        worksheet.write_number(row_num, col_num, clean_value, percent_format)
                        continue
                    except:
                        pass

                # Apply specific format for dates
                if ('Time' in df.columns[col_num] or 'Date' in df.columns[col_num]) and value:
                    cell_format = date_format

                # Write the cell with the appropriate format
                worksheet.write(row_num, col_num, value, cell_format)

        # Add auto filter
        worksheet.autofilter(0, 0, len(df), len(df.columns) - 1)

        # Freeze the header row
        worksheet.freeze_panes(1, 0)

    # Set up the buffer for sending
    output.seek(0)

    # Determine the correct mimetype for the response
    if report_format == 'excel':
        mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        file_ext = '.xlsx'
    elif report_format == 'csv':
        mimetype = 'text/csv'
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        file_ext = '.csv'
    else:  # Default to Excel
        mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        file_ext = '.xlsx'

    # Send the file to the user
    return send_file(
        output,
        as_attachment=True,
        download_name=f"{filename}{file_ext}",
        mimetype=mimetype
    )

# Admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. This area is only for administrators.', 'danger')
        return redirect(url_for('index'))

    # Get all exams created by the current admin user
    exams = Exam.query.filter_by(created_by=current_user.id).order_by(Exam.created_at.desc()).all()

    # Pass the current datetime to the template
    current_time = datetime.utcnow()

    return render_template('admin/dashboard.html', exams=exams, now=current_time)

@app.route('/admin/create-exam', methods=['GET', 'POST'])
@login_required
def create_exam():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        duration = int(request.form.get('duration'))
        randomize_questions = 'randomize_questions' in request.form
        proctoring_enabled = 'proctoring_enabled' in request.form
        max_tab_switches = int(request.form.get('max_tab_switches', 3))

        exam = Exam(
            title=title,
            description=description,
            duration=duration,
            randomize_questions=randomize_questions,
            proctoring_enabled=proctoring_enabled,
            max_tab_switches=max_tab_switches,
            created_by=current_user.id
        )

        db.session.add(exam)
        db.session.commit()

        flash('Exam created successfully.', 'success')
        return redirect(url_for('edit_exam', exam_id=exam.id))

    return render_template('admin/create_exam.html')

@app.route('/admin/edit-exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def edit_exam(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        exam.title = request.form.get('title')
        exam.description = request.form.get('description')
        exam.duration = int(request.form.get('duration'))
        exam.randomize_questions = 'randomize_questions' in request.form
        exam.proctoring_enabled = 'proctoring_enabled' in request.form
        exam.max_tab_switches = int(request.form.get('max_tab_switches', 3))

        db.session.commit()
        flash('Exam updated successfully.', 'success')

    return render_template('admin/edit_exam.html', exam=exam)

@app.route('/admin/exam/<int:exam_id>/questions', methods=['GET', 'POST'])
@login_required
def manage_questions(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        question_text = request.form.get('question_text')
        option_a = request.form.get('option_a')
        option_b = request.form.get('option_b')
        option_c = request.form.get('option_c')
        option_d = request.form.get('option_d')
        correct_option = request.form.get('correct_option')

        # Handle image upload
        question_image = None
        if 'question_image' in request.files:
            file = request.files['question_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                question_image = filename

        question = Question(
            exam_id=exam_id,
            question_text=question_text,
            question_image=question_image,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_option=correct_option
        )

        db.session.add(question)
        db.session.commit()

        flash('Question added successfully.', 'success')
        return redirect(url_for('manage_questions', exam_id=exam_id))

    questions = Question.query.filter_by(exam_id=exam_id).all()
    return render_template('admin/manage_questions.html', exam=exam, questions=questions)

@app.route('/admin/question/<int:question_id>/delete', methods=['POST'])
@login_required
def delete_question(question_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    question = Question.query.get_or_404(question_id)
    exam = question.exam

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Delete image if exists
    if question.question_image:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], question.question_image))
        except:
            pass

    db.session.delete(question)
    db.session.commit()

    flash('Question deleted successfully.', 'success')
    return redirect(url_for('manage_questions', exam_id=exam.id))
@app.route('/admin/exam/<int:exam_id>/start', methods=['POST'])
@login_required
def start_exam(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if not exam.questions:
        flash('Cannot start an exam with no questions.', 'danger')
        return redirect(url_for('manage_questions', exam_id=exam_id))

    exam.is_active = True
    exam.start_time = datetime.utcnow()
    exam.end_time = exam.start_time + timedelta(minutes=exam.duration)
    db.session.commit()

    # Schedule the auto-end timer
    end_timer = Timer(exam.duration * 60, end_exam_timer, args=[exam_id])
    end_timer.daemon = True
    end_timer.start()

    flash(f'Exam "{exam.title}" has been started and will end in {exam.duration} minutes.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/super-admin/add-user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_super_admin():
        flash('Access denied. This area is only for super administrators.', 'danger')
        return redirect(url_for('index'))

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    role = request.form.get('role')
    stream = request.form.get('stream')
    is_verified = 'is_verified' in request.form

    # Validate email
    if not validate_email(email):
        flash('Please enter a valid email address.', 'danger')
        return redirect(url_for('manage_users'))

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash('A user with this email already exists.', 'danger')
        return redirect(url_for('manage_users'))

    # Create new user
    user = User(
        email=email,
        name=name,
        role=role,
        stream=stream,
        is_verified=is_verified
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    flash('User added successfully.', 'success')
    return redirect(url_for('manage_users'))




@app.route('/admin/exam/<int:exam_id>/end', methods=['POST'])
@login_required
def end_exam(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    end_exam_timer(exam_id)
    flash(f'Exam "{exam.title}" has been ended manually.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/exam/<int:exam_id>/results', methods=['GET'])
@login_required
def exam_results(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    student_exams = StudentExam.query.filter_by(exam_id=exam_id).all()

    # Get students information
    results = []
    for student_exam in student_exams:
        student = User.query.get(student_exam.student_id)

        # Calculate detailed results for each question
        question_results = []
        for question in exam.questions:
            answer = StudentAnswer.query.filter_by(
                student_exam_id=student_exam.id,
                question_id=question.id
            ).first()

            question_results.append({
                'question_id': question.id,
                'selected_option': answer.selected_option if answer else None,
                'is_correct': answer.is_correct if answer else False,
                'correct_option': question.correct_option
            })

        # Get proctoring events count
        tab_switches = student_exam.tab_switches
        fullscreen_exits = student_exam.fullscreen_exits
        suspicious_events = ProctoringEvent.query.filter_by(student_exam_id=student_exam.id).count()

        results.append({
            'student_id': student.id,
            'student_name': student.name,
            'student_stream': student.stream,
            'student_contact': student.contact,
            'student_email': student.email,
            'score': student_exam.score,
            'start_time': student_exam.start_time,
            'end_time': student_exam.end_time,
            'is_completed': student_exam.is_completed,
            'tab_switches': tab_switches,
            'fullscreen_exits': fullscreen_exits,
            'suspicious_events': suspicious_events,
            'question_results': question_results
        })

    # Sort results by score (descending)
    results.sort(key=lambda x: x['score'], reverse=True)

    return render_template('admin/exam_results.html', exam=exam, results=results)

@app.route('/admin/exam/<int:exam_id>/proctoring-events', methods=['GET'])
@login_required
def proctoring_events(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    student_id = request.args.get('student_id')

    # Query to get student exams for this exam
    student_exams_query = StudentExam.query.filter_by(exam_id=exam_id)

    # Filter by student if specified
    if student_id:
        student_exams_query = student_exams_query.filter_by(student_id=student_id)

    student_exams = student_exams_query.all()

    # Get all events for these student exams
    events = []
    for student_exam in student_exams:
        student = User.query.get(student_exam.student_id)

        # Get events for this student exam
        student_events = ProctoringEvent.query.filter_by(student_exam_id=student_exam.id) \
            .order_by(ProctoringEvent.timestamp.desc()).all()

        for event in student_events:
            events.append({
                'student_name': student.name,
                'student_email': student.email,
                'event_type': event.event_type,
                'timestamp': event.timestamp,
                'details': event.details,
                'screenshot_path': event.screenshot_path
            })

    # Sort events by timestamp (most recent first)
    events.sort(key=lambda x: x['timestamp'], reverse=True)

    return render_template('admin/proctoring_events.html', exam=exam, events=events)

@app.route('/admin/exam/<int:exam_id>/toggle-results', methods=['POST'])
@login_required
def toggle_results_visibility(exam_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if exam.created_by != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_dashboard'))

    exam.show_results = not exam.show_results
    db.session.commit()

    status = "visible to students" if exam.show_results else "hidden from students"
    flash(f'Exam results are now {status}.', 'success')
    return redirect(url_for('exam_results', exam_id=exam_id))

# Student routes
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    # If student profile is not complete, redirect to complete profile
    if not current_user.name or not current_user.stream or not current_user.contact:
        return redirect(url_for('complete_profile'))
    # Get active exams
    active_exams = Exam.query.filter_by(is_active=True).all()
    # Get completed exams with visible results
    completed_exams = StudentExam.query.filter_by(
        student_id=current_user.id,
        is_completed=True
    ).join(Exam).filter(Exam.show_results == True).all()

    return render_template('student/dashboard.html',
                           active_exams=active_exams,
                           completed_exams=completed_exams,
                           now=datetime.utcnow)

@app.route('/student/complete-profile', methods=['GET', 'POST'])
@login_required
def complete_profile():
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        stream = request.form.get('stream')
        contact = request.form.get('contact')
        full_contact = request.form.get('full_contact')  # Get the full contact with country code
        avatar = request.form.get('avatar')  # Get the selected avatar value

        if not name or not stream or not avatar:
            flash('All fields are required.', 'danger')
            return redirect(url_for('complete_profile'))

        current_user.name = name
        current_user.stream = stream
        current_user.avatar = avatar  # Save the avatar value

        # Use the full contact with country code if available, otherwise use regular contact
        if full_contact:
            current_user.contact = full_contact
        else:
            current_user.contact = contact

        db.session.commit()

        flash('Profile completed successfully.', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('student/complete_profile.html')

@app.route('/student/take-exam/<int:exam_id>', methods=['GET', 'POST'])
@login_required
def take_exam(exam_id):
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    exam = Exam.query.get_or_404(exam_id)

    if not exam.is_active:
        flash('This exam is not active.', 'danger')
        return redirect(url_for('student_dashboard'))

    # Check if student has already taken this exam
    existing_exam = StudentExam.query.filter_by(
        student_id=current_user.id,
        exam_id=exam_id
    ).first()

    if existing_exam and existing_exam.is_completed:
        flash('You have already completed this exam.', 'info')
        return redirect(url_for('student_dashboard'))

    # If student is starting the exam
    if not existing_exam:
        # Generate randomized question order if enabled
        question_order = None
        if exam.randomize_questions:
            question_order = get_question_order(exam_id)
            question_order = json.dumps(question_order)

        student_exam = StudentExam(
            student_id=current_user.id,
            exam_id=exam_id,
            start_time=datetime.utcnow(),
            question_order=question_order
        )
        db.session.add(student_exam)
        db.session.commit()
    else:
        student_exam = existing_exam

    # Calculate remaining time
    remaining_seconds = 0
    if exam.end_time:
        time_diff = exam.end_time - datetime.utcnow()
        remaining_seconds = max(0, int(time_diff.total_seconds()))

    # Process form submission (answers)
    if request.method == 'POST':
        for question in exam.questions:
            answer_key = f'answer_{question.id}'
            selected_option = request.form.get(answer_key)

            # Check if an answer already exists
            existing_answer = StudentAnswer.query.filter_by(
                student_exam_id=student_exam.id,
                question_id=question.id
            ).first()

            if existing_answer:
                existing_answer.selected_option = selected_option
                existing_answer.is_correct = selected_option == question.correct_option
            else:
                answer = StudentAnswer(
                    student_exam_id=student_exam.id,
                    question_id=question.id,
                    selected_option=selected_option,
                    is_correct=selected_option == question.correct_option
                )
                db.session.add(answer)

        # If submit button was pressed, mark exam as completed
        if 'submit_exam' in request.form:
            student_exam.is_completed = True
            student_exam.end_time = datetime.utcnow()
            calculate_score(student_exam)

            flash('Exam submitted successfully.', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            db.session.commit()
            flash('Answers saved.', 'success')

    # Get existing answers
    answers = {}
    for answer in student_exam.answers:
        answers[answer.question_id] = answer.selected_option

    # Get questions in correct order if randomized
    ordered_questions = exam.questions
    if student_exam.question_order:
        question_order = json.loads(student_exam.question_order)
        questions_dict = {q.id: q for q in exam.questions}
        ordered_questions = [questions_dict[q_id] for q_id in question_order if q_id in questions_dict]

    return render_template('student/take_exam.html',
                           exam=exam,
                           student_exam=student_exam,
                           questions=ordered_questions,
                           answers=answers,
                           remaining_seconds=remaining_seconds,
                           proctoring_enabled=exam.proctoring_enabled,
                           max_tab_switches=exam.max_tab_switches)

@app.route('/student/exam-result/<int:student_exam_id>')
@login_required
def student_exam_result(student_exam_id):
    if current_user.role != 'student':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    student_exam = StudentExam.query.get_or_404(student_exam_id)

    if student_exam.student_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('student_dashboard'))

    exam = student_exam.exam

    if not exam.show_results:
        flash('Results for this exam are not available yet.', 'info')
        return redirect(url_for('student_dashboard'))

    # Get detailed results
    question_results = []
    for question in exam.questions:
        answer = StudentAnswer.query.filter_by(
            student_exam_id=student_exam.id,
            question_id=question.id
        ).first()

        question_results.append({
            'question': question,
            'selected_option': answer.selected_option if answer else None,
            'is_correct': answer.is_correct if answer else False
        })

    return render_template('student/exam_result.html',
                           student_exam=student_exam,
                           exam=exam,
                           question_results=question_results)
@app.route('/api/tab-focus-check', methods=['POST'])
@login_required
def tab_focus_check():
    """Track when student switches tabs or applications during exam"""
    if current_user.role != 'student':
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    data = request.get_json()
    student_exam_id = data.get('student_exam_id')
    lost_focus = data.get('lost_focus', False)
    screenshot = data.get('screenshot')

    student_exam = StudentExam.query.get(student_exam_id)

    if not student_exam or student_exam.student_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Invalid exam'}), 400

    # Check if exam is in progress
    if student_exam.is_completed:
        return jsonify({'status': 'info', 'message': 'Exam already completed'})

    exam = student_exam.exam

    if lost_focus:
        # Increment tab switch counter
        student_exam.tab_switches += 1
        db.session.commit()

        # Log the event
        log_proctoring_event(
            student_exam_id=student_exam_id,
            event_type='tab_switch',
            details=f"Tab switch detected. Total count: {student_exam.tab_switches}",
            screenshot=screenshot
        )

        # Check if maximum tab switches exceeded
        if exam.max_tab_switches > 0 and student_exam.tab_switches >= exam.max_tab_switches:
            # Auto-submit exam if tab switches exceed limit
            student_exam.is_completed = True
            student_exam.end_time = datetime.utcnow()
            calculate_score(student_exam)
            db.session.commit()

            return jsonify({
                'status': 'warning',
                'message': 'Maximum tab switches exceeded. Exam has been auto-submitted.',
                'action': 'redirect',
                'redirect_url': url_for('student_dashboard')
            })

        max_remaining = exam.max_tab_switches - student_exam.tab_switches
        warning_message = f"Tab switching detected! You have {max_remaining} warnings left before auto-submission."

        return jsonify({
            'status': 'warning',
            'message': warning_message
        })

    return jsonify({'status': 'ok'})

@app.route('/api/fullscreen-exit', methods=['POST'])
@login_required
def fullscreen_exit():
    """Track when student exits fullscreen mode during exam"""
    if current_user.role != 'student':
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    data = request.get_json()
    student_exam_id = data.get('student_exam_id')
    screenshot = data.get('screenshot')

    student_exam = StudentExam.query.get(student_exam_id)

    if not student_exam or student_exam.student_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Invalid exam'}), 400

    # Check if exam is in progress
    if student_exam.is_completed:
        return jsonify({'status': 'info', 'message': 'Exam already completed'})

    # Increment fullscreen exit counter
    student_exam.fullscreen_exits += 1
    db.session.commit()

    # Log the event
    log_proctoring_event(
        student_exam_id=student_exam_id,
        event_type='fullscreen_exit',
        details=f"Fullscreen exit detected. Total count: {student_exam.fullscreen_exits}",
        screenshot=screenshot
    )

    return jsonify({
        'status': 'warning',
        'message': 'Please return to fullscreen mode to continue the exam.'
    })

@app.route('/api/copy-paste-detected', methods=['POST'])
@login_required
def copy_paste_detected():
    """Track copy-paste attempts during exam"""
    if current_user.role != 'student':
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    data = request.get_json()
    student_exam_id = data.get('student_exam_id')
    event_type = data.get('event_type')  # 'copy' or 'paste'
    screenshot = data.get('screenshot')

    student_exam = StudentExam.query.get(student_exam_id)

    if not student_exam or student_exam.student_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Invalid exam'}), 400

    # Check if exam is in progress
    if student_exam.is_completed:
        return jsonify({'status': 'info', 'message': 'Exam already completed'})

    # Log the event
    log_proctoring_event(
        student_exam_id=student_exam_id,
        event_type=f'{event_type}_attempt',
        details=f"{event_type.capitalize()} attempt detected",
        screenshot=screenshot
    )

    return jsonify({
        'status': 'warning',
        'message': f'{event_type.capitalize()} operations are not allowed during the exam.'
    })

@app.route('/student/blog')
@login_required
def blog():
    # You can add any data you need to pass to the template here
    return render_template('student/blog.html')

@app.route('/api/capture-screenshot', methods=['POST'])
@login_required
def capture_screenshot():
    """Receive periodic screenshots during exam"""
    if current_user.role != 'student':
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    data = request.get_json()
    student_exam_id = data.get('student_exam_id')
    screenshot = data.get('screenshot')

    student_exam = StudentExam.query.get(student_exam_id)

    if not student_exam or student_exam.student_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Invalid exam'}), 400

    # Check if exam is in progress
    if student_exam.is_completed:
        return jsonify({'status': 'info', 'message': 'Exam already completed'})

    # Log the screenshot
    log_proctoring_event(
        student_exam_id=student_exam_id,
        event_type='periodic_screenshot',
        details="Periodic screenshot captured",
        screenshot=screenshot
    )

    return jsonify({'status': 'ok'})

@app.route('/api/mouse-leave', methods=['POST'])
@login_required
def mouse_leave():
    """Track when mouse leaves exam window"""
    if current_user.role != 'student':
        return jsonify({'status': 'error', 'message': 'Not authorized'}), 403

    data = request.get_json()
    student_exam_id = data.get('student_exam_id')
    screenshot = data.get('screenshot')

    student_exam = StudentExam.query.get(student_exam_id)

    if not student_exam or student_exam.student_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Invalid exam'}), 400

    # Check if exam is in progress
    if student_exam.is_completed:
        return jsonify({'status': 'info', 'message': 'Exam already completed'})

    # Log the event
    log_proctoring_event(
        student_exam_id=student_exam_id,
        event_type='mouse_leave',
        details="Mouse left exam window",
        screenshot=screenshot
    )

    return jsonify({
        'status': 'warning',
        'message': 'Your cursor left the exam window. Please keep focus on the exam.'
    })


@app.route('/init-db')
def init_db():
    # Check if database file already exists
    db_path = 'instance/exam.db'  # Adjust this path to match your setup
    if os.path.exists(db_path):
        # Database exists, just check for required users
        super_admin = User.query.filter_by(email='chandy1808@hotmail.com').first()
        admin = User.query.filter_by(email='rajsinghsenger3@gmail.com').first()

        if not super_admin or not admin:
            if not super_admin:
                super_admin = User(email='chandy1808@hotmail.com', role='super_admin', is_verified=True)
                super_admin.set_password('Father@786!')
                db.session.add(super_admin)

            if not admin:
                admin = User(email='rajsinghsenger3@gmail.com', role='admin', is_verified=True)
                admin.set_password('Father@786!')
                db.session.add(admin)

            db.session.commit()
            return 'Missing admin accounts have been created.'
        return 'Database already exists and admin accounts are present.'
    else:
        # Create new database
        db.create_all()

        # Create admin accounts
        super_admin = User(email='chandy1808@hotmail.com', role='super_admin', is_verified=True)
        super_admin.set_password('Father@786!')
        db.session.add(super_admin)

        admin = User(email='rajsinghsenger3@gmail.com', role='admin', is_verified=True)
        admin.set_password('Father@786!')
        db.session.add(admin)

        db.session.commit()
        return 'New database initialized with admin accounts.'
# Templates for the graphs and analytics
@app.route('/super-admin/api/user-stats')
@login_required
def user_stats_api():
    """API endpoint to get user statistics for charts"""
    if not current_user.is_super_admin():
        return jsonify({'error': 'Unauthorized'}), 403

    # User roles data
    role_counts = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
    role_data = {role: count for role, count in role_counts}

    # Verification status data
    verification_counts = db.session.query(User.is_verified, db.func.count(User.id)).group_by(User.is_verified).all()
    verification_data = {
        'Verified': dict(verification_counts).get(True, 0),
        'Unverified': dict(verification_counts).get(False, 0)
    }

    # Stream distribution data
    stream_counts = db.session.query(User.stream, db.func.count(User.id)) \
        .filter(User.stream != None) \
        .group_by(User.stream).all()
    stream_data = {stream: count for stream, count in stream_counts if stream}

    # Exam status data
    exam_counts = {
        'Active': Exam.query.filter_by(is_active=True).count(),
        'Completed': Exam.query.filter(Exam.end_time != None, Exam.is_active == False).count(),
        'Not Started': Exam.query.filter(Exam.start_time == None).count()
    }

    # Registration timeline data (last 7 days)
    today = datetime.utcnow().date()
    registration_data = []
    for i in range(7, -1, -1):
        target_date = today - timedelta(days=i)
        next_date = target_date + timedelta(days=1)
        count = User.query.filter(
            User.created_at >= target_date,
            User.created_at < next_date
        ).count()
        registration_data.append({
            'date': target_date.strftime('%Y-%m-%d'),
            'count': count
        })

    return jsonify({
        'roles': role_data,
        'verification': verification_data,
        'streams': stream_data,
        'exams': exam_counts,
        'registration_timeline': registration_data
    })

@app.route('/super-admin/user/<int:user_id>/details')
@login_required
def user_details(user_id):
    if not current_user.is_super_admin():
        return jsonify({'error': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)

    # Get user's exam history
    student_exams = StudentExam.query.filter_by(student_id=user_id).all()
    exams_taken = []

    for student_exam in student_exams:
        exam = Exam.query.get(student_exam.exam_id)
        exams_taken.append({
            'title': exam.title,
            'score': student_exam.score,
            'date': student_exam.end_time.strftime('%Y-%m-%d %H:%M:%S') if student_exam.end_time else 'Not Completed',
            'is_completed': student_exam.is_completed
        })

    # Get user's details
    user_details = {
        'id': user.id,
        'name': user.name or 'Not Set',
        'email': user.email,
        'role': user.role,
        'stream': user.stream or 'Not Set',
        'contact': user.contact or 'Not Set',
        'is_verified': user.is_verified,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'exams_taken': exams_taken
    }

    return jsonify(user_details)


@app.route('/super-admin/user/<int:user_id>/promote', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_super_admin():
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)

    # Only promote students to admin
    if user.role == 'student':
        user.role = 'admin'
        db.session.commit()
        return jsonify({'success': True, 'message': 'User promoted to admin'})
    else:
        return jsonify({'success': False, 'message': 'Cannot promote this user'})


@app.route('/super-admin/user/<int:user_id>/demote', methods=['POST'])
@login_required
def demote_user(user_id):
    if not current_user.is_super_admin():
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)

    # Only demote admins to student
    if user.role == 'admin':
        user.role = 'student'
        db.session.commit()
        return jsonify({'success': True, 'message': 'User demoted to student'})
    else:
        return jsonify({'success': False, 'message': 'Cannot demote this user'})


@app.route('/super-admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_super_admin():
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    # Prevent deleting super admins and the current user
    user = User.query.get_or_404(user_id)

    if user.role == 'super_admin' or user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot delete this user'})

    # Delete all related records
    # Delete student exams and their answers
    student_exams = StudentExam.query.filter_by(student_id=user_id).all()
    for student_exam in student_exams:
        # Delete student answers
        StudentAnswer.query.filter_by(student_exam_id=student_exam.id).delete()
        # Delete proctoring events
        ProctoringEvent.query.filter_by(student_exam_id=student_exam.id).delete()
        # Delete student exam
        db.session.delete(student_exam)

    # Delete exams created by this user if they are an admin
    if user.role == 'admin':
        exams = Exam.query.filter_by(created_by=user_id).all()
        for exam in exams:
            # Delete questions
            Question.query.filter_by(exam_id=exam.id).delete()
            # Delete student exams
            StudentExam.query.filter_by(exam_id=exam.id).delete()
            # Delete proctoring events
            db.session.query(ProctoringEvent).filter(
                ProctoringEvent.student_exam_id.in_(
                    db.session.query(StudentExam.id).filter_by(exam_id=exam.id)
                )
            ).delete(synchronize_session=False)
            # Delete exam
            db.session.delete(exam)

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'User deleted successfully'})




@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a unique token for password reset
            reset_token = str(uuid.uuid4())

            # Store the token with an expiration time (1 hour from now)
            user.reset_token = reset_token
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            # Create reset password URL
            reset_url = url_for('reset_password', token=reset_token, _external=True)

            # Send password reset email
            msg = Message('Password Reset Request',
                          recipients=[user.email],
                          sender=app.config['MAIL_DEFAULT_SENDER'])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.

This link will expire in 1 hour.
'''
            mail.send(msg)

            flash('An email with password reset instructions has been sent.', 'success')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'danger')

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Find user with the matching token
    user = User.query.filter_by(reset_token=token).first()

    # Check if token is valid and not expired
    if not user or not user.reset_token_expiration or user.reset_token_expiration < datetime.utcnow():
        flash('Invalid or expired password reset token.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate password
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        # Update user's password
        user.set_password(password)

        # Clear reset token and expiration
        user.reset_token = None
        user.reset_token_expiration = None

        db.session.commit()

        flash('Your password has been reset successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


if __name__ == '__main__':
    with app.app_context():
        db_path = 'instance/exam.db'  # Adjust path as needed
        if not os.path.exists(db_path):
            db.create_all()

            # Check if admin accounts exist
            super_admin = User.query.filter_by(email='chandy1808@hotmail.com').first()
            if not super_admin:
                super_admin = User(email='chandy1808@hotmail.com', role='super_admin', is_verified=True)
                super_admin.set_password('Father@786!')
                db.session.add(super_admin)

            admin = User.query.filter_by(email='rajsinghsenger3@gmail.com').first()
            if not admin:
                admin = User(email='rajsinghsenger3@gmail.com', role='admin', is_verified=True)
                admin.set_password('Father@786!')
                db.session.add(admin)

            db.session.commit()
            print('Database and admin accounts created.')

    app.run(debug=True)