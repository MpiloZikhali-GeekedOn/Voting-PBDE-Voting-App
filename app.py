from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import json
import uuid
from functools import wraps
import pytz

from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, desc, and_, or_
from sqlalchemy.orm import validates

# App Initialization
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Enable CORS
CORS(app)

# Set timezone for the application
TIMEZONE = pytz.timezone('Africa/Johannesburg')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Context Processors
@app.context_processor
def utility_processor():
    return {
        'now': datetime.now(TIMEZONE)  # Use local timezone
    }

# Database Initialization
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth4.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Ensure database exists and is initialized
def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")

# Initialize database on startup
init_db()

# Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Admin Credentials
ADMIN_EMAIL = "admin@voting.com"
ADMIN_PASSWORD = "admin123"  # Should be hashed in production

# File Upload Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# User Model
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    student_number = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(TIMEZONE))
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(20), default='student')  # 'student' or 'candidate'
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', or 'rejected'
    
    # Relationships
    votes = db.relationship('Vote', backref='voter', lazy=True)

    def get_id(self):
        return str(self.id)

# Candidate Model
class Candidate(db.Model):
    __tablename__ = 'candidates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(20), nullable=False)
    political_party = db.Column(db.String(100), nullable=False)
    contribution = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(TIMEZONE))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_candidate_user'), unique=True, nullable=False)
    
    # Relationships
    user = db.relationship('User', backref='candidate_profile')
    votes = db.relationship('Vote', backref='candidate', lazy=True)
    events = db.relationship('VotingEvent', 
                           secondary='event_candidates',
                           backref=db.backref('candidates', lazy='dynamic'))

    @validates('position')
    def validate_position(self, key, position):
        valid_positions = ['President', 'Vice', 'Treasurer']
        if position not in valid_positions:
            raise ValueError(f"Position must be one of: {', '.join(valid_positions)}")
        return position

# Voting Event Model
class VotingEvent(db.Model):
    __tablename__ = 'voting_events'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(TIMEZONE))
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    votes = db.relationship('Vote', backref='event', lazy=True)
    created_by = db.relationship('User', backref='created_events')

    @staticmethod
    def update_event_status():
        now = datetime.now(TIMEZONE)  # Use local timezone
        print(f"Current time (SAST): {now}")  # Debug print
        events = VotingEvent.query.all()
        for event in events:
            # Convert naive datetimes to local timezone if needed
            if event.start_date.tzinfo is None:
                event.start_date = TIMEZONE.localize(event.start_date)
            if event.end_date.tzinfo is None:
                event.end_date = TIMEZONE.localize(event.end_date)
                
            print(f"Updating event: {event.name}, Start: {event.start_date}, End: {event.end_date}")  # Debug print
            event.is_active = event.start_date <= now <= event.end_date
            print(f"Event {event.name} is_active: {event.is_active}")  # Debug print
        db.session.commit()

# Event-Candidate Association Table
event_candidates = db.Table('event_candidates',
    db.Column('event_id', db.Integer, db.ForeignKey('voting_events.id'), primary_key=True),
    db.Column('candidate_id', db.Integer, db.ForeignKey('candidates.id'), primary_key=True),
    db.Column('added_at', db.DateTime, default=lambda: datetime.now(TIMEZONE))
)

# Vote Model
class Vote(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('voting_events.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=lambda: datetime.now(TIMEZONE))
    ip_address = db.Column(db.String(45))  # Store IP for audit

    __table_args__ = (
        db.UniqueConstraint('voter_id', 'event_id', 'candidate_id', name='unique_vote'),
    )

# Audit Log Model for tracking important actions
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(TIMEZONE))

    user = db.relationship('User', backref='audit_logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all tables
with app.app_context():
    db.create_all()
    print("Database initialized successfully!")

@app.before_request
def update_events():
    VotingEvent.update_event_status()

# ------------------------- AUTH ROUTES -------------------------

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('view_events'))

@app.route('/menu')
@login_required
def menu():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('view_events'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('view_events'))

    if request.method == 'POST':
        name = request.form.get('name')
        student_number = request.form.get('student_number')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'student')  # Default to student if not specified

        # Validation
        if not all([name, student_number, email, password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))

        # Validate student number format (8 digits)
        if not student_number.isdigit() or len(student_number) != 8:
            flash('Invalid student number format! Must be 8 digits.', 'error')
            return redirect(url_for('register'))

        # Validate email format
        expected_email = f"{student_number}@dut4life.ac.za"
        if email != expected_email:
            flash('Email must match your student number format: studentnumber@dut4life.ac.za', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(student_number=student_number).first():
            flash('Student number already registered!', 'error')
            return redirect(url_for('register'))

        try:
            # Create new user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                name=name,
                student_number=student_number,
                email=email,
                password=hashed_password,
                role=role,
                status='pending' if role == 'candidate' else 'approved'
            )
            db.session.add(new_user)
            db.session.commit()

            # Log the registration
            log = AuditLog(
                user_id=new_user.id,
                action='REGISTER',
                details=f'User registration: {email} (Student: {student_number}, Role: {role})',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()

            # Automatically log in the user
            login_user(new_user)
            session['role'] = role

            if role == 'candidate':
                flash('Registration successful! Please wait for admin approval.', 'success')
                return redirect(url_for('student_dashboard'))
            else:
                flash('Registration successful! Welcome to the Student Voting System.', 'success')
                return redirect(url_for('view_events'))

        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session.get('role') == 'candidate':
            return redirect(url_for('student_dashboard'))
        return redirect(url_for('view_events'))

    if request.method == 'POST':
        login_id = request.form.get('login_id')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        # Check Admin Login
        if login_id == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session.clear()
            session['user_email'] = ADMIN_EMAIL
            session['role'] = 'admin'
            
            # Log admin login
            log = AuditLog(
                action='LOGIN',
                details=f'Admin login: {login_id}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Welcome Admin!', 'success')
            return redirect(url_for('admin_dashboard'))

        # If login_id is student number, convert to email format
        if login_id.isdigit() and len(login_id) == 8:
            login_id = f"{login_id}@dut4life.ac.za"

        # Check Student/Candidate Login (by email or student number)
        user = User.query.filter(User.email == login_id).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact admin.', 'error')
                return redirect(url_for('login'))

            login_user(user, remember=remember)
            session['role'] = user.role
            
            # Log user login
            log = AuditLog(
                user_id=user.id,
                action='LOGIN',
                details=f'User login: {user.email} (Student: {user.student_number}, Role: {user.role})',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()

            flash('Login successful!', 'success')
            
            # Redirect based on role
            if user.role == 'candidate':
                return redirect(url_for('student_dashboard'))
            else:
                next_page = request.args.get('next')
                return redirect(next_page if next_page else url_for('view_events'))

        flash('Invalid credentials!', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    was_student = session.get('role') == 'student'  # Check if user was a student before logout
    
    if current_user.is_authenticated:
        # Log the logout
        log = AuditLog(
            user_id=current_user.id if not session.get('role') == 'admin' else None,
            action='LOGOUT',
            details=f'Logout: {current_user.email if not session.get("role") == "admin" else "admin"}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

    # Clear the user session
    logout_user()
    session.clear()
    
    # Clear the remember me cookie
    response = make_response(redirect(url_for('register') if was_student else url_for('login')))
    response.delete_cookie('remember_token')  # Clear Flask-Login's remember me cookie
    response.delete_cookie('session')  # Clear the session cookie
    
    flash('You have been logged out. See you next time!', 'info')
    return response

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if name:
            current_user.name = name

        if current_password and new_password:
            if not bcrypt.check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect!', 'error')
                return redirect(url_for('profile'))

            if new_password != confirm_password:
                flash('New passwords do not match!', 'error')
                return redirect(url_for('profile'))

            current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # Log password change
            log = AuditLog(
                user_id=current_user.id,
                action='PASSWORD_CHANGE',
                details='User changed password',
                ip_address=request.remote_addr
            )
            db.session.add(log)

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating profile.', 'error')

    return render_template('profile.html', user=current_user)

# ------------------------- ADMIN ROUTES -------------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Get statistics
    total_candidates = Candidate.query.count()
    total_events = VotingEvent.query.count()
    now = datetime.now(TIMEZONE)  # Use local time
    active_events = VotingEvent.query.filter(
        and_(
            VotingEvent.start_date <= now,
            VotingEvent.end_date >= now,
            VotingEvent.is_active == True
        )
    ).count()
    total_votes = Vote.query.count()

    # Get recent activities
    recent_activities = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(10).all()

    return render_template('admin_dashboard.html',
                        total_candidates=total_candidates,
                        total_events=total_events,
                        active_events=active_events,
                        total_votes=total_votes,
                        recent_activities=recent_activities)

@app.route('/admin/candidates', methods=['GET', 'POST'])
@admin_required
def manage_candidates():
    if request.method == 'POST':
        candidate_id = request.form.get('candidate_id')
        if candidate_id:  # Update existing candidate
            try:
                candidate = Candidate.query.get_or_404(candidate_id)
                position = request.form.get('position')
                
                # Validate position before updating
                valid_positions = ['President', 'Vice', 'Treasurer']
                if position not in valid_positions:
                    flash(f'Invalid position. Must be one of: {", ".join(valid_positions)}', 'error')
                    return redirect(url_for('manage_candidates'))
                
                # Update candidate fields
                candidate.name = request.form.get('name')
                candidate.department = request.form.get('department')
                candidate.position = position
                candidate.political_party = request.form.get('political_party')
                candidate.contribution = request.form.get('contribution')
                
                image = request.files.get('image')
                if image and allowed_file(image.filename):
                    # Delete old image if it exists
                    if candidate.image_url:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate.image_url)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                    
                    filename = secure_filename(f"{uuid.uuid4()}_{image.filename}")
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    candidate.image_url = filename
                
                db.session.commit()
                flash('Candidate updated successfully!', 'success')
            except ValueError as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while updating the candidate.', 'error')
        else:  # Create new candidate
            try:
                name = request.form.get('name')
                department = request.form.get('department')
                position = request.form.get('position')
                political_party = request.form.get('political_party')
                contribution = request.form.get('contribution')
                image = request.files.get('image')

                if not all([name, department, position, political_party, contribution]):
                    flash('All fields except image are required!', 'error')
                    return redirect(url_for('manage_candidates'))

                # Validate position
                valid_positions = ['President', 'Vice', 'Treasurer']
                if position not in valid_positions:
                    flash(f'Invalid position. Must be one of: {", ".join(valid_positions)}', 'error')
                    return redirect(url_for('manage_candidates'))

                new_candidate = Candidate(
                    name=name,
                    department=department,
                    position=position,
                    political_party=political_party,
                    contribution=contribution
                )

                if image and allowed_file(image.filename):
                    filename = secure_filename(f"{uuid.uuid4()}_{image.filename}")
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    new_candidate.image_url = filename

                db.session.add(new_candidate)
                db.session.commit()

                # Log the action
                log = AuditLog(
                    action='CREATE_CANDIDATE',
                    details=f'Created candidate: {name}',
                    ip_address=request.remote_addr
                )
                db.session.add(log)
                db.session.commit()

                flash('Candidate added successfully!', 'success')
            except ValueError as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while adding the candidate.', 'error')

    # Get all candidates with their user status
    candidates = Candidate.query.join(User).order_by(Candidate.created_at.desc()).all()
    return render_template('admin/manage_candidates.html', candidates=candidates)

@app.route('/admin/events', methods=['GET', 'POST'])
@admin_required
def manage_events():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        if not all([name, start_date, end_date]):
            flash('Name, start date, and end date are required!', 'error')
            return redirect(url_for('manage_events'))

        try:
            # Parse dates and ensure they're in local timezone
            start_date = datetime.strptime(start_date, '%Y-%m-%dT%H:%M')
            end_date = datetime.strptime(end_date, '%Y-%m-%dT%H:%M')
            
            # Localize the datetimes to local timezone
            start_date = TIMEZONE.localize(start_date)
            end_date = TIMEZONE.localize(end_date)

            if start_date >= end_date:
                flash('End date must be after start date!', 'error')
                return redirect(url_for('manage_events'))

            new_event = VotingEvent(
                name=name,
                description=description,
                start_date=start_date,
                end_date=end_date,
                is_active=True  # Ensure new events are active by default
            )

            db.session.add(new_event)
            db.session.commit()

            # Log the action
            log = AuditLog(
                action='CREATE_EVENT',
                details=f'Created event: {name} (Start: {start_date}, End: {end_date})',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()

            flash('Event created successfully!', 'success')
            return redirect(url_for('manage_events'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the event: {str(e)}', 'error')
            return redirect(url_for('manage_events'))

    events = VotingEvent.query.order_by(VotingEvent.created_at.desc()).all()
    return render_template('admin/manage_events.html', events=events)

@app.route('/admin/event/<int:event_id>/candidates', methods=['GET', 'POST'])
@admin_required
def manage_event_candidates(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    
    if request.method == 'POST':
        selected_candidates = request.form.getlist('candidates')
        try:
            # Clear existing candidates
            event.candidates = []
            
            # Add selected candidates
            for candidate_id in selected_candidates:
                candidate = Candidate.query.get(candidate_id)
                if candidate:
                    event.candidates.append(candidate)
            
            db.session.commit()
            
            # Log the action
            log = AuditLog(
                action='UPDATE_EVENT_CANDIDATES',
                details=f'Updated candidates for event: {event.name}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Event candidates updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating candidates.', 'error')
            
    # Only get approved candidates
    candidates = Candidate.query.join(User).filter(User.status == 'approved').all()
    return render_template('admin/manage_event_candidates.html', 
                         event=event, 
                         candidates=candidates)

@app.route('/admin/event/<int:event_id>/delete', methods=['POST'])
@admin_required
def delete_event(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    try:
        # Delete associated votes first
        Vote.query.filter_by(event_id=event_id).delete()
        
        # Delete event
        db.session.delete(event)
        
        # Log the action
        log = AuditLog(
            action='DELETE_EVENT',
            details=f'Deleted event: {event.name}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the event.', 'error')
    
    return redirect(url_for('manage_events'))

@app.route('/admin/candidate/<int:candidate_id>/delete', methods=['POST'])
@admin_required
def delete_candidate(candidate_id):
    candidate = Candidate.query.get_or_404(candidate_id)
    try:
        db.session.delete(candidate)
        db.session.commit()

        # Log the action
        log = AuditLog(
            action='DELETE_CANDIDATE',
            details=f'Deleted candidate: {candidate.name}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        flash('Candidate deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the candidate.', 'error')

    return redirect(url_for('manage_candidates'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_positions_for_event(event_id):
    # Define this function to retrieve positions for the event
    event = VotingEvent.query.get(event_id)
    if not event:
        return []
    return [candidate.position for candidate in event.candidates]

@app.route('/event_results/<int:event_id>')
@login_required
def event_results(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    
    # Get all positions from the event's candidates
    positions = {}
    for candidate in event.candidates:
        if candidate.position not in positions:
            positions[candidate.position] = {
                'title': candidate.position,
                'description': f'Candidates running for {candidate.position}',
                'candidates': [],
                'total_votes': 0,
                'winner': None
            }
        
        # Get vote count for this candidate
        vote_count = Vote.query.filter_by(
            candidate_id=candidate.id,
            event_id=event_id
        ).count()
        
        # Handle image URL
        image_url = None
        if candidate.image_url:
            image_url = url_for('static', filename=f'uploads/{candidate.image_url}')
        
        # Add candidate to position with vote count
        positions[candidate.position]['candidates'].append({
            'id': candidate.id,
            'name': candidate.name,
            'bio': candidate.contribution,
            'image_url': image_url,
            'vote_count': vote_count
        })
        
        # Add to total votes for this position
        positions[candidate.position]['total_votes'] += vote_count
    
    # Calculate winners for each position
    for position in positions.values():
        if position['candidates']:
            # Sort candidates by vote count
            position['candidates'].sort(key=lambda x: x['vote_count'], reverse=True)
            # Set winner as the candidate with most votes
            position['winner'] = position['candidates'][0]
    
    return render_template('event_results.html',
                         event=event,
                         positions=positions.values())

# ------------------------- VOTING ROUTES -------------------------

@app.route('/events')
@login_required
def view_events():
    # Use local timezone for consistent comparison
    now = datetime.now(TIMEZONE)
    
    # Pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of events per page

    # Active events: started but not ended
    active_events = VotingEvent.query.filter(
        and_(
            VotingEvent.start_date <= now,
            VotingEvent.end_date >= now,
            VotingEvent.is_active == True
        )
    ).order_by(VotingEvent.start_date).paginate(page=page, per_page=per_page, error_out=False)

    # Past events: already ended
    past_events = VotingEvent.query.filter(
        VotingEvent.end_date < now
    ).order_by(VotingEvent.end_date.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # Upcoming events: not started yet
    upcoming_events = VotingEvent.query.filter(
        VotingEvent.start_date > now
    ).order_by(VotingEvent.start_date).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('events.html',
                         active_events=active_events.items,
                         past_events=past_events.items,
                         upcoming_events=upcoming_events.items,
                         current_time=now,
                         active_events_pagination=active_events,
                         past_events_pagination=past_events,
                         upcoming_events_pagination=upcoming_events)

@app.route('/event/<int:event_id>')
@login_required
def view_event(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    now = datetime.now(TIMEZONE)
    
    # Ensure event dates are timezone-aware
    if event.start_date.tzinfo is None:
        event.start_date = TIMEZONE.localize(event.start_date)
    if event.end_date.tzinfo is None:
        event.end_date = TIMEZONE.localize(event.end_date)
    
    # Check if event is active
    is_active = event.start_date <= now <= event.end_date and event.is_active
    
    # Get candidates for this event
    candidates = event.candidates
    
    # Check if user has already voted
    user_vote = None
    if current_user.is_authenticated:
        user_vote = Vote.query.filter_by(
            voter_id=current_user.id,
            event_id=event_id
        ).first()
    
    # Get vote counts for each candidate
    candidate_votes = {}
    total_votes = Vote.query.filter_by(event_id=event_id).count()
    
    for candidate in candidates:
        votes = Vote.query.filter_by(
            candidate_id=candidate.id,
            event_id=event_id
        ).count()
        percentage = (votes / total_votes * 100) if total_votes > 0 else 0
        candidate_votes[candidate.id] = {
            'count': votes,
            'percentage': round(percentage, 1)
        }
    
    return render_template('event_detail.html',
                         event=event,
                         candidates=candidates,
                         is_active=is_active,
                         user_vote=user_vote,
                         candidate_votes=candidate_votes,
                         total_votes=total_votes)

@app.route('/vote/<int:event_id>/<int:candidate_id>', methods=['POST'])
@login_required
def vote(event_id, candidate_id):
    # Prevent candidates from voting
    if current_user.role == 'candidate':
        flash('Candidates are not allowed to vote in elections.', 'error')
        return redirect(url_for('view_event', event_id=event_id))

    try:
        # Get the event and candidate
        event = VotingEvent.query.get_or_404(event_id)
        candidate = Candidate.query.get_or_404(candidate_id)
        
        # Check if event is active
        now = datetime.now(TIMEZONE)
        print(f"Current time (SAST): {now}")
        
        # Ensure event dates are timezone-aware
        if event.start_date.tzinfo is None:
            event.start_date = TIMEZONE.localize(event.start_date)
        if event.end_date.tzinfo is None:
            event.end_date = TIMEZONE.localize(event.end_date)
            
        print(f"Event start: {event.start_date}, Event end: {event.end_date}")
        print(f"Event is_active: {event.is_active}")
        
        # Debug print timezone info
        print(f"Start date timezone: {event.start_date.tzinfo}")
        print(f"End date timezone: {event.end_date.tzinfo}")
        print(f"Current time timezone: {now.tzinfo}")
        
        if not (event.start_date <= now <= event.end_date and event.is_active):
            print("Event is not active")
            flash('This voting event is not currently active.', 'error')
            return redirect(url_for('view_events'))
        
        # Check if user has already voted in this event
        existing_vote = Vote.query.filter_by(
            voter_id=current_user.id,
            event_id=event_id
        ).first()
        
        if existing_vote:
            print("User has already voted")
            flash('You have already voted in this event.', 'error')
            return redirect(url_for('view_event', event_id=event_id))
        
        # Create new vote
        new_vote = Vote(
            voter_id=current_user.id,
            candidate_id=candidate_id,
            event_id=event_id,
            ip_address=request.remote_addr
        )
        db.session.add(new_vote)
        
        # Log the voting action
        log = AuditLog(
            user_id=current_user.id,
            action='VOTE_CAST',
            details=f'Vote cast in event: {event.name}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        
        try:
            db.session.commit()
            print("Vote recorded successfully")
            flash('Your vote has been recorded successfully!', 'success')
        except IntegrityError as e:
            db.session.rollback()
            print(f"Database integrity error: {str(e)}")
            flash('You have already voted in this event.', 'error')
        except Exception as e:
            db.session.rollback()
            print(f"Database error: {str(e)}")
            flash('An error occurred while saving your vote. Please try again.', 'error')
        
    except Exception as e:
        db.session.rollback()
        print(f"Voting error: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('An error occurred while recording your vote. Please try again.', 'error')
        
    return redirect(url_for('view_event', event_id=event_id))

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    # Get current time in local timezone
    now = datetime.now(TIMEZONE)

    # Get active events
    active_events = VotingEvent.query.filter(
        and_(
            VotingEvent.start_date <= now,
            VotingEvent.end_date >= now,
            VotingEvent.is_active == True
        )
    ).order_by(VotingEvent.start_date).all()

    # Get past events
    past_events = VotingEvent.query.filter(
        VotingEvent.end_date < now
    ).order_by(VotingEvent.end_date.desc()).all()

    return render_template('student_dashboard.html',
                         active_events=active_events,
                         past_events=past_events)

@app.route('/admin/applications')
@admin_required
def manage_applications():
    # Get pending applications
    pending_applications = User.query.filter_by(
        role='candidate',
        status='pending'
    ).order_by(User.created_at.desc()).all()

    # Get processed applications (approved or rejected)
    processed_applications = User.query.filter(
        User.role == 'candidate',
        User.status.in_(['approved', 'rejected'])
    ).order_by(User.created_at.desc()).all()

    return render_template('admin/manage_applications.html',
                         pending_applications=pending_applications,
                         processed_applications=processed_applications)

@app.route('/admin/applications/<int:user_id>/status', methods=['POST'])
@admin_required
def update_application_status(user_id):
    user = User.query.get_or_404(user_id)
    new_status = request.form.get('status')

    if new_status not in ['approved', 'rejected']:
        flash('Invalid status!', 'error')
        return redirect(url_for('manage_applications'))

    try:
        user.status = new_status
        
        # If approved, create a candidate profile
        if new_status == 'approved':
            # Check if candidate profile already exists
            existing_candidate = Candidate.query.filter_by(user_id=user.id).first()
            if not existing_candidate:
                new_candidate = Candidate(
                    name=user.name,
                    department='Not Specified',  # These fields will be updated later
                    position='President',  # Default to President, can be changed later
                    political_party='Not Specified',
                    contribution='No platform specified yet',
                    user_id=user.id
                )
                db.session.add(new_candidate)
        
        db.session.commit()

        # Log the action
        log = AuditLog(
            action='UPDATE_APPLICATION_STATUS',
            details=f'Updated application status for {user.email} to {new_status}',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Application status updated to {new_status}!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating the application status.', 'error')

    return redirect(url_for('manage_applications'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)

