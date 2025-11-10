import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import traceback
from functools import wraps
from datetime import datetime, date
import uuid
import random
from config_secret import ADMIN_REGISTRATION_KEY, MAIL_USERNAME, MAIL_PASSWORD, SECRET_KEY

# --- 1. APP AND DATABASE CONFIGURATION ---
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY 

db_path = os.path.join(basedir, 'instance', 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- EMAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = ('KKWIEER Exam Cell', 'kkwexamcell@gmail.com')

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
db = SQLAlchemy(app)

# --- LOGIN DECORATORS ---
def login_required(role="any"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'danger')
                return redirect(url_for('student_login'))
            
            if role != "any" and session.get('role') != role:
                flash('You do not have permission to access this page.', 'danger')
                if session.get('role') == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
                    
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- DATABASE MODELS ---
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    def get_reset_token(self, expires_sec=1800):
        return s.dumps({'user_id': self.id, 'role': 'student'}, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token):
        try:
            data = s.loads(token, salt='password-reset-salt', max_age=1800)
            if data.get('role') == 'student':
                return Student.query.get(data.get('user_id'))
        except (SignatureExpired, BadTimeSignature): 
            return None
        return None

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    photo = db.Column(db.String(200), nullable=True)

    def get_reset_token(self, expires_sec=1800):
        return s.dumps({'user_id': self.id, 'role': 'admin'}, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token):
        try:
            data = s.loads(token, salt='password-reset-salt', max_age=1800)
            if data.get('role') == 'admin':
                return Admin.query.get(data.get('user_id'))
        except (SignatureExpired, BadTimeSignature): 
            return None
        return None

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_type = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.String(10), nullable=False)
    year = db.Column(db.String(10), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    no_of_classes = db.Column(db.Integer, nullable=False)

class ExamRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.String(10), nullable=False)
    semester = db.Column(db.String(10), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    exam_name = db.Column(db.String(100), nullable=False)
    exam_date = db.Column(db.Date, nullable=False)

class RollNumber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id', ondelete='CASCADE'), nullable=False)
    serial_no = db.Column(db.Integer, nullable=False)
    roll_number = db.Column(db.String(50), nullable=False)
    exam = db.relationship('Exam', backref=db.backref('roll_numbers', lazy=True, cascade="all, delete-orphan"))

class StudentAllocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id', ondelete='CASCADE'), nullable=False)
    serial_no = db.Column(db.Integer, nullable=False, index=True)
    classroom = db.Column(db.String(50), nullable=False)
    bench_number = db.Column(db.Integer, nullable=False)
    exam = db.relationship('Exam', backref=db.backref('allocations', lazy=True, cascade="all, delete-orphan"))

class LoginSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    user_type = db.Column(db.String(10), nullable=False)  # 'admin' or 'student'
    username = db.Column(db.String(80), nullable=False)
    login_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    session_active = db.Column(db.Boolean, default=True)

class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wing = db.Column(db.String(1), nullable=False)
    block_no = db.Column(db.Integer, nullable=False)
    class_no = db.Column(db.Integer, nullable=False)
    __table_args__ = (db.UniqueConstraint('wing', 'block_no', 'class_no', name='unique_classroom'),)

# --- ALLOCATION LOGIC ---
def allocate_students(serial_count, classroom_dict):
    allocations = []
    serial_index = 1
    # Randomly arrange classrooms instead of sorting
    classroom_items = list(classroom_dict.items())
    random.shuffle(classroom_items)
    
    for classroom, capacity in classroom_items:
        if serial_index > serial_count: 
            break
        for i in range(capacity):
            if serial_index > serial_count: 
                break
            allocations.append({'serial_no': serial_index, 'classroom': classroom, 'bench_number': i + 1})
            serial_index += 1
    return allocations

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    # Update logout time for current session
    if 'login_session_id' in session:
        login_session = LoginSession.query.get(session['login_session_id'])
        if login_session:
            login_session.logout_time = datetime.utcnow()
            login_session.session_active = False
            db.session.commit()
    
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
             flash('Username and password are required.', 'danger')
             return redirect(url_for('student_login'))
        student = Student.query.filter_by(username=username).first()
        if student and check_password_hash(student.password, password):
            session.clear()  # Clear any existing session
            session['user_id'] = student.id
            session['username'] = student.username
            session['role'] = 'student'
            session.permanent = True
            
            # Log the login session
            login_session = LoginSession(
                user_id=student.id,
                user_type='student',
                username=student.username,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(login_session)
            db.session.commit()
            session['login_session_id'] = login_session.id
            
            flash(f'Welcome {student.fullname}!', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('loginpage.html')

@app.route('/signup', methods=['GET', 'POST'])
def student_signup():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        if not all([fullname, email, username, password]):
             flash('All fields are required.', 'danger')
             return redirect(url_for('student_signup'))
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('student_signup'))
        if Student.query.filter((Student.username == username) | (Student.email == email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('student_signup'))
        
        new_student = Student(fullname=fullname, email=email, username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_student)
        db.session.commit()
        
        # Log the signup activity
        signup_session = LoginSession(
            user_id=new_student.id,
            user_type='student',
            username=new_student.username,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            session_active=False  # Signup, not active login
        )
        db.session.add(signup_session)
        db.session.commit()
        
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('student_login'))
    return render_template('signup.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('admin_login'))
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['role'] = 'admin'
            
            # Log the admin login session
            login_session = LoginSession(
                user_id=admin.id,
                user_type='admin',
                username=admin.username,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(login_session)
            db.session.commit()
            session['login_session_id'] = login_session.id
            
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        registration_key = request.form.get('registration_key')
        if registration_key != ADMIN_REGISTRATION_KEY:
            flash('Invalid registration key.', 'danger')
            return redirect(url_for('admin_signup'))
        
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([fullname, email, username, password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin_signup'))
        
        if Admin.query.filter((Admin.username == username) | (Admin.email == email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('admin_signup'))
        
        new_admin = Admin(fullname=fullname, email=email, username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_admin)
        db.session.commit()
        
        # Log the admin signup activity
        signup_session = LoginSession(
            user_id=new_admin.id,
            user_type='admin',
            username=new_admin.username,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            session_active=False  # Signup, not active login
        )
        db.session.add(signup_session)
        db.session.commit()
        
        flash('Admin account created successfully!', 'success')
        return redirect(url_for('admin_login'))
    return render_template('admin_signup.html')

# --- STUDENT DASHBOARD ---
@app.route('/student/dashboard')
@login_required('student')
def student_dashboard():
    return render_template('student_dashboard.html')

@app.route('/dashboard')
@login_required('student')
def student_dashboard_alt():
    return redirect(url_for('student_dashboard'))

@app.route('/test_student')
def test_student():
    return f"<h1>Student Dashboard Test</h1><p>Session: {dict(session)}</p><a href='/student/dashboard'>Go to Dashboard</a>"

@app.route('/student/check_allocation', methods=['POST'])
@login_required('student')
def check_allocation():
    exam_type = request.form.get('exam_type')
    semester = request.form.get('semester')
    year = request.form.get('year')
    branch = request.form.get('branch')
    roll_no = request.form.get('roll_no')
    
    # Find the serial number for this roll number
    roll_entry = RollNumber.query.join(Exam).filter(
        Exam.exam_type == exam_type,
        Exam.semester == semester,
        Exam.year == year,
        Exam.branch == branch,
        RollNumber.roll_number == roll_no
    ).first()
    
    if not roll_entry:
        return jsonify({'found': False})
    
    allocation = StudentAllocation.query.filter_by(
        exam_id=roll_entry.exam_id,
        serial_no=roll_entry.serial_no
    ).first()
    
    if allocation:
        wing = allocation.classroom[0] if allocation.classroom else 'A'
        block_no = allocation.classroom[1:] if len(allocation.classroom) > 1 else '1'
        
        return jsonify({
            'found': True,
            'bench_number': allocation.bench_number,
            'classroom': allocation.classroom,
            'wing': wing,
            'block_no': block_no
        })
    else:
        return jsonify({'found': False})

# --- ADMIN DASHBOARD ---
@app.route('/admin/dashboard')
@login_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/home')
@login_required('admin')
def admin_home():
    return render_template('admin_dashboard.html')

@app.route('/admin/info')
@login_required('admin')
def admin_info():
    admins = Admin.query.all()
    return render_template('admin_info.html', admins=admins)

@app.route('/admin/edit_profile', methods=['POST'])
@login_required('admin')
def admin_edit_profile():
    fullname = request.form.get('fullname')
    username = request.form.get('username')
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    if not all([fullname, username, email]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('admin_info'))
    
    existing_admin = Admin.query.filter(
        (Admin.username == username) | (Admin.email == email),
        Admin.id != session['user_id']
    ).first()
    
    if existing_admin:
        flash('Username or email already exists.', 'danger')
        return redirect(url_for('admin_info'))
    
    current_admin = Admin.query.get(session['user_id'])
    current_admin.fullname = fullname
    current_admin.username = username
    current_admin.email = email
    current_admin.phone = phone if phone else None
    
    db.session.commit()
    session['username'] = username
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('admin_info'))

@app.route('/admin/upload_photo', methods=['POST'])
@login_required('admin')
def upload_admin_photo():
    if 'photo' not in request.files:
        flash('No photo selected', 'danger')
        return redirect(url_for('admin_info'))
    
    file = request.files['photo']
    if file.filename == '':
        flash('No photo selected', 'danger')
        return redirect(url_for('admin_info'))
    
    if file and file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
        filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        current_admin = Admin.query.get(session['user_id'])
        current_admin.photo = filename
        db.session.commit()
        
        flash('Photo uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Please upload an image file.', 'danger')
    
    return redirect(url_for('admin_info'))

@app.route('/admin/exam', methods=['GET', 'POST'])
@login_required('admin')
def admin_exam():
    if request.method == 'POST':
        exam_type = request.form.get('exam_type')
        semester = request.form.get('semester')
        branch = request.form.get('branch')
        year = request.form.get('year')
        no_of_classes = int(request.form.get('no_of_classes', 0))
        selected_classrooms = request.form.getlist('selected_classrooms')
        
        if len(selected_classrooms) != no_of_classes:
            flash(f'Please select exactly {no_of_classes} classrooms.', 'danger')
            return redirect(url_for('admin_exam'))
        
        if 'student_file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(url_for('admin_exam'))
        
        file = request.files['student_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin_exam'))
        
        content = file.read().decode('utf-8')
        roll_numbers = [roll.strip() for roll in content.split(',') if roll.strip()]
        
        total_capacity = no_of_classes * 35
        if len(roll_numbers) > total_capacity:
            flash(f'{len(roll_numbers) - total_capacity} students are remaining to be allocated a block. Please increase number of classes.', 'danger')
            return redirect(url_for('admin_exam'))
        
        exam = Exam(
            exam_type=exam_type,
            semester=semester,
            branch=branch,
            year=year,
            no_of_classes=no_of_classes
        )
        db.session.add(exam)
        db.session.flush()
        
        # Save roll numbers with serial numbers
        for i, roll_no in enumerate(roll_numbers, 1):
            roll_entry = RollNumber(
                exam_id=exam.id,
                serial_no=i,
                roll_number=roll_no
            )
            db.session.add(roll_entry)
        
        classroom_dict = {}
        for classroom_id in selected_classrooms:
            classroom = Classroom.query.get(classroom_id)
            if classroom:
                classroom_name = f"{classroom.wing}{classroom.class_no}"
                classroom_dict[classroom_name] = 35
        
        allocations = allocate_students(len(roll_numbers), classroom_dict)
        
        for alloc in allocations:
            student_alloc = StudentAllocation(
                exam_id=exam.id,
                serial_no=alloc['serial_no'],
                classroom=alloc['classroom'],
                bench_number=alloc['bench_number']
            )
            db.session.add(student_alloc)
        
        db.session.commit()
        flash('Exam and allocations created successfully!', 'success')
        return redirect(url_for('admin_allocation'))
    
    all_classrooms = Classroom.query.order_by(Classroom.wing, Classroom.class_no).all()
    return render_template('admin_exam.html', all_classrooms=all_classrooms)

@app.route('/admin/allocation', methods=['GET', 'POST'])
@login_required('admin')
def admin_allocation():
    if request.method == 'POST':
        delete_exam_id = request.form.get('delete_exam_id')
        if delete_exam_id:
            exam = Exam.query.get(delete_exam_id)
            if exam:
                db.session.delete(exam)
                db.session.commit()
                flash('Allocation deleted successfully!', 'success')
            else:
                flash('Allocation not found.', 'danger')
            return redirect(url_for('admin_allocation'))
        
        # Handle edit allocation table
        exam_id = request.form.get('exam_id')
        row_count = int(request.form.get('row_count', 0))
        if exam_id and row_count > 0:
            # Delete existing allocations
            StudentAllocation.query.filter_by(exam_id=exam_id).delete()
            
            # Add new allocations
            for i in range(row_count):
                subject = request.form.get(f'subject_{i}')
                students = request.form.get(f'students_{i}')
                classroom = request.form.get(f'classroom_{i}')
                
                if subject and students and classroom:
                    # Parse student range and create allocations
                    if '-' in students:
                        start_roll, end_roll = students.split('-')
                        start_num = int(''.join(filter(str.isdigit, start_roll)))
                        end_num = int(''.join(filter(str.isdigit, end_roll)))
                        prefix = ''.join(filter(str.isalpha, start_roll))
                        
                        for j, roll_num in enumerate(range(start_num, end_num + 1)):
                            roll_no = f"{prefix}{roll_num}"
                            allocation = StudentAllocation(
                                exam_id=exam_id,
                                seat_number=roll_no,
                                classroom=classroom,
                                bench_number=(j % 35) + 1
                            )
                            db.session.add(allocation)
                    else:
                        allocation = StudentAllocation(
                            exam_id=exam_id,
                            seat_number=students,
                            classroom=classroom,
                            bench_number=1
                        )
                        db.session.add(allocation)
            
            db.session.commit()
            flash('Allocation table updated successfully!', 'success')
        return redirect(url_for('admin_allocation'))
    
    exams = Exam.query.all()
    return render_template('admin_allocation.html', exams=exams)

@app.route('/admin/allocation_details/<int:exam_id>')
@login_required('admin')
def allocation_details(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    allocations = StudentAllocation.query.filter_by(exam_id=exam_id).order_by(StudentAllocation.serial_no).all()
    
    classroom_groups = {}
    for alloc in allocations:
        if alloc.classroom not in classroom_groups:
            classroom_groups[alloc.classroom] = []
        # Get roll number from serial number
        roll_entry = RollNumber.query.filter_by(exam_id=exam_id, serial_no=alloc.serial_no).first()
        roll_no = roll_entry.roll_number if roll_entry else f"Serial-{alloc.serial_no}"
        classroom_groups[alloc.classroom].append((alloc.serial_no, roll_no))
    
    subject_name = f"{exam.exam_type} - {exam.semester} Sem - {exam.year} Year - {exam.branch}"
    
    details = []
    for classroom, student_data in classroom_groups.items():
        if student_data:
            # Sort by serial number to ensure sequential ranges
            student_data.sort(key=lambda x: x[0])
            roll_numbers = [data[1] for data in student_data]
            student_range = f"{roll_numbers[0]} to {roll_numbers[-1]}" if len(roll_numbers) > 1 else roll_numbers[0]
            student_count = len(roll_numbers)
            # Find the actual block number from Classroom table
            wing = classroom[0] if classroom else 'A'
            class_no = classroom[1:] if len(classroom) > 1 else '1'
            classroom_obj = Classroom.query.filter_by(wing=wing, class_no=int(class_no)).first()
            block_no = classroom_obj.block_no if classroom_obj else class_no
            
            details.append({
                'subject': subject_name,
                'students': student_range,
                'classroom': classroom,
                'block_no': block_no,
                'student_count': student_count,
                'min_serial': student_data[0][0],
                'all_roll_numbers': roll_numbers
            })
    
    # Sort details by minimum serial number to show sequential ranges
    details.sort(key=lambda x: x['min_serial'])
    # Remove min_serial from output
    for detail in details:
        del detail['min_serial']
    
    return jsonify({'details': details})

@app.route('/admin/records', methods=['GET', 'POST'])
@app.route('/admin/schedule', methods=['GET', 'POST'])
@login_required('admin')
def admin_records():
    if request.method == 'POST':
        year = request.form.get('year')
        semester = request.form.get('semester')
        branch = request.form.get('branch')
        exam_name = request.form.get('exam_name')
        exam_date = request.form.get('exam_date')
        
        exam_date_obj = datetime.strptime(exam_date, '%Y-%m-%d').date()
        if exam_date_obj < date.today():
            flash('Exam date cannot be in the past.', 'danger')
            records = ExamRecord.query.order_by(ExamRecord.exam_date.desc()).all()
            today = date.today().strftime('%Y-%m-%d')
            return render_template('admin_schedule.html', records=records, today=today)
        
        record = ExamRecord(
            year=year,
            semester=semester,
            branch=branch,
            exam_name=exam_name,
            exam_date=exam_date_obj
        )
        db.session.add(record)
        db.session.commit()
        flash('Exam record added successfully!', 'success')
    
    records = ExamRecord.query.order_by(ExamRecord.exam_date.desc()).all()
    today = date.today().strftime('%Y-%m-%d')
    return render_template('admin_schedule.html', records=records, today=today)

@app.route('/admin/edit_record', methods=['POST'])
@login_required('admin')
def edit_record():
    record_id = request.form.get('record_id')
    exam_name = request.form.get('exam_name')
    exam_date = request.form.get('exam_date')
    semester = request.form.get('semester')
    
    record = ExamRecord.query.get(record_id)
    if record:
        record.exam_name = exam_name
        record.exam_date = datetime.strptime(exam_date, '%Y-%m-%d').date()
        record.semester = semester
        db.session.commit()
        flash('Exam record updated successfully!', 'success')
    else:
        flash('Record not found.', 'danger')
    
    return redirect(url_for('admin_records'))

@app.route('/admin/delete_record', methods=['POST'])
@login_required('admin')
def delete_record():
    record_id = request.form.get('record_id')
    
    record = ExamRecord.query.get(record_id)
    if record:
        db.session.delete(record)
        db.session.commit()
        flash('Exam record deleted successfully!', 'success')
    else:
        flash('Record not found.', 'danger')
    
    return redirect(url_for('admin_records'))

@app.route('/admin/login_history')
@login_required('admin')
def admin_login_history():
    # Get all login sessions ordered by login time (most recent first)
    sessions = LoginSession.query.order_by(LoginSession.login_time.desc()).limit(100).all()
    return render_template('admin_login_history.html', sessions=sessions)

@app.route('/admin/restore_classroom', methods=['POST'])
@login_required('admin')
def restore_classroom():
    wing = request.form.get('wing')
    block_no = request.form.get('block_no')
    class_no = request.form.get('class_no')
    
    if wing and block_no and class_no:
        existing = Classroom.query.filter_by(wing=wing, block_no=int(block_no), class_no=int(class_no)).first()
        if not existing:
            restored_classroom = Classroom(wing=wing, block_no=int(block_no), class_no=int(class_no))
            db.session.add(restored_classroom)
            db.session.commit()
            flash('Classroom restored successfully!', 'success')
        else:
            flash('Classroom already exists!', 'danger')
    return redirect(url_for('classroom'))

@app.route('/api/classrooms')
@login_required('admin')
def get_classrooms():
    classrooms = Classroom.query.order_by(Classroom.wing, Classroom.class_no).all()
    return jsonify([{
        'id': c.id,
        'name': f"{c.wing}{c.class_no}",
        'wing': c.wing,
        'block': c.block_no
    } for c in classrooms])

@app.route('/admin/classroom', methods=['GET', 'POST'])
@login_required('admin')
def classroom():
    if request.method == 'POST':
        delete_id = request.form.get('delete_id')
        if delete_id:
            classroom = Classroom.query.get(delete_id)
            if classroom:
                wing = classroom.wing
                block_no = classroom.block_no
                class_no = classroom.class_no
                db.session.delete(classroom)
                db.session.commit()
                session['deleted_classroom'] = {'wing': wing, 'block_no': block_no, 'class_no': class_no}
                flash(f'Classroom {wing}{class_no} deleted! <button class="btn btn-sm btn-outline-light" onclick="restoreClassroom()">Restore</button>', 'warning')
        else:
            wing = request.form.get('wing')
            block_no = request.form.get('block_no')
            class_no = request.form.get('class_no')
            
            if wing and block_no and class_no:
                # Check if classroom already exists
                existing = Classroom.query.filter_by(wing=wing, block_no=int(block_no), class_no=int(class_no)).first()
                if existing:
                    flash('Classroom already exists!', 'danger')
                else:
                    new_classroom = Classroom(wing=wing, block_no=int(block_no), class_no=int(class_no))
                    db.session.add(new_classroom)
                    db.session.commit()
                    flash('Classroom added successfully!', 'success')
    
    classrooms_by_wing = {
        'A': Classroom.query.filter_by(wing='A').all(),
        'B': Classroom.query.filter_by(wing='B').all(),
        'C': Classroom.query.filter_by(wing='C').all(),
        'D': Classroom.query.filter_by(wing='D').all(),
        'E': Classroom.query.filter_by(wing='E').all()
    }
    return render_template('classroom.html', classrooms_by_wing=classrooms_by_wing)

# --- PASSWORD RESET ROUTES ---
@app.route('/forgot_password_student', methods=['GET', 'POST'])
def sforgot():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Email address is required.', 'danger')
            return redirect(url_for('sforgot'))
        
        student = Student.query.filter(db.func.lower(Student.email) == email).first()
        if student:
            token = student.get_reset_token()
            reset_url = url_for('reset_password_student', token=token, _external=True)
            try:
                msg = Message('Password Reset Request', recipients=[student.email])
                msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.'''
                mail.send(msg)
                flash('A password reset email has been sent to your email address.', 'info')
            except:
                flash('Error sending email. Please try again later.', 'danger')
        else:
            flash('A password reset email has been sent if the account exists.', 'info')
        return redirect(url_for('student_login'))
    return render_template('sforgot.html')

@app.route('/admin/forgot_password', methods=['GET', 'POST'])
def aforgot():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Email address is required.', 'danger')
            return render_template('aforgot.html')
        
        admin = Admin.query.filter(db.func.lower(Admin.email) == email).first()
        if admin:
            try:
                token = admin.get_reset_token()
                reset_url = url_for('reset_password_admin', token=token, _external=True)
                msg = Message('Admin Password Reset Request', recipients=[admin.email])
                msg.body = f'''To reset your admin password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.'''
                mail.send(msg)
                flash('A password reset email has been sent to your email address.', 'success')
            except Exception as e:
                flash(f'Error sending email: {str(e)}', 'danger')
                return render_template('aforgot.html')
        else:
            flash('A password reset email has been sent if the account exists.', 'info')
        return redirect(url_for('admin_login'))
    return render_template('aforgot.html')

@app.route('/reset_password_student/<token>', methods=['GET', 'POST'])
def reset_password_student(token):
    student = Student.verify_reset_token(token)
    if not student:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('sforgot'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('resetpass_token.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('resetpass_token.html')
        
        student.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('student_login'))
    
    return render_template('resetpass_token.html')

@app.route('/reset_password_admin/<token>', methods=['GET', 'POST'])
def reset_password_admin(token):
    admin = Admin.verify_reset_token(token)
    if not admin:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('aforgot'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('arestpass_token.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('arestpass_token.html')
        
        admin.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('arestpass_token.html')

def create_default_classrooms():
    # Add 20 default classrooms
    default_classrooms = [
        {'wing': 'A', 'block_no': 1, 'class_no': 101},
        {'wing': 'A', 'block_no': 1, 'class_no': 102},
        {'wing': 'A', 'block_no': 1, 'class_no': 103},
        {'wing': 'A', 'block_no': 1, 'class_no': 104},
        {'wing': 'B', 'block_no': 2, 'class_no': 201},
        {'wing': 'B', 'block_no': 2, 'class_no': 202},
        {'wing': 'B', 'block_no': 2, 'class_no': 203},
        {'wing': 'B', 'block_no': 2, 'class_no': 204},
        {'wing': 'C', 'block_no': 3, 'class_no': 301},
        {'wing': 'C', 'block_no': 3, 'class_no': 302},
        {'wing': 'C', 'block_no': 3, 'class_no': 303},
        {'wing': 'C', 'block_no': 3, 'class_no': 304},
        {'wing': 'D', 'block_no': 4, 'class_no': 401},
        {'wing': 'D', 'block_no': 4, 'class_no': 402},
        {'wing': 'D', 'block_no': 4, 'class_no': 403},
        {'wing': 'D', 'block_no': 4, 'class_no': 404},
        {'wing': 'E', 'block_no': 5, 'class_no': 501},
        {'wing': 'E', 'block_no': 5, 'class_no': 502},
        {'wing': 'E', 'block_no': 5, 'class_no': 503},
        {'wing': 'E', 'block_no': 5, 'class_no': 504}
    ]
    
    for classroom_data in default_classrooms:
        existing = Classroom.query.filter_by(
            wing=classroom_data['wing'],
            block_no=classroom_data['block_no'],
            class_no=classroom_data['class_no']
        ).first()
        if not existing:
            classroom = Classroom(**classroom_data)
            db.session.add(classroom)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Clear all tables except classrooms
        Student.query.delete()
        Admin.query.delete()
        Exam.query.delete()
        ExamRecord.query.delete()
        RollNumber.query.delete()
        StudentAllocation.query.delete()
        LoginSession.query.delete()
        db.session.commit()
        
        # Ensure classrooms exist
        create_default_classrooms()
    app.run(debug=True)