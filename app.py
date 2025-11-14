import os
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash, session, g 
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import send_from_directory

# --- Configuration ---
app = Flask(__name__)
# Use a simple SQLite DB for deployment simplicity
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed_in_production'

# File Upload Setup
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB file size

# Admin Email (Used as recipient for notifications)
ADMIN_EMAIL = 'rt3dprintservice0828@gmail.com'

# Flask-Mail Configuration (using provided credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = ADMIN_EMAIL
app.config['MAIL_PASSWORD'] = 'ucxh ezmp vesn gwol' # App Password

db = SQLAlchemy(app)
mail = Mail(app)

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    projects = db.relationship('Project', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Workflow fields
    project_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    stl_path = db.Column(db.String(255)) # Path to uploaded STL file
    status = db.Column(db.String(50), default='PENDING') # PENDING, PAYMENT_AWAITING, PAID, PROCESSING, DELIVERED
    
    # Payment related fields
    payment_amount = db.Column(db.Float)
    payment_qr_link = db.Column(db.String(255)) # Link to QR code or instructions
    payment_proof_path = db.Column(db.String(255)) # Path to uploaded screenshot
    
    # Delivery related fields
    admin_notes = db.Column(db.Text)
    delivery_link = db.Column(db.String(255)) # Link to final ZIP/Drive file
    
    # Rating field
    user_rating = db.Column(db.Integer)

    def __repr__(self):
        return f"Project('{self.id}', '{self.user_id}', '{self.status}')"

# --- Utility Functions ---

def send_email(subject, recipients, body, html=None):
    """Utility function to send emails."""
    try:
        msg = Message(subject, sender=ADMIN_EMAIL, recipients=recipients)
        msg.body = body
        if html:
            msg.html = html
        mail.send(msg)
        print(f"Email sent successfully to {', '.join(recipients)}.")
    except Exception as e:
        print(f"Email failed to send: {e}")
        # In a real app, you would log this error

def is_allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# --- Authentication and Role Management Decorators ---

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def admin_required(f):
    @login_required
    def wrapper(*args, **kwargs):
        user = db.session.get(User, session.get('user_id'))
        if user is None or not user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# --- Template Context Injection ---

@app.before_request
def check_auth_status():
    """Sets user status variables on the request context (g)."""
    g.current_user_is_admin = False
    g.current_user_email = None
    g.logged_in = 'user_id' in session
    
    if g.logged_in:
        user = db.session.get(User, session.get('user_id'))
        if user:
            g.current_user_is_admin = user.is_admin
            g.current_user_email = user.email

@app.context_processor
def inject_user_status():
    """Injects user status from g into all templates automatically."""
    return {
        'logged_in': g.logged_in,
        'current_user_is_admin': g.current_user_is_admin,
        'current_user_email': g.current_user_email
    }

# --- Routes ---

@app.route('/')
def index():
    """Home page."""
    # The 'logged_in' variable is now passed automatically via the context processor
    return render_template('index.html', title="Home")

# 1. Signup Email Notifications
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.logged_in:
        return redirect(url_for('user_dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already registered.', 'warning')
            return redirect(url_for('signup'))

        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send emails
        send_email(
            subject='Welcome to RT3DPRINT!',
            recipients=[email],
            body=f'Thank you for signing up to RT3DPRINT! Explore and share your ideas by logging into the website. Your account is: {email}'
        )
        send_email(
            subject='New User Signup Alert',
            recipients=[ADMIN_EMAIL],
            body=f'A new user has signed up: {email}'
        )

        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', title="Sign Up")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.logged_in:
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
            
    return render_template('login.html', title="Sign In")

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# 2. Contact Form Workflow
@app.route('/submit_request', methods=['POST'])
@login_required
def submit_request():
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    
    if not user:
        flash("User not found.", 'danger')
        return redirect(url_for('index'))

    # Check if a file was uploaded
    if 'stl_file' not in request.files:
        flash('No file part in the request.', 'danger')
        return redirect(url_for('index'))

    file = request.files['stl_file']
    
    if file.filename == '':
        flash('No selected file.', 'danger')
        return redirect(url_for('index'))

    # --- UPDATED: Broadened Allowed extensions for 3D models and Archives ---
    ALLOWED_EXTENSIONS = {'stl', 'obj', '3mf', 'zip', 'rar', '7z', 'fbx', 'dae', 'blend', '3ds', 'glb', 'gltf', 'step', 'iges', 'skp'}
    if file and is_allowed_file(file.filename, ALLOWED_EXTENSIONS):
    # ------------------------------------------------------------------------
        # Create a unique filename
        filename = secure_filename(file.filename)
        unique_filename = f"{secrets.token_hex(8)}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        new_project = Project(
            user_id=user_id,
            project_type=request.form.get('project_type'),
            description=request.form.get('description'),
            stl_path=file_path,
            status='PENDING'
        )
        db.session.add(new_project)
        db.session.commit()

        # Send emails (Step 2)
        # User email
        send_email(
            subject='RT3DPRINT Project Request Received',
            recipients=[user.email],
            body="Thanks for filling the form. Your project request is now being reviewed. We will contact you soon with payment details and estimated print time."
        )
        # Admin email
        send_email(
            subject=f'New Project Request from {user.email}',
            recipients=[ADMIN_EMAIL],
            body=f'New project request received from {user.email} (Project ID: {new_project.id}).\nType: {new_project.project_type}\nDescription: {new_project.description}'
        )

        flash('Project request submitted successfully! Check your dashboard for updates.', 'success')
        return redirect(url_for('user_dashboard'))
    else:
        # --- UPDATED: More informative error message ---
        flash('Invalid file type. Please upload a 3D model file (e.g., STL, OBJ, FBX, GLB) or a common archive (ZIP, RAR, 7Z).', 'danger')
        return redirect(url_for('index'))


@app.route('/user/dashboard')
@login_required
def user_dashboard():
    user_id = session['user_id']
    projects = Project.query.filter_by(user_id=user_id).order_by(Project.id.desc()).all()
    return render_template('user_dashboard.html', title="My Dashboard", projects=projects)

# 3. Admin Payment Setup (Action taken by Admin)
@app.route('/admin/set_payment/<int:project_id>', methods=['POST'])
@admin_required
def admin_set_payment(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    amount = request.form.get('amount')
    qr_link = request.form.get('qr_link')

    if not amount or not qr_link:
        flash('Amount and QR Link are required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    project.payment_amount = float(amount)
    project.payment_qr_link = qr_link
    project.status = 'PAYMENT_AWAITING'
    db.session.commit()

    # Send email (Step 3)
    user = db.session.get(User, project.user_id)
    payment_link_html = f'<a href="{qr_link}">Click here to view the Payment QR/Details</a>'
    
    send_email(
        subject=f'Payment Required for Project ID: {project_id}',
        recipients=[user.email],
        body=f"Your 3D printing request (ID: {project_id}) has been reviewed. The payment amount is ${amount:.2f}.\n\n{qr_link}",
        html=f"Your 3D printing request (ID: {project_id}) has been reviewed. The payment amount is **${amount:.2f}**.<br><br>Please make the payment and upload the screenshot on your dashboard.<br><br>{payment_link_html}"
    )

    flash(f'Payment details set for Project ID {project_id}. User notified.', 'success')
    return redirect(url_for('admin_dashboard'))

# 4. User Payment Upload (Action taken by User)
@app.route('/user/upload_payment/<int:project_id>', methods=['POST'])
@login_required
def user_upload_payment(project_id):
    project = db.session.get(Project, project_id)
    if not project or project.user_id != session['user_id'] or project.status != 'PAYMENT_AWAITING':
        flash('Cannot upload payment proof at this stage.', 'danger')
        return redirect(url_for('user_dashboard'))

    if 'payment_proof' not in request.files:
        flash('No payment proof file selected.', 'danger')
        return redirect(url_for('user_dashboard'))

    file = request.files['payment_proof']
    
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    if file and is_allowed_file(file.filename, ALLOWED_EXTENSIONS):
        filename = secure_filename(file.filename)
        unique_filename = f"proof_{secrets.token_hex(8)}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        project.payment_proof_path = file_path
        project.status = 'PAID' # Change status to paid, admin must now approve and start processing
        db.session.commit()

        # Send email (Step 4)
        user = db.session.get(User, project.user_id)
        send_email(
            subject=f'Payment Proof Uploaded for Project ID: {project_id}',
            recipients=[ADMIN_EMAIL],
            body=f'User {user.email} has paid and uploaded the screenshot for Project ID: {project.id}. Please check the admin dashboard and start processing.'
        )

        flash('Payment proof uploaded successfully! Awaiting Admin verification.', 'success')
    else:
        flash('Invalid file type. Only PNG, JPG, JPEG allowed for proof.', 'danger')

    return redirect(url_for('user_dashboard'))

# 5. Project Delivery (Action taken by Admin)
@app.route('/admin/delivery/<int:project_id>', methods=['POST'])
@admin_required
def admin_delivery(project_id):
    project = db.session.get(Project, project_id)
    if not project or project.status not in ['PAID', 'PROCESSING']:
        flash('Project status is not ready for delivery.', 'danger')
        return redirect(url_for('admin_dashboard'))

    delivery_link = request.form.get('delivery_link')
    admin_notes = request.form.get('admin_notes')

    if not delivery_link:
        flash('Delivery link is required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    project.delivery_link = delivery_link
    project.admin_notes = admin_notes
    project.status = 'DELIVERED'
    db.session.commit()

    # Send email (Step 5)
    user = db.session.get(User, project.user_id)
    send_email(
        subject=f'Your RT3DPRINT Project ID: {project_id} is Ready!',
        recipients=[user.email],
        body=f"Your 3D printing project (ID: {project_id}) has been completed and is ready for download. Please access the download link on your user dashboard.",
        html=f"Your 3D printing project (ID: {project_id}) has been completed and is ready for download. <br><br>Notes: {admin_notes}<br><br>You can download it from your **User Dashboard** or use this link: <a href='{delivery_link}'>{delivery_link}</a>"
    )

    flash(f'Project ID {project_id} delivered. User notified.', 'success')
    return redirect(url_for('admin_dashboard'))


# 6. User Rating (Action taken by User)
@app.route('/user/rate/<int:project_id>', methods=['POST'])
@login_required
def user_rate_project(project_id):
    project = db.session.get(Project, project_id)
    rating = request.form.get('rating', type=int)

    if not project or project.user_id != session['user_id'] or project.status != 'DELIVERED':
        flash('Cannot rate this project.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    if project.user_rating is not None:
        flash('You have already rated this project.', 'warning')
        return redirect(url_for('user_dashboard'))

    if 1 <= rating <= 5:
        project.user_rating = rating
        db.session.commit()

        # Send email (Step 6)
        user = db.session.get(User, project.user_id)
        send_email(
            subject=f'New Rating Received for Project ID: {project_id}',
            recipients=[ADMIN_EMAIL],
            body=f'User {user.email} has rated Project ID: {project_id} with {rating} stars.'
        )

        flash(f'Thank you for rating Project ID {project_id} with {rating} stars!', 'success')
    else:
        flash('Invalid rating value. Must be between 1 and 5.', 'danger')

    return redirect(url_for('user_dashboard'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    projects = Project.query.order_by(Project.id.desc()).all()
    return render_template('admin_dashboard.html', title="Admin Dashboard", projects=projects)

# Route to serve uploaded files securely (e.g., STL files, payment proofs)
@app.route('/uploads/<path:filename>')
@login_required
def download_file(filename):
    # This function should implement logic to check if the current user
    # is authorized to view the file (i.e., they are the project owner or admin).
    # For simplicity, we just check if they are logged in.
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# --- Initialization and Main Run ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Pre-seed Admin User (For initial setup)
        if User.query.filter_by(email=ADMIN_EMAIL).first() is None:
            admin = User(email=ADMIN_EMAIL, is_admin=True)
            admin.set_password('rt3dprintadmin') # Default Admin Password
            db.session.add(admin)
            db.session.commit()
            print(f"\n--- Initial Admin User Created ---")
            print(f"Email: {ADMIN_EMAIL}")
            print(f"Password: rt3dprintadmin\n")
            
    app.run(debug=True)