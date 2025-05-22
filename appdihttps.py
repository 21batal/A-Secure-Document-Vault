# appdi.py - Complete Fixed Version
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import re, os, pyotp, qrcode, io, base64, jwt, stat
from functools import wraps
from sqlalchemy.exc import IntegrityError
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from werkzeug.utils import secure_filename
import OpenSSL
import uuid
import shutil
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

app = Flask(__name__)
app.secret_key = "yourkey"

# Add context processor for templates
@app.context_processor
def inject_user():
    if 'user_id' in session:
        return {'current_user': User.query.get(session['user_id'])}
    return {'current_user': None}

# DB Config with connection pooling
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/"your_db"?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 299,
    'pool_pre_ping': True
}
basedir = os.path.abspath(os.path.dirname(__file__))
# Secure File Upload Config
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.expanduser('~'), 'secure_docs_uploads')
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx', 'txt'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # True in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Default session lifetime
app.config['SESSION_COOKIE_EXPIRES'] = None  # Session expires when browser closes by default
app.config['HMAC_KEY'] = "your-hmac-secret-key"
app.config['PRIVATE_KEY_PATH'] = os.path.join(os.path.expanduser('~'), 'secure_docs_keys/private_key.pem')
app.config['PUBLIC_KEY_PATH'] = os.path.join(os.path.expanduser('~'), 'secure_docs_keys/public_key.pem')
app.config['KEY_FOLDER'] = os.path.join(os.path.expanduser('~'), 'secure_docs_keys')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['UPLOAD_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'uploads')

# OAuth Setup
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Remove in production
os.environ['FLASK_DANCE_DEBUG'] = '1'

github_blueprint = make_github_blueprint(
    client_id='yourid',
    client_secret='yourid',
    redirect_to='github_callback'
)
app.register_blueprint(github_blueprint, url_prefix='/github_login')

google_blueprint = make_google_blueprint(
    client_id='yourid',
    client_secret='yourid',
    redirect_to='google_callback',
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
)
app.register_blueprint(google_blueprint, url_prefix='/google_login')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models (unchanged from original)
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    github_id = db.Column(db.String(128), unique=True, nullable=True)
    google_id = db.Column(db.String(128), unique=True, nullable=True)
    auth_method = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    twofa_secret = db.Column(db.String(32), nullable=True)
    is_twofa_enabled = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False, default=2)
    role = db.relationship('Role', backref='users')
    is_admin_requested = db.Column(db.Boolean, default=False)


    def has_role(self, role_name):
        return self.role.name == role_name

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = db.Column(db.String(45))

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    sha256_hash = db.Column(db.String(64))
    hmac_tag = db.Column(db.String(128))
    signature_path = db.Column(db.String(255))
    is_encrypted = db.Column(db.Boolean, default=True)
    file_size = db.Column(db.Integer)
    encrypted_aes_key = db.Column(db.LargeBinary)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Enhanced Helper Functions
def secure_path(path):
    """Secure path validation that works for all file operations"""
    try:
        if not path:
            raise ValueError("Empty path provided")
            
        # Normalize and get absolute path
        abs_path = os.path.abspath(os.path.normpath(path))
        
        # Check if path is in allowed directories
        allowed_dirs = [
            os.path.abspath(app.config['UPLOAD_FOLDER']),
            os.path.abspath(app.config['KEY_FOLDER'])
        ]
        
        # Verify the path is within allowed directories
        if not any(abs_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
            app.logger.error(f"Path traversal attempt detected: {path}")
            raise ValueError("Invalid file path - not in allowed directory")
            
        return abs_path
    except (TypeError, ValueError, AttributeError) as e:
        app.logger.error(f"Path validation error: {str(e)}")
        raise ValueError("Invalid file path")

def ensure_upload_dir(upload_id):
    """Ensure upload directory exists with secure permissions"""
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], upload_id)
    try:
        os.makedirs(upload_dir, mode=0o700, exist_ok=True)
        return upload_dir
    except OSError as e:
        app.logger.error(f"Failed to create upload directory: {str(e)}")
        raise ValueError("Could not create upload directory")

def validate_file_path(*path_parts):
    try:
        full_path = os.path.join(*path_parts)
        abs_path = os.path.abspath(full_path)
        base_path = os.path.abspath(app.config['UPLOAD_FOLDER'])
        app.logger.info(f"[DEBUG] full_path: {full_path}")
        app.logger.info(f"[DEBUG] abs_path: {abs_path}")
        app.logger.info(f"[DEBUG] base_path: {base_path}")

        if not abs_path.startswith(base_path):
            raise ValueError("Invalid file path")
        return abs_path
    except (TypeError, ValueError) as e:
        app.logger.error(f"Path validation failed: {str(e)}")
        raise ValueError("Invalid file path")


def generate_qr_code(secret, email):
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=email, issuer_name="SecureDocs")
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def role_required(role_names):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = User.query.get(session['user_id'])
            if not user:
                abort(403)
            if isinstance(role_names, str):
                roles = [role_names]
            else:
                roles = role_names
            if user.role.name not in roles and user.role.name != 'Admin':
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return role_required('Admin')(f)

def user_or_admin_required(f):
    return role_required(['User','Admin'])(f)

PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&()_+])[A-Za-z\d!@#$%^&()_+]{8,}$')

def is_valid_password(password):
    return PASSWORD_REGEX.match(password)

def generate_aes_key():
    return os.urandom(32)

def encrypt_file(file_path, key):
    try:
        with open(secure_path(file_path), 'rb') as f:
            data = f.read()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv + encrypted
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_file(encrypted_path, key, output_path):
    try:
        with open(secure_path(encrypted_path), 'rb') as f:
            data = f.read()
        
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        try:
            data = unpadder.update(padded_data) + unpadder.finalize()
        except ValueError as e:
            raise ValueError("Invalid padding (possibly wrong key)")
        
        with open(secure_path(output_path), 'wb') as f:
            f.write(data)
    except Exception as e:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise e

def generate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(secure_path(file_path), 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_hmac(file_path, key):
    h = hmac.new(key.encode(), digestmod=hashlib.sha256)
    with open(secure_path(file_path), 'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()

def secure_path(path):
    """Secure path validation that works for both uploads and key files"""
    try:
        # Normalize and get absolute path
        abs_path = os.path.abspath(os.path.normpath(path))
        
        # Check if path is in allowed directories
        allowed_dirs = [
            os.path.abspath(app.config['UPLOAD_FOLDER']),
            os.path.abspath(app.config['KEY_FOLDER'])
        ]
        
        # Allow if path is in any allowed directory
        if any(abs_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
            return abs_path
            
        raise ValueError("Path not in allowed directories")
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Invalid file path")

def load_private_key():
    key_path = app.config['PRIVATE_KEY_PATH']
    if not os.path.exists(key_path):
        raise FileNotFoundError("Private key is missing. Cannot decrypt documents.")

    try:
        with open(secure_path(key_path), 'rb') as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        app.logger.error(f"Failed to load private key: {str(e)}")
        raise ValueError("Could not load private key")


def load_public_key():
    key_path = app.config['PUBLIC_KEY_PATH']
    if not os.path.exists(key_path):
        raise FileNotFoundError("Public key is missing. Cannot encrypt new documents.")

    try:
        with open(secure_path(key_path), 'rb') as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except Exception as e:
        app.logger.error(f"Failed to load public key: {str(e)}")
        raise ValueError("Could not load public key")


def generate_key_pair():
    key_dir = app.config['KEY_FOLDER']
    private_path = app.config['PRIVATE_KEY_PATH']
    public_path = app.config['PUBLIC_KEY_PATH']
    
    # Create key directory if it doesn't exist
    os.makedirs(key_dir, exist_ok=True, mode=0o700)
    
    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Write private key
    with open(private_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(private_path, 0o600)
    
    # Write public key
    with open(public_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    os.chmod(public_path, 0o644)

def sign_file(file_path, private_key):
    with open(secure_path(file_path), 'rb') as f:
        data = f.read()
    
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(file_path, signature, public_key):
    with open(secure_path(file_path), 'rb') as f:
        data = f.read()
    
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def allowed_file(filename):
    """Enhanced file extension validation"""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_EXTENSIONS']
def is_current_user_admin():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return user and user.role_id == 1
    return False
# Routes (all original routes with enhanced security)
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('logout'))
    
    # Get document stats
    total_docs = Document.query.filter_by(user_id=user.id).count()
    recent_docs = Document.query.filter_by(user_id=user.id).order_by(Document.uploaded_at.desc()).limit(5).all()
    
    return render_template('home.html', 
                         user=user,
                         total_docs=total_docs,
                         recent_docs=recent_docs)
@app.route('/approve_admin/<int:user_id>')
def approve_admin(user_id):
    if not is_current_user_admin():
        abort(403)

    user = User.query.get_or_404(user_id)
    admin_role = Role.query.filter_by(name='admin').first()
    if admin_role:
        user.role_id = admin_role.id
        user.is_admin_requested = False
        db.session.commit()
        flash(f"{user.username} has been promoted to admin.", "success")

    return redirect(url_for('admin_dashboard'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        requested_role_id = int(request.form.get('role', 2))  # 'admin' might be 1, 'user' is 2
        
        if not is_valid_password(password):
            flash("Password must be secure.", 'danger')
            return redirect(url_for('signup'))

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash("Email or username already exists.", 'danger')
            return redirect(url_for('signup'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Enforce new users are added as regular users unless approved later
        user_role_id = 2  # Force 'user' role
        is_admin_requested = (requested_role_id == 1)  # Assuming 1 = admin

        if is_admin_requested:
            flash("Your request to become an admin has been sent. Until approved, you are assigned as a regular user.", 'info')
        else:
            flash("Signup successful. Please login.", 'success')

        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            auth_method='manual',
            role_id=user_role_id,
            is_admin_requested=is_admin_requested
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash("Error creating account.", 'danger')

    roles = Role.query.all()
    return render_template('signup.html', roles=roles)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(email=email, auth_method='manual').first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['pre_2fa_user_id'] = user.id
            session['username'] = user.username
            session['temp_2fa_secret'] = pyotp.random_base32()
            
            # Set session expiration based on remember me
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)  # 30 days
            else:
                session.permanent = False
                app.permanent_session_lifetime = timedelta(minutes=30)  # 30 minutes
            
            db.session.add(LoginLog(user_id=user.id, ip_address=request.remote_addr))
            db.session.commit()
            return redirect(url_for('verify_2fa'))
        flash("Invalid credentials.", 'danger')
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user.twofa_secret:
        return redirect(url_for('setup_2fa'))

    if request.method == 'POST':
        otp = request.form['otp']
        if pyotp.TOTP(user.twofa_secret).verify(otp):
            session['user_id'] = user.id
            session.pop('pre_2fa_user_id', None)
            flash('2FA verification successful', 'success')
            return redirect(url_for('home'))
        flash('Invalid 2FA code', 'danger')

    qr_base64 = generate_qr_code(user.twofa_secret, user.email)
    return render_template('verify_2fa.html', qr_code=qr_base64, user=user)

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user.twofa_secret:
        user.twofa_secret = pyotp.random_base32()
        db.session.commit()

    qr_base64 = generate_qr_code(user.twofa_secret, user.email)

    if request.method == 'POST':
        otp = request.form['otp']
        if pyotp.TOTP(user.twofa_secret).verify(otp):
            user.is_twofa_enabled = True
            db.session.commit()
            session['user_id'] = user.id
            session.pop('pre_2fa_user_id', None)
            flash("2FA setup complete", "success")
            return redirect(url_for('home'))
        flash("Invalid OTP", "danger")

    return render_template('setup_2fa.html', 
                         qr_code=qr_base64,
                         secret=user.twofa_secret)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    documents = Document.query.all()
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(50).all()
    
    # Pending admin requests (assuming role_id = 2 is user)
    pending_admin_requests = User.query.filter_by(is_admin_requested=True, role_id=2).all()

    return render_template('admin_dashboard.html',
                           users=users,
                           documents=documents,
                           logs=logs,
                           user=User.query.get(session['user_id']),
                           pending_admin_requests=pending_admin_requests)



@app.route('/admin/users/<int:user_id>/promote', methods=['POST'])
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    admin_role = Role.query.filter_by(name='Admin').first()
    if not admin_role:
        abort(500)
    user.role_id = admin_role.id
    db.session.commit()
    flash(f'{user.username} has been promoted to Admin', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/<int:user_id>/demote', methods=['POST'])
@admin_required
def demote_user(user_id):
    if session['user_id'] == user_id:
        flash('You cannot demote your own account role', 'danger')
        return redirect(url_for('admin_dashboard'))
    user = User.query.get_or_404(user_id)
    user_role = Role.query.filter_by(name='User').first()
    if not user_role:
        abort(500)
    user.role_id = user_role.id
    db.session.commit()
    flash(f'{user.username} has been demoted to User', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    if session['user_id'] == user_id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_dashboard'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        new_role_id = request.form.get('role_id')
        if new_role_id:
            user.role_id = int(new_role_id)

        new_password = request.form.get('password')
        if new_password:
            if is_valid_password(new_password):
                user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            else:
                flash('Password does not meet requirements', 'danger')

        try:
            db.session.commit()
            flash(f'User {user.username} updated!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {e}', 'error')

    roles = Role.query.all()
    return render_template('admin_edit_user.html', user=user, roles=roles)

@app.route('/admin/logs')
@admin_required
def admin_logs():
    login_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_logs.html', login_logs=login_logs, audit_logs=audit_logs)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/activity')
def activity():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('activity.html', username=session.get('username'))

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('settings.html', 
                         username=session.get('username'),
                         user=user)

@app.route('/auth/github/callback')
def github_callback():
    try:
        if not github.authorized:
            flash("GitHub authorization failed.", 'danger')
            return redirect(url_for('login'))

        resp = github.get('/user')
        if not resp.ok:
            flash("Failed to fetch GitHub user info.", 'danger')
            return redirect(url_for('login'))

        github_info = resp.json()
        github_id = str(github_info['id'])
        username = github_info.get('login')
        email = github_info.get('email') or f"{github_id}@github.com"

        user = User.query.filter_by(github_id=github_id).first()
        if not user:
            existing = User.query.filter_by(email=email, auth_method='manual').first()
            if existing:
                flash("Email already registered with manual login.", 'danger')
                return redirect(url_for('login'))

            user = User(
                username=username,
                email=email,
                github_id=github_id,
                auth_method='github'
            )
            db.session.add(user)
            db.session.commit()

        db.session.add(LoginLog(
            user_id=user.id,
            ip_address=request.remote_addr
        ))
        db.session.commit()

        session['user_id'] = user.id
        session['username'] = user.username
        session.permanent = True  

        flash("Login successful.", 'success')
        return redirect(url_for('home'))

    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred during GitHub login: {str(e)}", 'danger')
        return redirect(url_for('login'))
    
@app.route("/auth/google/callback")
def google_callback():
    if not google.authorized:
        flash("Google authorization failed.", 'danger')
        return redirect(url_for("login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch Google user info.", 'danger')
        return redirect(url_for("login"))
    
    google_info = resp.json()
    google_id = str(google_info['id'])
    username = google_info.get('login') or google_info.get('name')
    email = google_info.get('email') or f"{google_id}@google.com"

    user = User.query.filter_by(email=email).first() or User.query.filter_by(google_id=google_id).first()

    if not user:
        user = User(
            username=username,
            email=email,
            google_id=google_id,
            auth_method="google"
        )
        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("The email or username is already taken. Please use another one.", 'danger')
            return redirect(url_for("login"))

    db.session.add(LoginLog(
        user_id=user.id,
        ip_address=request.remote_addr
    ))
    db.session.commit()

    session['user_id'] = user.id
    session['username'] = user.username
    session.permanent = True  

    flash("Login via Google successful!", 'success')
    return redirect(url_for("home"))

@app.route('/documents')
@user_or_admin_required
def documents():
    user = User.query.get(session['user_id'])
    documents = Document.query.filter_by(user_id=user.id).all()
    return render_template('documents.html', documents=documents, user=user)


@app.route('/documents/upload', methods=['GET', 'POST'])
@user_or_admin_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            original_filename = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{unique_id}_{original_filename}")
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], f"enc_{unique_id}_{original_filename}")
            final_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{original_filename}")
            
            # Save original file temporarily
            file.save(temp_path)
            
            # Generate AES key and encrypt it with RSA public key
            aes_key = generate_aes_key()
            public_key = load_public_key()
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            assert len(encrypted_aes_key) == 256
            # Load private key for signing
            private_key = load_private_key()
            
            # Generate hashes & signatures
            file_hash = generate_sha256(temp_path)
            hmac_tag = generate_hmac(temp_path, app.config['HMAC_KEY'])
            signature = sign_file(temp_path, private_key)
            
            signature_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{original_filename}.sig")
            with open(signature_path, 'wb') as f:
                f.write(signature)
            
            # Encrypt file with AES key
            encrypted_data = encrypt_file(temp_path, aes_key)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Rename encrypted file to final path
            os.rename(encrypted_path, final_path)
            file_size = os.path.getsize(final_path)
            
            # Create DB record with encrypted AES key
            document = Document(
                user_id=session['user_id'],
                filename=original_filename,
                storage_path=final_path,
                sha256_hash=file_hash,
                hmac_tag=hmac_tag,
                signature_path=signature_path,
                is_encrypted=True,
                file_size=file_size,
                encrypted_aes_key=encrypted_aes_key
            )
            db.session.add(document)
            db.session.commit()
            
            # Clean up temp file
            os.remove(temp_path)
            
            flash('Document uploaded and secured successfully!', 'success')
            return redirect(url_for('documents'))
        
        flash('Invalid file type', 'danger')
    
    return render_template('upload.html')



# Fixed Download Route
@app.route('/documents/download/<int:doc_id>')
@user_or_admin_required
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    current_user = User.query.get(session['user_id'])

    if document.user_id != session['user_id'] and not current_user.has_role('Admin'):
        abort(403)
    
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    temp_path = os.path.join(temp_dir, document.filename)

    try:
        # Load private key with better error handling
        try:
            private_key = load_private_key()
            app.logger.info(f"Private key loaded successfully for document {doc_id}")
        except Exception as e:
            app.logger.error(f"Failed to load private key: {str(e)}")
            raise ValueError("System error: Could not load decryption keys")

        # Verify encrypted_aes_key exists and is proper length
        if not document.encrypted_aes_key or len(document.encrypted_aes_key) != 256:
            app.logger.error(f"Invalid encrypted AES key for document {doc_id}")
            raise ValueError("Document encryption key is invalid or missing")

        # Decrypt the AES key
        try:
            aes_key = private_key.decrypt(
                document.encrypted_aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if len(aes_key) != 32:  # AES-256 key should be 32 bytes
                raise ValueError("Decrypted key has incorrect length")
        except Exception as e:
            app.logger.error(f"AES key decryption failed: {str(e)}")
            raise ValueError("Failed to decrypt document key. The document may be corrupted.")

        # Rest of the decryption and verification flow remains the same...
        # [Keep the existing code for file decryption and verification]
        
        # Decrypt the file with the retrieved AES key
        try:
            decrypt_file(document.storage_path, aes_key, temp_path)
        except ValueError as e:
            if "Invalid padding" in str(e):
                raise ValueError("Document decryption failed. The document may be corrupted or the key is invalid.")
            raise
        
        # Verify integrity
        try:
            current_hmac = generate_hmac(temp_path, app.config['HMAC_KEY'])
            if current_hmac != document.hmac_tag:
                os.remove(temp_path)
                raise ValueError("Document integrity check failed. The document may have been tampered with.")
        except Exception as e:
            app.logger.error(f"HMAC verification failed: {str(e)}")
            raise ValueError("Document integrity verification failed.")
        
        # Verify signature
        try:
            public_key = load_public_key()
            with open(document.signature_path, 'rb') as f:
                signature = f.read()
            
            if not verify_signature(temp_path, signature, public_key):
                os.remove(temp_path)
                raise ValueError("Document signature verification failed. The document may have been modified.")
        except Exception as e:
            app.logger.error(f"Signature verification failed: {str(e)}")
            raise ValueError("Document signature verification failed.")
        
        # Verify hash
        try:
            current_hash = generate_sha256(temp_path)
            if current_hash != document.sha256_hash:
                os.remove(temp_path)
                raise ValueError("Document hash verification failed. The document may be corrupted.")
        except Exception as e:
            app.logger.error(f"Hash verification failed: {str(e)}")
            raise ValueError("Document hash verification failed.")
        
        # Log the download
        db.session.add(AuditLog(
            user_id=session['user_id'],
            action=f"Downloaded document: {document.filename}",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        ))
        db.session.commit()
        app.logger.info(f"[DEBUG] Sending file: {temp_path}")
        
        app.logger.info(f"[DEBUG] Original Encrypted Path: {document.storage_path}")


        # Send file to user
        response = send_file(temp_path, as_attachment=True, download_name=document.filename)
        
        # Cleanup temp file after sending
        @response.call_on_close
        def remove_temp_file():
            try:
                os.remove(temp_path)
            except Exception:
                pass
        
        return response
    
    except ValueError as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        app.logger.error(f"Document download error: {str(e)}")
        return jsonify({
            'error': True,
            'message': str(e)
        }), 500
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        app.logger.error(f"Unexpected error during document download: {str(e)}")
        return jsonify({
            'error': True,
            'message': "An unexpected error occurred while processing your document."
        }), 500

@app.route('/profile', methods=['GET', 'POST'])
@user_or_admin_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        try:
            db.session.commit()
            flash('Profile updated!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {e}', 'error')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['POST'])
@user_or_admin_required
def change_password():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login first', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or user.auth_method != 'manual':
        flash('Password change not available', 'danger')
        return redirect(url_for('settings'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not bcrypt.check_password_hash(user.password_hash, current_password):
        flash('Current password incorrect', 'danger')
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('settings'))

    if not is_valid_password(new_password):
        flash('Password too weak (8+ chars, mixed case, special chars)', 'danger')
        return redirect(url_for('settings'))

    try:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Password updated!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error changing password: {e}', 'error')

    return redirect(url_for('settings'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

def generate_ssl_cert():
    cert_path = os.path.join(app.config['KEY_FOLDER'], 'cert.pem')
    key_path = os.path.join(app.config['KEY_FOLDER'], 'key.pem')
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        os.makedirs(app.config['KEY_FOLDER'], exist_ok=True, mode=0o700)
        
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        cert = OpenSSL.crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        with open(cert_path, 'wb') as f:
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        os.chmod(cert_path, 0o644)
        
        with open(key_path, 'wb') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        os.chmod(key_path, 0o600)

@app.route('/documents/delete/<int:doc_id>', methods=['POST'])
@user_or_admin_required
def delete_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    current_user = User.query.get(session['user_id'])
    
    if document.user_id != session['user_id'] and not current_user.has_role('Admin'):
        abort(403)
    
    try:
        # Delete physical files
        if os.path.exists(document.storage_path):
            os.remove(document.storage_path)
        if os.path.exists(document.signature_path):
            os.remove(document.signature_path)
            
        # Delete from database
        db.session.delete(document)
        db.session.commit()
        
        flash('Document deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting document: {str(e)}', 'danger')
    
    return redirect(url_for('documents'))

@app.route('/documents/verify/<int:doc_id>')
@user_or_admin_required
def verify_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    current_user = User.query.get(session['user_id'])
    
    if document.user_id != session['user_id'] and not current_user.has_role('Admin'):
        abort(403)
    
    try:
        # Verify HMAC
        current_hmac = generate_hmac(document.storage_path, app.config['HMAC_KEY'])
        hmac_valid = current_hmac == document.hmac_tag
        
        # Verify signature
        public_key = load_public_key()
        with open(document.signature_path, 'rb') as f:
            signature = f.read()
        signature_valid = verify_signature(document.storage_path, signature, public_key)
        
        # Verify hash
        current_hash = generate_sha256(document.storage_path)
        hash_valid = current_hash == document.sha256_hash
        
        # Log verification attempt
        db.session.add(AuditLog(
            user_id=session['user_id'],
            action=f"Verified document: {document.filename}",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        ))
        db.session.commit()
        
        return jsonify({
            'success': True,
            'hmac_valid': hmac_valid,
            'signature_valid': signature_valid,
            'hash_valid': hash_valid,
            'message': 'Document verification complete'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error verifying document: {str(e)}'
        }), 500

@app.route('/admin/suspicious_activity')
@admin_required
def suspicious_activity():
    # Get failed login attempts
    failed_logins = LoginLog.query.filter(
        LoginLog.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
    ).order_by(LoginLog.timestamp.desc()).all()
    
    # Get multiple uploads from same IP
    suspicious_uploads = db.session.query(
        Document, AuditLog
    ).join(
        AuditLog, Document.id == AuditLog.id
    ).filter(
        AuditLog.action.like('%Uploaded document%'),
        AuditLog.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
    ).order_by(AuditLog.timestamp.desc()).all()
    
    return render_template('suspicious_activity.html',
                         failed_logins=failed_logins,
                         suspicious_uploads=suspicious_uploads)

def regenerate_key_pair():
    """Regenerate RSA key pair with additional safety checks"""
    key_dir = app.config['KEY_FOLDER']
    private_path = app.config['PRIVATE_KEY_PATH']
    public_path = app.config['PUBLIC_KEY_PATH']
    
    # Verify directory exists and has correct permissions
    if not os.path.exists(key_dir):
        os.makedirs(key_dir, mode=0o700)
    else:
        if (os.stat(key_dir).st_mode & 0o777) != 0o700:
            os.chmod(key_dir, 0o700)
    
    # [Rest of the existing regeneration code...]
    
    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Write private key
    with open(private_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(private_path, 0o600)
    
    # Write public key
    with open(public_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    os.chmod(public_path, 0o644)
    
    return private_key, public_key

# Initialize keys on startup
with app.app_context():
    try:
        private_key = load_private_key()
        public_key = load_public_key()
    except Exception as e:
        app.logger.critical(f"Key loading failed: {str(e)}")
        raise SystemExit("❌ RSA keys missing or corrupted. Fix before running the server.")


if __name__ == '__main__':
    # Create directories with secure permissions
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True, mode=0o755)
    os.makedirs(app.config['KEY_FOLDER'], exist_ok=True, mode=0o700)
    
    with app.app_context():
        try:
            db.create_all()
            generate_key_pair()
            generate_ssl_cert()
            if not Role.query.first():
                db.session.add_all([Role(name='Admin'), Role(name='User')])
                db.session.commit()
        except Exception as e:
            print(f"Startup error: {str(e)}")
            raise

    # Run with SSL
    ssl_context = (
        os.path.join(app.config['KEY_FOLDER'], 'cert.pem'),
        os.path.join(app.config['KEY_FOLDER'], 'key.pem')
    )
    app.run(
        debug=True,
        ssl_context=ssl_context,
        host='0.0.0.0',
        port="what ever you prefer"
    )
