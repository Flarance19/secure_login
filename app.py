"""
SecureVault — Secure Login System
==================================
Features:
  - Bcrypt password hashing (cost factor 12)
  - SQLAlchemy ORM (prevents SQL injection)
  - Input validation & sanitization
  - Secure session management
  - Rate limiting (brute-force protection)
  - TOTP-based 2FA (Google Authenticator compatible)
  - CSRF protection
  - Account lockout after failed attempts
  - Secure HTTP headers
"""

import os
import re
import time
import secrets
import pyotp
import qrcode
import io, base64
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, abort)
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI='sqlite:///securevault.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,   # Set True in production with HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

db     = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ─── Rate Limiter (in-memory) ─────────────────────────────────────────────────

login_attempts = defaultdict(list)   # ip -> [timestamps]
MAX_ATTEMPTS   = 5
WINDOW_SECONDS = 300   # 5 minutes

def is_rate_limited(ip):
    now = time.time()
    attempts = [t for t in login_attempts[ip] if now - t < WINDOW_SECONDS]
    login_attempts[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def record_attempt(ip):
    login_attempts[ip].append(time.time())

def clear_attempts(ip):
    login_attempts[ip] = []

# ─── Models ───────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'

    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(32), unique=True, nullable=False)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password_hash   = db.Column(db.String(128), nullable=False)
    totp_secret     = db.Column(db.String(32), nullable=True)
    two_fa_enabled  = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    last_login      = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(
            password, rounds=12).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def lock_account(self, minutes=15):
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        self.failed_attempts = 0

    def generate_totp_secret(self):
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def verify_totp(self, code):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=1)

    def get_totp_uri(self):
        return pyotp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email, issuer_name='SecureVault')

# ─── Validation ───────────────────────────────────────────────────────────────

def validate_username(u):
    if not u or len(u) < 3 or len(u) > 32:
        return 'Username must be 3–32 characters.'
    if not re.match(r'^[a-zA-Z0-9_]+$', u):
        return 'Username may only contain letters, numbers, and underscores.'
    return None

def validate_email(e):
    if not e or len(e) > 120:
        return 'Invalid email address.'
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', e):
        return 'Invalid email address.'
    return None

def validate_password(p):
    if not p or len(p) < 8:
        return 'Password must be at least 8 characters.'
    if len(p) > 128:
        return 'Password too long.'
    if not re.search(r'[A-Z]', p):
        return 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', p):
        return 'Password must contain at least one lowercase letter.'
    if not re.search(r'\d', p):
        return 'Password must contain at least one digit.'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', p):
        return 'Password must contain at least one special character.'
    return None

def sanitize(text):
    """Strip dangerous characters — defense in depth."""
    if not text:
        return ''
    return re.sub(r'[<>\'"`;]', '', str(text).strip())

# ─── Decorators ───────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['X-XSS-Protection']        = '1; mode=block'
    response.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy']  = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response

app.after_request(add_security_headers)

# ─── CSRF ─────────────────────────────────────────────────────────────────────

def generate_csrf():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']

def check_csrf():
    token = request.form.get('_csrf')
    if not token or token != session.get('_csrf'):
        abort(403)

app.jinja_env.globals['csrf_token'] = generate_csrf

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ── Register ──

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        check_csrf()

        username = sanitize(request.form.get('username', ''))
        email    = sanitize(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        # Validate
        err = validate_username(username)
        if err: flash(err, 'error'); return render_template('register.html')

        err = validate_email(email)
        if err: flash(err, 'error'); return render_template('register.html')

        err = validate_password(password)
        if err: flash(err, 'error'); return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        # Uniqueness check (via ORM — no raw SQL)
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# ── Login ──

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        check_csrf()
        ip = request.remote_addr

        if is_rate_limited(ip):
            flash('Too many login attempts. Please wait 5 minutes.', 'error')
            return render_template('login.html')

        username = sanitize(request.form.get('username', ''))
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        # Check account lock
        if user and user.is_locked():
            flash('Account locked due to repeated failures. Try again later.', 'error')
            return render_template('login.html')

        # Verify credentials
        if not user or not user.check_password(password):
            record_attempt(ip)
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.lock_account(minutes=15)
                    flash('Account locked for 15 minutes due to too many failures.', 'error')
                else:
                    flash(f'Invalid credentials. {5 - user.failed_attempts} attempts remaining.', 'error')
                db.session.commit()
            else:
                flash('Invalid credentials.', 'error')
            return render_template('login.html')

        # Reset failures on success
        user.failed_attempts = 0
        user.locked_until = None

        # 2FA check
        if user.two_fa_enabled:
            session['_2fa_user_id'] = user.id
            session['_2fa_ts']      = time.time()
            db.session.commit()
            return redirect(url_for('verify_2fa'))

        # Full login
        session.permanent = True
        session['user_id']   = user.id
        session['username']  = user.username
        user.last_login = datetime.utcnow()
        db.session.commit()
        clear_attempts(ip)

        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

# ── 2FA Verify ──

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    uid = session.get('_2fa_user_id')
    ts  = session.get('_2fa_ts', 0)

    if not uid or time.time() - ts > 300:
        session.pop('_2fa_user_id', None)
        session.pop('_2fa_ts', None)
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        check_csrf()
        code = request.form.get('code', '').strip()
        user = User.query.get(uid)

        if user and user.verify_totp(code):
            session.pop('_2fa_user_id', None)
            session.pop('_2fa_ts', None)
            session.permanent = True
            session['user_id']  = user.id
            session['username'] = user.username
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code. Please try again.', 'error')

    return render_template('verify_2fa.html')

# ── Dashboard ──

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

# ── Setup 2FA ──

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        check_csrf()
        action = request.form.get('action')

        if action == 'enable':
            code = request.form.get('code', '').strip()
            if user.verify_totp(code):
                user.two_fa_enabled = True
                db.session.commit()
                flash('Two-Factor Authentication enabled!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid code. Please scan the QR code and try again.', 'error')

        elif action == 'disable':
            user.two_fa_enabled = False
            user.totp_secret    = None
            db.session.commit()
            flash('Two-Factor Authentication disabled.', 'info')
            return redirect(url_for('dashboard'))

    # Generate new secret for setup
    if not user.totp_secret:
        user.generate_totp_secret()
        db.session.commit()

    # QR code
    uri = user.get_totp_uri()
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template('setup_2fa.html', user=user, qr_b64=qr_b64)

# ── Logout ──

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('login'))

# ── Security Info API ──

@app.route('/api/security-info')
@login_required
def security_info():
    user = User.query.get(session['user_id'])
    return jsonify({
        'username':       user.username,
        'email':          user.email,
        'two_fa_enabled': user.two_fa_enabled,
        'last_login':     user.last_login.isoformat() if user.last_login else None,
        'created_at':     user.created_at.isoformat(),
    })

# ─── Init & Run ───────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    print("\n🔐 SecureVault running at http://127.0.0.1:5000\n")
    app.run(debug=False, host='127.0.0.1', port=5000)
