# 🔐 SecureVault — Secure Login System

A production-ready secure login web application built with Flask.

## Security Features

| Feature | Implementation |
|---|---|
| Password Hashing | Bcrypt (cost factor 12) |
| SQL Injection Prevention | SQLAlchemy ORM (parameterized queries) |
| CSRF Protection | Custom token per session |
| Session Management | Flask sessions (30-min timeout, HttpOnly cookies) |
| Rate Limiting | 5 attempts per 5 minutes per IP |
| Account Lockout | 15-minute lockout after 5 failed logins |
| 2FA (Optional) | TOTP via Google Authenticator (RFC 6238) |
| Input Validation | Regex + length limits on all fields |
| Security Headers | CSP, X-Frame-Options, X-XSS-Protection, etc. |
| Password Strength | Enforced: uppercase + lowercase + digit + symbol |

## Project Structure

```
secure_login/
├── app.py                  ← Main Flask application
├── requirements.txt        ← Python dependencies
├── README.md
└── templates/
    ├── base.html           ← Shared layout + nav + flash messages
    ├── login.html          ← Login page
    ├── register.html       ← Registration with password strength meter
    ├── dashboard.html      ← Security dashboard
    ├── verify_2fa.html     ← 2FA code entry
    └── setup_2fa.html      ← 2FA QR code setup
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python app.py

# 3. Open in browser
http://127.0.0.1:5000
```

## Setting up 2FA

1. Register and log in
2. Go to Dashboard → **Enable 2FA**
3. Scan the QR code with Google Authenticator or Authy
4. Enter the 6-digit code to confirm
5. All future logins will require the code

## Environment Variables

```bash
# Set a strong secret key in production
export SECRET_KEY="your-random-64-char-hex-string"
```

## Production Checklist

- [ ] Set `SESSION_COOKIE_SECURE=True` (requires HTTPS)
- [ ] Use PostgreSQL instead of SQLite
- [ ] Set `SECRET_KEY` from environment variable
- [ ] Enable HTTPS with a valid TLS certificate
- [ ] Use a production WSGI server (gunicorn, uWSGI)
- [ ] Set `DEBUG=False`
