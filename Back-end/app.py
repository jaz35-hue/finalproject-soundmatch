from dotenv import load_dotenv
load_dotenv()
import os
import shutil
import re
from datetime import datetime, timedelta
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from flask import Flask, render_template, url_for, redirect, flash, request
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email, Regexp, EqualTo
from flask_bcrypt import Bcrypt

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = (BASE_DIR.parent / "templates-front-end").resolve()
STATIC_DIR = FRONTEND_DIR / "static"
INSTANCE_DIR = BASE_DIR / "instance"

# Ensure expected directories exist so deployments work out of the box
FRONTEND_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(FRONTEND_DIR),
    static_folder=str(STATIC_DIR),
)

# SECRET_KEY must be set via environment variable for security
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    # Generate a warning in development, but fail in production
    if os.environ.get('PRODUCTION', '').lower() in ('true', '1', 'yes'):
        raise ValueError("SECRET_KEY environment variable is required in production!")
    else:
        # Development fallback (NOT SECURE - only for local dev)
        import secrets
        app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
        print("⚠️  WARNING: Using auto-generated SECRET_KEY. Set SECRET_KEY environment variable for production!")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress deprecation warning
db_path = BASE_DIR / 'database.db'

app.config.update(
    MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME'),
)

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# If an `instance/database.db` exists (from previous runs), copy it locally
# so the app will continue using the same data. Only copy when the root DB is missing.
instance_db_path = INSTANCE_DIR / 'database.db'
if not db_path.exists() and instance_db_path.exists():
    try:
        shutil.copy2(instance_db_path, db_path)
    except Exception:
        # ignore copy errors; DB creation will proceed later
        pass

# Database configuration - supports both SQLite (dev) and PostgreSQL (production)
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # PostgreSQL (production) - Render provides DATABASE_URL
    # SQLAlchemy needs postgresql:// (not postgres://)
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    # Check if psycopg2 is available (for PostgreSQL)
    try:
        import psycopg2
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print("Using PostgreSQL database (production)")
    except ImportError:
        print("⚠️  WARNING: DATABASE_URL set but psycopg2-binary not installed!")
        print("⚠️  Falling back to SQLite. Install psycopg2-binary for PostgreSQL support.")
        print("⚠️  Run: pip install psycopg2-binary --only-binary :all:")
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
else:
    # SQLite (local development)
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
    print(f"Using SQLite database (development): {db_path}")

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Setup Flask-Limiter for rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Use Redis in production: os.environ.get('REDIS_URL', 'memory://')
    strategy="fixed-window"
)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    """User model with secure email verification and account lockout."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)  # Increased for bcrypt hashes
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verify_token = db.Column(db.String(255), nullable=True, index=True)
    token_created_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Account lockout fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    account_locked = db.Column(db.Boolean, default=False, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Password reset fields
    reset_token = db.Column(db.String(255), nullable=True, index=True)
    reset_token_created_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def is_account_locked(self):
        """Check if account is currently locked."""
        if not self.account_locked:
            return False
        if self.locked_until and datetime.utcnow() > self.locked_until:
            # Lock expired, unlock account
            self.account_locked = False
            self.locked_until = None
            self.failed_login_attempts = 0
            db.session.commit()
            return False
        return True
    
    def increment_failed_login(self, max_attempts=5, lockout_duration_minutes=30):
        """Increment failed login attempts and lock account if threshold reached."""
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= max_attempts:
            self.account_locked = True
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_duration_minutes)
            print(f"Account {self.username} locked until {self.locked_until}")
        
        db.session.commit()
    
    def reset_failed_login_attempts(self):
        """Reset failed login attempts on successful login."""
        if self.failed_login_attempts > 0:
            self.failed_login_attempts = 0
            db.session.commit()


def check_and_update_schema():
    """Check if database schema is up to date and recreate if needed."""
    with app.app_context():
        # Skip automatic schema updates for PostgreSQL (use migrations instead)
        database_url = os.environ.get('DATABASE_URL', '')
        if database_url and 'postgresql' in database_url:
            print("PostgreSQL detected - skipping automatic schema update.")
            print("Use Flask-Migrate for schema changes in production.")
            # Just ensure tables exist
            db.create_all()
            return True
        
        from sqlalchemy import inspect, text
        
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'user' in tables:
            # Check existing columns
            columns = [col['name'] for col in inspector.get_columns('user')]
            print(f"Existing columns in user table: {columns}")
            
            # Required columns for current schema
            required_columns = {
                'id', 'username', 'email', 'password', 'is_verified', 'verify_token', 
                'token_created_at', 'created_at', 'last_login', 'failed_login_attempts', 
                'account_locked', 'locked_until', 'reset_token', 'reset_token_created_at'
            }
            existing_columns = set(columns)
            
            # Check if all required columns exist
            missing_columns = required_columns - existing_columns
            
            if missing_columns:
                print(f"Missing columns detected: {missing_columns}")
                print("Recreating database with updated schema...")
                
                # Drop and recreate the table
                try:
                    db.drop_all()
                    db.create_all()
                    print("Database schema updated successfully!")
                    return True
                except Exception as e:
                    print(f"Error recreating tables: {str(e)}")
                    return False
            else:
                print("Database schema is up to date.")
                return True
        return True


def init_db():
    """Initialize the database and create all tables."""
    with app.app_context():
        # First, try to update schema if table exists
        schema_updated = check_and_update_schema()
        
        # Create all tables (will only create if they don't exist)
        db.create_all()
        
        if not schema_updated:
            # If schema update failed, drop and recreate
            print("Schema update failed. Dropping and recreating tables...")
            db.drop_all()
            db.create_all()
            print("Database tables recreated successfully!")
        else:
            print("Database tables created/updated successfully!")


class RegisterForm(FlaskForm):
    """Secure registration form with comprehensive validation."""
    username = StringField(
        validators=[
            InputRequired(message="Username is required."),
            Length(min=4, max=20, message="Username must be between 4 and 20 characters."),
            Regexp('^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores.")
        ],
        render_kw={"placeholder": "Username (4-20 characters)", "autocomplete": "username"}
    )
    email = EmailField(
        validators=[
            InputRequired(message="Email is required."),
            Email(message="Please enter a valid email address.")
        ],
        render_kw={"placeholder": "Email address", "autocomplete": "email"}
    )
    password = PasswordField(
        validators=[
            InputRequired(message="Password is required."),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters."),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character."
            )
        ],
        render_kw={"placeholder": "Password (min 8 characters)", "autocomplete": "new-password"}
    )
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        """Validate username uniqueness and format."""
        if not username.data:
            return
        
        username.data = username.data.strip()
        
        # Check for reserved usernames
        reserved = ['admin', 'administrator', 'root', 'system', 'support', 'help', 'info']
        if username.data.lower() in reserved:
            raise ValidationError("This username is reserved. Please choose another.")
        
        try:
            existing_user = User.query.filter_by(username=username.data).first()
            if existing_user:
                raise ValidationError("This username is already taken. Please choose another.")
        except Exception as e:
            print(f"Error validating username: {str(e)}")
            # Don't block registration on validation errors, but log them

    def validate_email(self, email):
        """Validate email uniqueness and format."""
        if not email.data:
            return
        
        email.data = email.data.lower().strip()
        
        # Additional email format validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email.data):
            raise ValidationError("Please enter a valid email address.")
        
        try:
            existing_email = User.query.filter_by(email=email.data).first()
            if existing_email:
                raise ValidationError("This email is already registered. Please use a different email or try logging in.")
        except Exception as e:
            print(f"Error validating email: {str(e)}")
    
    def validate_password(self, password):
        """Additional password strength validation."""
        if not password.data:
            return
        
        # Check for common weak passwords
        weak_passwords = ['password', '12345678', 'qwerty', 'abc123', 'password123', 'admin123']
        if password.data.lower() in weak_passwords:
            raise ValidationError("This password is too common. Please choose a stronger password.")
        
        # Check for username in password (if username field exists and has data)
        try:
            username_field = getattr(self, 'username', None)
            if username_field and username_field.data:
                if username_field.data.lower() in password.data.lower():
                    raise ValidationError("Password cannot contain your username.")
        except AttributeError:
            pass  # Username field not available yet


def generate_verification_token(user):
    """Generate a secure verification token for the user."""
    # Include user ID and timestamp for additional security
    payload = {
        'email': user.email,
        'user_id': user.id,
        'timestamp': datetime.utcnow().isoformat()
    }
    token = serializer.dumps(payload, salt='email-verify')
    return token


def send_verification_email(user, resend=False):
    """
    Send verification email to user with secure token.
    
    Args:
        user: User object to send email to
        resend: Boolean indicating if this is a resend request
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Check if mail is configured first
        mail_username = app.config.get('MAIL_USERNAME')
        mail_password = app.config.get('MAIL_PASSWORD')
        
        if not mail_username or not mail_password:
            print("Warning: Email not configured. MAIL_USERNAME or MAIL_PASSWORD missing.")
            return False, "Email service is not configured. Please contact support."

        # Generate secure token
        token = generate_verification_token(user)
        user.verify_token = token
        user.token_created_at = datetime.utcnow()
        db.session.commit()

        # Create verification URL
        try:
            verify_url = url_for('verify_email', token=token, _external=True)
        except RuntimeError:
            # Fallback if not in request context
            with app.app_context():
                verify_url = url_for('verify_email', token=token, _external=True)
        
        # Create email message with HTML support
        subject = "Verify your SoundMatch account" if not resend else "Verify your SoundMatch account - New Link"
        
        # Plain text version
        body_text = f"""Hi {user.username},

{'A new verification link has been generated. ' if resend else ''}Please click the following link to verify your account:

{verify_url}

This link will expire in 1 hour.

If you didn't create this account, please ignore this email.

For security reasons, do not share this link with anyone.

Best regards,
SoundMatch Team"""
        
        # HTML version (basic, can be enhanced)
        body_html = f"""<html>
<body>
    <h2>Welcome to SoundMatch, {user.username}!</h2>
    <p>{'A new verification link has been generated. ' if resend else ''}Please click the button below to verify your account:</p>
    <p><a href="{verify_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Account</a></p>
    <p>Or copy and paste this link into your browser:</p>
    <p><a href="{verify_url}">{verify_url}</a></p>
    <p><strong>This link will expire in 1 hour.</strong></p>
    <p>If you didn't create this account, please ignore this email.</p>
    <hr>
    <p style="color: #666; font-size: 12px;">For security reasons, do not share this link with anyone.</p>
    <p style="color: #666; font-size: 12px;">Best regards,<br>SoundMatch Team</p>
</body>
</html>"""
        
        msg = Message(
            subject=subject,
            recipients=[user.email],
            body=body_text,
            html=body_html
        )
        
        mail.send(msg)
        print(f"Verification email sent to {user.email} (resend: {resend})")
        return True, "Verification email sent successfully!"
        
    except Exception as e:
        print(f"Error sending verification email: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Still save the token even if email fails
        try:
            token = generate_verification_token(user)
            user.verify_token = token
            user.token_created_at = datetime.utcnow()
            db.session.commit()
            print(f"Token saved for user {user.username} despite email failure")
            return False, "Failed to send email, but token was saved. Please contact support."
        except Exception as token_error:
            print(f"Error saving token: {str(token_error)}")
            return False, "Failed to generate verification token. Please try again."



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username", "autocomplete": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password", "autocomplete": "current-password"})
    
    submit = SubmitField("Login")


class ForgotPasswordForm(FlaskForm):
    """Form for requesting password reset."""
    email = EmailField(
        validators=[InputRequired(message="Email is required."), Email(message="Please enter a valid email address.")],
        render_kw={"placeholder": "Email address", "autocomplete": "email"}
    )
    submit = SubmitField("Send Reset Link")


class ResetPasswordForm(FlaskForm):
    """Form for resetting password with token."""
    password = PasswordField(
        validators=[
            InputRequired(message="Password is required."),
            Length(min=8, max=128, message="Password must be between 8 and 128 characters."),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character."
            )
        ],
        render_kw={"placeholder": "New Password", "autocomplete": "new-password"}
    )
    confirm_password = PasswordField(
        validators=[
            InputRequired(message="Please confirm your password."),
            EqualTo('password', message="Passwords must match.")
        ],
        render_kw={"placeholder": "Confirm Password", "autocomplete": "new-password"}
    )
    submit = SubmitField("Reset Password")


class ResendVerificationForm(FlaskForm):
    """Form for resending verification email."""
    email = EmailField(
        validators=[
            InputRequired(message="Email is required."),
            Email(message="Please enter a valid email address.")
        ],
        render_kw={"placeholder": "Email address", "autocomplete": "email"}
    )
    submit = SubmitField("Resend Verification Email")


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID. Returns None if user_id is invalid."""
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None


@app.route('/')
def home():
    return render_template('home.html') 


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit login attempts
def login():
    """Secure user login with email verification check and account lockout."""
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        
        try:
            user = User.query.filter_by(username=username).first()
            
            # Check if account is locked
            if user and user.is_account_locked():
                remaining_time = (user.locked_until - datetime.utcnow()).total_seconds() / 60
                flash(f'Account is temporarily locked due to too many failed login attempts. Please try again in {int(remaining_time)} minutes.', 'danger')
                return render_template('login.html', form=form)
            
            # Check if user exists and password is correct
            if user and bcrypt.check_password_hash(user.password, password):
                # Check if email is verified
                if not user.is_verified:
                    flash('Please verify your email before logging in. Check your inbox for the verification link.', 'warning')
                    flash('Didn\'t receive the email? <a href="' + url_for('resend_verification') + '">Resend verification email</a>', 'info')
                    return render_template('login.html', form=form)
                
                # Reset failed login attempts on successful login
                user.reset_failed_login_attempts()
                
                # Update last login
                user.last_login = datetime.utcnow()
                db.session.commit()
                
                # Log user in
                login_user(user, remember=False)
                
                # Redirect to intended page or dashboard
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                # Increment failed login attempts if user exists
                if user:
                    user.increment_failed_login()
                    if user.is_account_locked():
                        flash('Too many failed login attempts. Your account has been temporarily locked.', 'danger')
                    else:
                        remaining_attempts = 5 - user.failed_login_attempts
                        if remaining_attempts > 0:
                            flash(f'Invalid username or password. {remaining_attempts} attempt(s) remaining.', 'danger')
                        else:
                            flash('Invalid username or password. Account locked.', 'danger')
                else:
                    # Don't reveal if username exists (security best practice)
                    flash('Invalid username or password. Please try again.', 'danger')
        except Exception as e:
            print(f"Login error: {str(e)}")
            import traceback
            traceback.print_exc()
            flash('An error occurred during login. Please try again.', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/check-email')
def check_email():
    """Page shown after registration to remind users to check their email."""
    return render_template('check_email.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit registration to prevent spam
def register():
    """Secure user registration with email verification."""
    form = RegisterForm()

    if form.validate_on_submit():
        try:
            # Normalize and sanitize input
            email = form.email.data.lower().strip()
            username = form.username.data.strip()
            password = form.password.data
            
            # Final duplicate check (defense in depth)
            existing_username = User.query.filter_by(username=username).first()
            if existing_username:
                flash('Username already exists. Please choose a different username.', 'danger')
                form.username.errors.append('Username already exists.')
                return render_template('register.html', form=form)
            
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already registered. Please use a different email or try logging in.', 'danger')
                form.email.errors.append('Email already registered.')
                return render_template('register.html', form=form)
            
            # Hash password with bcrypt (automatically uses secure rounds)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password=hashed_password,
                is_verified=False,
                created_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.commit()
            
            # Send verification email
            email_sent, email_message = send_verification_email(new_user, resend=False)
            
            if email_sent:
                # Redirect to check email page for better UX
                flash('Registration successful! Please check your email to verify your account.', 'success')
                return redirect(url_for('check_email'))
            else:
                # If email isn't configured, auto-verify the user so they can log in
                # In production, you might want to handle this differently
                new_user.is_verified = True
                new_user.verify_token = None
                new_user.token_created_at = None
                db.session.commit()
                flash('Registration successful! Email verification is not configured. You can log in now.', 'warning')
                return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            import traceback
            error_trace = traceback.format_exc()
            print(f"Registration error: {str(e)}")
            print(f"Traceback: {error_trace}")
            
            # Handle database errors
            error_str = str(e).lower()
            if 'unique constraint failed' in error_str or 'integrityerror' in error_str:
                if 'username' in error_str:
                    flash('Username already exists. Please choose a different username.', 'danger')
                    form.username.errors.append('Username already exists.')
                elif 'email' in error_str:
                    flash('Email already registered. Please use a different email.', 'danger')
                    form.email.errors.append('Email already registered.')
                else:
                    flash('Username or email already exists.', 'danger')
                    form.username.errors.append('Username or email already exists.')
                    form.email.errors.append('Username or email already exists.')
            else:
                flash('An error occurred during registration. Please try again or contact support.', 'danger')
                form.username.errors.append('An error occurred. Please try again.')

    return render_template('register.html', form=form)


@app.route('/verify/<token>')
def verify_email(token):
    """Verify user email with secure token validation."""
    try:
        # Load and validate token (1 hour expiration)
        payload = serializer.loads(token, salt='email-verify', max_age=3600)
        
        # Extract email and user_id from payload
        email = payload.get('email')
        user_id = payload.get('user_id')
        
        if not email:
            flash('Invalid verification token format.', 'danger')
            return redirect(url_for('login'))
            
    except SignatureExpired:
        flash('Verification link has expired. Please request a new verification email.', 'warning')
        return redirect(url_for('resend_verification'))
    except BadSignature:
        flash('Invalid or tampered verification token. Please request a new verification email.', 'danger')
        return redirect(url_for('resend_verification'))
    except Exception as e:
        print(f"Error verifying token: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while verifying your email. Please try again.', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Find user by email and verify token matches
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User account not found. Please register again.', 'danger')
            return redirect(url_for('register'))
        
        # Check if already verified
        if user.is_verified:
            flash('Your email is already verified. You can log in now.', 'info')
            return redirect(url_for('login'))
        
        # Verify token matches stored token
        if user.verify_token != token:
            flash('Invalid verification token. Please request a new verification email.', 'danger')
            return redirect(url_for('resend_verification'))
        
        # Verify the account
        user.is_verified = True
        user.verify_token = None
        user.token_created_at = None
        db.session.commit()
        
        flash('Email verified successfully! You can now log in to your account.', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user verification status: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while verifying your email. Please contact support.', 'danger')
        return redirect(url_for('login'))


def send_password_reset_email(user):
    """Send password reset email to user. Returns (success: bool, message: str)."""
    try:
        # Check if mail is configured
        mail_username = app.config.get('MAIL_USERNAME')
        mail_password = app.config.get('MAIL_PASSWORD')
        
        if not mail_username or not mail_password:
            print("Warning: Email not configured. MAIL_USERNAME or MAIL_PASSWORD missing.")
            return False, "Email service is not configured. Please contact support."

        # Generate secure reset token
        payload = {
            'email': user.email,
            'user_id': user.id,
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'password_reset'
        }
        token = serializer.dumps(payload, salt='password-reset')
        user.reset_token = token
        user.reset_token_created_at = datetime.utcnow()
        db.session.commit()

        # Create reset URL
        try:
            reset_url = url_for('reset_password', token=token, _external=True)
        except RuntimeError:
            with app.app_context():
                reset_url = url_for('reset_password', token=token, _external=True)
        
        # Create email message
        subject = "Reset your SoundMatch password"
        
        body_text = f"""Hi {user.username},

You requested to reset your password. Click the following link to reset it:

{reset_url}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email. Your password will remain unchanged.

For security reasons, do not share this link with anyone.

Best regards,
SoundMatch Team"""
        
        body_html = f"""<html>
<body>
    <h2>Password Reset Request</h2>
    <p>Hi {user.username},</p>
    <p>You requested to reset your password. Click the button below to reset it:</p>
    <p><a href="{reset_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
    <p>Or copy and paste this link into your browser:</p>
    <p><a href="{reset_url}">{reset_url}</a></p>
    <p><strong>This link will expire in 1 hour.</strong></p>
    <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
    <hr>
    <p style="color: #666; font-size: 12px;">For security reasons, do not share this link with anyone.</p>
    <p style="color: #666; font-size: 12px;">Best regards,<br>SoundMatch Team</p>
</body>
</html>"""
        
        msg = Message(
            subject=subject,
            recipients=[user.email],
            body=body_text,
            html=body_html
        )
        
        mail.send(msg)
        print(f"Password reset email sent to {user.email}")
        return True, "Password reset email sent successfully!"
        
    except Exception as e:
        print(f"Error sending password reset email: {str(e)}")
        import traceback
        traceback.print_exc()
        return False, f"Failed to send password reset email: {str(e)}"


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit password reset requests
def forgot_password():
    """Handle password reset requests."""
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        
        try:
            user = User.query.filter_by(email=email).first()
            
            # Don't reveal if email exists (security best practice)
            if not user:
                flash('If an account exists with this email, a password reset link has been sent.', 'info')
                return render_template('forgot_password.html', form=form)
            
            # Send password reset email
            email_sent, message = send_password_reset_email(user)
            
            if email_sent:
                flash('If an account exists with this email, a password reset link has been sent. Please check your inbox.', 'success')
            else:
                flash(f'Failed to send password reset email: {message}', 'danger')
            
            return render_template('forgot_password.html', form=form)
            
        except Exception as e:
            print(f"Error in forgot_password: {str(e)}")
            import traceback
            traceback.print_exc()
            flash('An error occurred. Please try again later.', 'danger')
    
    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per hour")  # Rate limit password reset attempts
def reset_password(token):
    """Handle password reset with token."""
    form = ResetPasswordForm()
    
    # Validate token first
    try:
        payload = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiration
        email = payload.get('email')
        user_id = payload.get('user_id')
        token_type = payload.get('type')
        
        if not email or token_type != 'password_reset':
            flash('Invalid password reset token.', 'danger')
            return redirect(url_for('forgot_password'))
            
    except SignatureExpired:
        flash('Password reset link has expired. Please request a new one.', 'warning')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid or tampered password reset token.', 'danger')
        return redirect(url_for('forgot_password'))
    except Exception as e:
        print(f"Error validating reset token: {str(e)}")
        flash('An error occurred while validating the reset token.', 'danger')
        return redirect(url_for('forgot_password'))
    
    # Find user
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User account not found.', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Verify token matches stored token
        if user.reset_token != token:
            flash('Invalid password reset token. Please request a new one.', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Handle form submission
        if form.validate_on_submit():
            try:
                # Hash new password
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                
                # Update password and clear reset token
                user.password = hashed_password
                user.reset_token = None
                user.reset_token_created_at = None
                user.reset_failed_login_attempts()  # Reset failed attempts on password change
                db.session.commit()
                
                flash('Password reset successful! You can now log in with your new password.', 'success')
                return redirect(url_for('login'))
                
            except Exception as e:
                db.session.rollback()
                print(f"Error resetting password: {str(e)}")
                import traceback
                traceback.print_exc()
                flash('An error occurred while resetting your password. Please try again.', 'danger')
        
        return render_template('reset_password.html', form=form, token=token)
        
    except Exception as e:
        print(f"Error in reset_password: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))


@app.route('/resend-verification', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit resend verification
def resend_verification():
    """Resend verification email to user."""
    form = ResendVerificationForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        
        try:
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Don't reveal if email exists (security best practice)
                flash('If an account exists with this email, a verification link has been sent.', 'info')
                return render_template('resend_verification.html', form=form)
            
            if user.is_verified:
                flash('Your email is already verified. You can log in now.', 'info')
                return redirect(url_for('login'))
            
            # Check rate limiting (prevent abuse)
            if user.token_created_at:
                time_since_last = datetime.utcnow() - user.token_created_at
                if time_since_last < timedelta(minutes=5):
                    flash('Please wait a few minutes before requesting another verification email.', 'warning')
                    return render_template('resend_verification.html', form=form)
            
            # Send new verification email
            email_sent, message = send_verification_email(user, resend=True)
            
            if email_sent:
                flash('A new verification email has been sent. Please check your inbox.', 'success')
            else:
                flash(f'Failed to send verification email: {message}', 'danger')
            
            return render_template('resend_verification.html', form=form)
            
        except Exception as e:
            print(f"Error resending verification: {str(e)}")
            import traceback
            traceback.print_exc()
            flash('An error occurred. Please try again later.', 'danger')
    
    return render_template('resend_verification.html', form=form)


# Error handler for 500 errors
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    import traceback
    error_trace = traceback.format_exc()
    print(f"500 Error: {str(error)}")
    print(f"Traceback: {error_trace}")
    flash('An internal server error occurred. Please try again later.', 'danger')
    return redirect(url_for('home')), 500


# Error handler for 404 errors
@app.errorhandler(404)
def not_found_error(error):
    flash('Page not found.', 'warning')
    return redirect(url_for('home')), 404


if __name__ == '__main__':
    init_db()

    port = int(os.environ.get('PORT', 5000))
    debug_env = os.environ.get('FLASK_DEBUG', '').lower()
    debug = debug_env in {'1', 'true', 'yes'}

    app.run(host='0.0.0.0', port=port, debug=debug)
