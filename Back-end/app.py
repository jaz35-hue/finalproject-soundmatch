from dotenv import load_dotenv
load_dotenv()
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
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
    """User model with account lockout protection."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)  # Increased for bcrypt hashes
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Account lockout fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    account_locked = db.Column(db.Boolean, default=False, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
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
                'id', 'username', 'password', 'created_at', 'last_login', 
                'failed_login_attempts', 'account_locked', 'locked_until'
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


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username", "autocomplete": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password", "autocomplete": "current-password"})
    
    submit = SubmitField("Login")


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
    """Secure user login with account lockout."""
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


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit registration to prevent spam
def register():
    """Secure user registration."""
    form = RegisterForm()

    if form.validate_on_submit():
        try:
            # Normalize and sanitize input
            username = form.username.data.strip()
            password = form.password.data
            
            # Final duplicate check (defense in depth)
            existing_username = User.query.filter_by(username=username).first()
            if existing_username:
                flash('Username already exists. Please choose a different username.', 'danger')
                form.username.errors.append('Username already exists.')
                return render_template('register.html', form=form)
            
            # Hash password with bcrypt (automatically uses secure rounds)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Create new user
            new_user = User(
                username=username,
                password=hashed_password,
                created_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
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
                else:
                    flash('Username already exists.', 'danger')
                    form.username.errors.append('Username already exists.')
            else:
                flash('An error occurred during registration. Please try again or contact support.', 'danger')
                form.username.errors.append('An error occurred. Please try again.')

    return render_template('register.html', form=form)


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
