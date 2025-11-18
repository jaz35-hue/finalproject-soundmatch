import os
import shutil
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from flask import Flask, render_template, url_for, redirect, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email
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

app.config['SECRET_KEY'] = 'SJZKEY2026@05'
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

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verify_token = db.Column(db.String(120), nullable=True)


def init_db():
    """Initialize the database and create all tables."""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    email = EmailField(validators=[InputRequired(), Email()],
                       render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("That email is already registered.")


def send_verification_email(user):
    token = serializer.dumps(user.email, salt='email-verify')
    user.verify_token = token
    db.session.commit()

    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message("Verify your SoundMatch account", recipients=[user.email])
    msg.body = f"Hi {user.username}, confirm your account: {verify_url}"
    mail.send(msg)



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    
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
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('dashboard'))
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
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            send_verification_email(new_user)
            flash('Registration successful! Please check your email to verify your account.', 'info')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            # Handle database errors (e.g., duplicate username constraint)
            form.username.errors.append('An error occurred. Please try again.')

    return render_template('register.html', form=form)


@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
    except SignatureExpired:
        flash('Verification link expired, please request a new one.', 'warning')
        return redirect(url_for('login'))
    except BadSignature:
        flash('Invalid verification token.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first_or_404()
    user.is_verified = True
    user.verify_token = None
    db.session.commit()
    flash('Email confirmed! You can log in now.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()

    port = int(os.environ.get('PORT', 5000))
    debug_env = os.environ.get('FLASK_DEBUG', '').lower()
    debug = debug_env in {'1', 'true', 'yes'}

    app.run(host='0.0.0.0', port=port, debug=debug)
