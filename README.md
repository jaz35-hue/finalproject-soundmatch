# finalproject-soundmatch

## Adding Email Authentication (Step-by-step)

The current app already handles username/password sign-up and login. Follow these steps to extend it with email verification and login notifications using Flask-Mail. Each step includes concrete code that plugs into `Back-end/app.py`.

### 1. Install the mail dependency

Add `Flask-Mail` to your virtual environment (and to `Back-end/requirements.txt` if you plan to deploy):

```
pip install Flask-Mail
```

```Back-end/requirements.txt
Flask-Mail==0.9.1
```

### 2. Configure mail credentials

In `Back-end/app.py`, define the SMTP settings right after the Flask app is created. Render lets you keep secrets in environment variables; fall back to `.env` or dummy data for local tests.

```python
from flask_mail import Mail, Message

app = Flask(
    __name__,
    template_folder=str(FRONTEND_DIR),
    static_folder=str(STATIC_DIR),
)

app.config.update(
    MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=int(os.environ.get('MAIL_PORT', 587)),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER'),
)
mail = Mail(app)
```

### 3. Extend the `User` model

Add columns to store the email itself plus verification metadata. Create a one-time-use token field or simply store a boolean flag if you plan to expire tokens table-side.

```python
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verify_token = db.Column(db.String(120), nullable=True)
```

After editing the model, run a migration (e.g., using Flask-Migrate) or drop/recreate the SQLite DB locally.

### 4. Update the forms

Expose the email field in both registration and login forms. Only require email during registration; for login you can either keep username/password or switch entirely to email/password.

```python
class RegisterForm(FlaskForm):
    username = StringField(...existing validators...)
    email = StringField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField(...)
```

### 5. Send the verification email

Right after saving the new user, create a signed token (using `itsdangerous.URLSafeTimedSerializer`) and email a verification link.

```python
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_verification_email(user):
    token = serializer.dumps(user.email, salt='email-verify')
    user.verify_token = token
    db.session.commit()

    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message("Verify your SoundMatch account", recipients=[user.email])
    msg.body = f"Hi {user.username}, confirm your account: {verify_url}"
    mail.send(msg)
```

Trigger `send_verification_email(new_user)` inside the `/register` route after `db.session.commit()`.

### 6. Build the verification route

Add a new route that consumes the token and marks the user as verified.

```python
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
```

### 7. Prevent login until verified

In the `/login` route, add a guard after password validation.

```python
if not user.is_verified:
    flash('Please verify your email before logging in.', 'warning')
    return redirect(url_for('login'))
```

### 8. Optional: send login notifications

Send a short “new login” email each time `login_user` succeeds.

```python
def send_login_alert(user):
    msg = Message("New SoundMatch login", recipients=[user.email])
    msg.body = "We noticed a login to your account. If this wasn’t you, reset your password."
    mail.send(msg)
```

Call `send_login_alert(user)` immediately after `login_user(user)`.

### 9. Testing checklist

1. Register with a real email address.
2. Confirm the email link works within the configured expiration window.
3. Attempt to log in before verifying (should be blocked).
4. Restart the server and confirm verified state persists.
5. Deploy to Render with the mail environment variables set.

Following these steps keeps all templating and routing inside the existing Flask app while layering on email-based verification and alerts.
