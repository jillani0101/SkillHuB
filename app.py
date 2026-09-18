import os
import re
import smtplib
import time
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
    current_app,
    abort,
)
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv

from db import get_db_connection
from google_auth import google_auth, init_oauth

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY") or os.urandom(32).hex()
if not os.getenv("SECRET_KEY"):
    logging.getLogger(__name__).warning(
        "SECRET_KEY not set in environment — using an ephemeral key. "
        "Sessions will reset on every restart."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    WTF_CSRF_TIME_LIMIT=None,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

csrf = CSRFProtect(app)
socketio = SocketIO(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("skillhub")

init_oauth(app)
app.register_blueprint(google_auth)

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL") or MAIL_USERNAME
MAIL_FROM = os.getenv("MAIL_FROM")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
class MailError(Exception):
    """Raised when an email cannot be delivered by any configured provider."""


def _send_via_resend(to, subject, body, reply_to=None):
    import resend

    resend.api_key = RESEND_API_KEY
    sender = MAIL_FROM or "SkillHub <onboarding@resend.dev>"
    payload = {"from": sender, "to": to, "subject": subject, "text": body}
    if reply_to:
        payload["reply_to"] = reply_to
    resend.Emails.send(payload)


def _send_via_smtp(to, subject, body, reply_to=None):
    if not (MAIL_USERNAME and MAIL_PASSWORD):
        raise MailError(
            "SMTP is not configured (MAIL_USERNAME / MAIL_PASSWORD missing)."
        )
    msg = MIMEMultipart()
    msg["From"] = MAIL_FROM or f"SkillHub <{MAIL_USERNAME}>"
    msg["To"] = ", ".join(to) if isinstance(to, (list, tuple)) else to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.attach(MIMEText(body, "plain"))
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_USERNAME, to if isinstance(to, (list, tuple)) else [to], msg.as_string())


def send_email(to, subject, body, reply_to=None):
    """Deliver an email via Resend, falling back to Gmail SMTP."""
    recipients = to if isinstance(to, (list, tuple)) else [to]
    failures = []
    if RESEND_API_KEY:
        try:
            _send_via_resend(recipients, subject, body, reply_to)
            return
        except Exception as exc:
            failures.append(f"resend: {exc}")
            log.warning("Resend failed (%s); trying SMTP.", exc)
    if MAIL_USERNAME and MAIL_PASSWORD:
        try:
            _send_via_smtp(recipients, subject, body, reply_to)
            return
        except Exception as exc:
            failures.append(f"smtp: {exc}")
    raise MailError("; ".join(failures) or "No email provider is configured.")


def _notify_mail_error(email, action):
    log.error("Failed to send %s email to %s.", action, email)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_valid_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def utcnow():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _unread_count(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM notification WHERE user_id=? AND is_read=0", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row["cnt"] if row else 0


def _member_count(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM application WHERE project_id=? AND status='accepted'", (project_id,))
    row = cur.fetchone()
    conn.close()
    return row["cnt"] if row else 0


def _is_team_member(user_id, project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT owner_id FROM project WHERE project_id=?", (project_id,))
    project = cur.fetchone()
    if project and project["owner_id"] == user_id:
        conn.close()
        return True
    cur.execute(
        "SELECT 1 FROM application WHERE project_id=? AND user_id=? AND status='accepted'",
        (project_id, user_id),
    )
    ok = cur.fetchone() is not None
    conn.close()
    return ok


def requires_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        # Always check the live role in the DB, not the (stale) session value.
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT role, status FROM user WHERE user_id=?", (session["user_id"],))
            user = cur.fetchone()
        finally:
            conn.close()
        if not user or user["status"] == "banned" or user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def format_dt(value):
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%b %d, %Y · %I:%M %p")
    text = str(value).replace("T", " ")
    if "." in text:
        text = text.split(".")[0]
    try:
        dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%b %d, %Y · %I:%M %p")
    except ValueError:
        return text


app.jinja_env.filters["dt"] = format_dt
app.jinja_env.filters["date_only"] = lambda v: format_dt(v).split("·")[0].strip()


# ---------------------------------------------------------------------------
# Context processor — injects current user + unread count into every template
# ---------------------------------------------------------------------------
@app.context_processor
def inject_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return {}
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, email, role, status FROM user WHERE user_id=?", (user_id,))
    user = cur.fetchone()
    conn.close()
    if not user or user["status"] == "banned":
        session.clear()
        return {}
    return {
        "current_user": user,
        "unread_count": _unread_count(user_id),
        "is_admin": user["role"] == "admin",
    }


# ---------------------------------------------------------------------------
# Security headers + error handlers
# ---------------------------------------------------------------------------
@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You don't have permission to view that page."), 403


@app.errorhandler(500)
def server_error(_):
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


# ---------------------------------------------------------------------------
# Auth: verification tokens
# ---------------------------------------------------------------------------
ts = URLSafeTimedSerializer(SECRET_KEY)

def generate_confirmation_token(email):
    return ts.dumps(email, salt="email-confirm")


def confirm_token(token, max_age=3600):
    try:
        return ts.loads(token, salt="email-confirm", max_age=max_age)
    except Exception:
        return None


def generate_reset_token(email):
    return ts.dumps(email, salt="password-reset")


def confirm_reset_token(token, max_age=1800):
    try:
        return ts.loads(token, salt="password-reset", max_age=max_age)
    except Exception:
        return None


def send_confirmation_email(email):
    token = generate_confirmation_token(email)
    confirm_url = url_for("confirm_email", token=token, _external=True)
    body = (
        "Welcome to SkillHub!\n\n"
        "Click the link below to verify your email and activate your account:\n\n"
        f"{confirm_url}\n\n"
        "This link expires in 1 hour. If you didn't sign up, you can ignore this email."
    )
    send_email(email, "Confirm your SkillHub account", body)


def send_reset_email(email, reset_url):
    body = (
        "You requested a password reset for your SkillHub account.\n\n"
        "Click the link below to set a new password:\n\n"
        f"{reset_url}\n\n"
        "This link expires in 30 minutes. If you didn't request this, you can ignore this email."
    )
    send_email(email, "Reset your SkillHub password", body)


# Login throttling (simple in-memory limiter)
_LOGIN_FAILURES = {}

def _login_key(identifier):
    return f"{identifier}|{request.remote_addr}"

def _login_allowed(key):
    record = _LOGIN_FAILURES.get(key)
    if record and record[0] >= 5 and time.time() - record[1] < 900:
        return False
    if record:
        _LOGIN_FAILURES.pop(key, None)
    return True

def _record_failure(key):
    record = _LOGIN_FAILURES.get(key, (0, time.time()))
    if time.time() - record[1] > 900:
        record = (0, time.time())
    _LOGIN_FAILURES[key] = (record[0] + 1, time.time())


def _resend_allowed(email):
    marker = f"resend_sent:{email.lower()}"
    last = session.get(marker)
    now = time.time()
    if last and now - last < 60:
        return False, max(1, int(60 - (now - last)))
    session[marker] = now
    return True, 0


# ---------------------------------------------------------------------------
# Routes — public
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("home_page"))
    return render_template("landing.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/faq")
def faq():
    return render_template("faq.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        email = request.form.get("email", "").strip()[:150]
        subject = request.form.get("subject", "").strip()[:200]
        message = request.form.get("message", "").strip()[:3000]

        if not (name and email and subject and message):
            return render_template(
                "contact.html",
                submitted=False,
                error="Please fill in all fields.",
                form=request.form,
            )
        if not is_valid_email(email):
            return render_template(
                "contact.html",
                submitted=False,
                error="Please enter a valid email address.",
                form=request.form,
            )

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO contact_message (name, email, subject, message, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, subject, message, utcnow()),
        )
        conn.commit()
        conn.close()

        if ADMIN_EMAIL:
            try:
                send_email(
                    ADMIN_EMAIL,
                    f"[SkillHub Contact] {subject}",
                    f"From: {name} <{email}>\n\n{message}",
                    reply_to=email,
                )
            except MailError as exc:
                log.warning("Contact email not delivered: %s", exc)

        return render_template("contact.html", submitted=True)

    return render_template("contact.html", submitted=False)


# ---------------------------------------------------------------------------
# Routes — auth
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home_page"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("login.html", form=request.form)

        if not _login_allowed(_login_key(email)):
            flash("Too many failed attempts. Try again in 15 minutes.", "danger")
            return render_template("login.html", form=request.form)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM user WHERE email=?", (email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            _LOGIN_FAILURES.pop(_login_key(email), None)
            if user["status"] == "banned":
                flash("Your account has been banned. Contact the site administrator.", "danger")
                return render_template("login.html", form=request.form)
            if not user["is_verified"]:
                flash("Please verify your email before logging in. Use the link below to resend.", "warning")
                return render_template("login.html", form=request.form, unverified_email=email)

            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role"] = user["role"] or "user"
            session.permanent = True
            return redirect(url_for("home_page"))

        _record_failure(_login_key(email))
        flash("Invalid email or password.", "danger")
        return render_template("login.html", form=request.form)

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not (username and email and password and confirm_password):
            flash("Please fill in all fields.", "danger")
            return render_template("register.html", form=request.form)

        if len(username) < 3 or len(username) > 50:
            flash("Username must be between 3 and 50 characters.", "danger")
            return render_template("register.html", form=request.form)

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", form=request.form)

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html", form=request.form)
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", form=request.form)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM user WHERE email=?", (email,))
        if cur.fetchone():
            conn.close()
            flash("An account with that email already exists. Try logging in.", "danger")
            return render_template("register.html", form=request.form)

        cur.execute("SELECT user_id FROM user WHERE username=?", (username,))
        if cur.fetchone():
            conn.close()
            flash("That username is already taken.", "danger")
            return render_template("register.html", form=request.form)

        hashed = generate_password_hash(password)
        cur.execute(
            "INSERT INTO user (username, email, password, status, is_verified, created_at) VALUES (?, ?, ?, 'active', 0, ?)",
            (username, email, hashed, utcnow()),
        )
        conn.commit()
        conn.close()

        try:
            send_confirmation_email(email)
            flash("Account created! Check your email for a confirmation link.", "success")
        except MailError as exc:
            _notify_mail_error(email, "confirmation")
            flash(
                "Account created, but we couldn't send the verification email right now. "
                "You can send it again from the login page.",
                "warning",
            )

        return redirect(url_for("login", email=email))

    return render_template("register.html")


@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("That confirmation link is invalid or has expired.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM user WHERE email=?", (email,))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("Account not found. Please register again.", "danger")
        return redirect(url_for("register"))

    if user["status"] == "banned":
        conn.close()
        flash("Your account has been banned.", "danger")
        return redirect(url_for("login"))

    if not user["is_verified"]:
        cur.execute("UPDATE user SET is_verified=1 WHERE user_id=?", (user["user_id"],))
        conn.commit()
    conn.close()

    session.clear()
    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["role"] = user["role"] or "user"
    flash("Email verified! Welcome to SkillHub.", "success")
    return redirect(url_for("home_page"))


@app.route("/resend-confirmation", methods=["POST"])
def resend_confirmation():
    email = request.form.get("email", "").strip().lower()
    if not is_valid_email(email):
        flash("Please enter a valid email address.", "danger")
        return redirect(url_for("login"))

    allowed, wait = _resend_allowed(email)
    if not allowed:
        flash(f"Please wait {wait}s before requesting another email.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM user WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    if user and not user["is_verified"]:
        try:
            send_confirmation_email(email)
            flash("A new confirmation link has been sent. Check your inbox.", "success")
        except MailError:
            _notify_mail_error(email, "confirmation (resend)")
            flash("We couldn't send the email right now. Please try again shortly.", "danger")
    else:
        flash("No unverified account found for that email.", "warning")
    return redirect(url_for("login", email=email))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email or not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("forgot_password.html", form=request.form)

        allowed, wait = _resend_allowed(email)
        if not allowed:
            flash(f"Please wait {wait}s before requesting another email.", "warning")
            return render_template("forgot_password.html", form=request.form)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM user WHERE email=?", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            try:
                token = generate_reset_token(email)
                reset_url = url_for("reset_password", token=token, _external=True)
                send_reset_email(email, reset_url)
            except MailError:
                _notify_mail_error(email, "password reset")
                flash("We couldn't send the reset email right now. Please try again shortly.", "danger")
                return render_template("forgot_password.html", form=request.form)

        flash("If that email is registered, you'll receive a reset link shortly.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash("That reset link is invalid or has expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("reset_password.html", token=token)
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        hashed = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE user SET password=? WHERE email=?", (hashed, email))
        conn.commit()
        conn.close()

        flash("Password updated! You can now sign in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Routes — app (authenticated)
# ---------------------------------------------------------------------------
@app.route("/profile")
@app.route("/profile/<int:user_id>")
@requires_login
def profile(user_id=None):
    target_id = user_id if user_id is not None else session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM user WHERE user_id=?", (target_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("home_page"))
    user = dict(user)

    cur.execute(
        "SELECT us.user_id, s.skill_id, s.skill_name, us.level FROM user_skill us "
        "JOIN skill s ON us.skill_id = s.skill_id WHERE us.user_id=? ORDER BY s.skill_name",
        (target_id,),
    )
    skills = cur.fetchall()

    cur.execute("SELECT * FROM project WHERE owner_id=? ORDER BY created_at DESC", (target_id,))
    projects = cur.fetchall()

    cur.execute(
        "SELECT p.* FROM project p JOIN application a ON p.project_id = a.project_id "
        "WHERE a.user_id=? AND a.status='accepted' ORDER BY p.created_at DESC",
        (target_id,),
    )
    joined_projects = cur.fetchall()
    conn.close()

    return render_template(
        "profile.html",
        user=user,
        skills=skills,
        projects=projects,
        joined_projects=joined_projects,
        is_own_profile=(target_id == session["user_id"]),
    )


@app.route("/settings", methods=["GET", "POST"])
@requires_login
def settings():
    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM user WHERE user_id=?", (user_id,))
    user = cur.fetchone()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "profile":
            username = request.form.get("username", "").strip()
            bio = request.form.get("bio", "").strip()[:500]
            if len(username) < 3 or len(username) > 50:
                flash("Username must be between 3 and 50 characters.", "danger")
            else:
                cur.execute("SELECT user_id FROM user WHERE username=? AND user_id<>?", (username, user_id))
                if cur.fetchone():
                    flash("That username is already taken.", "danger")
                else:
                    cur.execute("UPDATE user SET username=?, bio=? WHERE user_id=?", (username, bio, user_id))
                    conn.commit()
                    session["username"] = username
                    flash("Profile updated.", "success")
        elif action == "password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")
            if not check_password_hash(user["password"], current_pw):
                flash("Your current password is incorrect.", "danger")
            elif len(new_pw) < 8:
                flash("New password must be at least 8 characters.", "danger")
            elif new_pw != confirm_pw:
                flash("New passwords do not match.", "danger")
            else:
                cur.execute("UPDATE user SET password=? WHERE user_id=?", (generate_password_hash(new_pw), user_id))
                conn.commit()
                flash("Password changed.", "success")

        conn.close()
        return redirect(url_for("settings"))

    conn.close()
    return render_template("settings.html", user=user)


@app.route("/setup-skills", methods=["GET", "POST"])
@requires_login
def setup_skills():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "skip":
            conn.close()
            return redirect(url_for("home_page"))

        selected_skills = request.form.getlist("skills")
        for skill_id in selected_skills:
            level = request.form.get(f"level_{skill_id}", "").strip() or "Beginner"
            if level not in ("Beginner", "Intermediate", "Expert"):
                level = "Beginner"
            cur.execute(
                "INSERT OR IGNORE INTO user_skill (user_id, skill_id, level) VALUES (?, ?, ?)",
                (session["user_id"], skill_id, level),
            )
        conn.commit()
        conn.close()
        flash("Your skills have been saved.", "success")
        return redirect(url_for("home_page"))

    cur.execute("SELECT * FROM user_skill WHERE user_id=?", (session["user_id"],))
    owned = {row["skill_id"] for row in cur.fetchall()}
    cur.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cur.fetchall()
    conn.close()
    return render_template("setup_skills.html", skills=skills, owned=owned)


def _load_projects(where_clause="", params=(), user_id=None):
    """Load project cards for the feed, enriched with skills and counts."""
    if user_id is None:
        user_id = session.get("user_id")
    conn = get_db_connection()
    cur = conn.cursor()

    query = f"""
        SELECT p.project_id, p.project_name, p.description, p.status, p.max_members,
               p.created_at, p.owner_id, u.username AS owner_name,
               (SELECT a.status FROM application a
                WHERE a.project_id = p.project_id AND a.user_id = ? LIMIT 1) AS application_status,
               (SELECT COUNT(*) FROM project_comment c WHERE c.project_id = p.project_id) AS comment_count,
               (SELECT COUNT(*) FROM application a2
                WHERE a2.project_id = p.project_id AND a2.status = 'accepted') AS accepted_count
        FROM project p
        JOIN user u ON p.owner_id = u.user_id
    """
    if where_clause:
        query += " WHERE " + where_clause
    query += " ORDER BY p.created_at DESC"

    cur.execute(query, (user_id,) + tuple(params))
    rows = cur.fetchall()
    projects = []

    if rows:
        skill_map = {}
        placeholders = ",".join("?" * len(rows))
        cur.execute(
            f"SELECT ps.project_id, s.skill_name FROM project_skill ps "
            f"JOIN skill s ON ps.skill_id = s.skill_id "
            f"WHERE ps.project_id IN ({placeholders}) ORDER BY s.skill_name",
            tuple(r["project_id"] for r in rows),
        )
        for r in cur.fetchall():
            skill_map.setdefault(r["project_id"], []).append(r["skill_name"])

        for r in rows:
            p = dict(r)
            p["required_skills"] = skill_map.get(p["project_id"], [])
            p["is_full"] = p["max_members"] is not None and p["accepted_count"] >= p["max_members"]
            projects.append(p)

    conn.close()
    return projects


@app.route("/home")
@requires_login
def home_page():
    return render_template("home.html", projects=_load_projects())


@app.route("/search")
@requires_login
def search():
    query = request.args.get("q", "").strip()
    projects = []
    if query:
        projects = _load_projects(
            "(p.project_name LIKE ? OR p.description LIKE ?)",
            (f"%{query}%", f"%{query}%"),
        )
    return render_template("home.html", projects=projects, query=query)


@app.route("/project/<int:project_id>", methods=["GET", "POST"])
@requires_login
def project_detail(project_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT p.*, u.username AS owner_name FROM project p JOIN user u ON p.owner_id = u.user_id WHERE p.project_id=?",
        (project_id,),
    )
    project = cur.fetchone()
    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()[:2000]
        if content:
            cur.execute(
                "INSERT INTO project_comment (project_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
                (project_id, session["user_id"], content, utcnow()),
            )
            conn.commit()
        conn.close()
        return redirect(url_for("project_detail", project_id=project_id))

    cur.execute(
        "SELECT c.*, u.username FROM project_comment c JOIN user u ON c.user_id = u.user_id "
        "WHERE c.project_id=? ORDER BY c.created_at DESC",
        (project_id,),
    )
    comments = cur.fetchall()

    cur.execute("SELECT status FROM application WHERE user_id=? AND project_id=? LIMIT 1", (session["user_id"], project_id))
    app_row = cur.fetchone()
    application_status = app_row["status"] if app_row else None

    cur.execute(
        "SELECT s.skill_name FROM project_skill ps JOIN skill s ON ps.skill_id = s.skill_id "
        "WHERE ps.project_id=? ORDER BY s.skill_name",
        (project_id,),
    )
    required_skills = [row["skill_name"] for row in cur.fetchall()]
    conn.close()

    return render_template(
        "project_detail.html",
        project=project,
        comments=comments,
        application_status=application_status,
        required_skills=required_skills,
        accepted_count=_member_count(project_id),
        is_full=project["max_members"] is not None and _member_count(project_id) >= project["max_members"],
    )


@app.route("/delete-comment/<int:comment_id>/<int:project_id>", methods=["POST"])
@requires_login
def delete_comment(comment_id, project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM project_comment WHERE comment_id=?", (comment_id,))
    comment = cur.fetchone()
    if comment and comment["user_id"] == session["user_id"]:
        cur.execute("DELETE FROM project_comment WHERE comment_id=?", (comment_id,))
        conn.commit()
        flash("Comment deleted.", "success")
    conn.close()
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/create-project", methods=["GET", "POST"])
@requires_login
def create_project():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        name = request.form.get("project_name", "").strip()[:150]
        desc = request.form.get("description", "").strip()[:3000]
        selected_skills = request.form.getlist("skills")
        max_raw = request.form.get("max_members", "").strip()
        max_members = None
        if max_raw:
            try:
                max_members = int(max_raw)
            except ValueError:
                max_members = None
            if max_members is not None and max_members < 1:
                max_members = None

        cur.execute("SELECT * FROM skill ORDER BY skill_name")
        skills = cur.fetchall()

        if not name:
            conn.close()
            flash("Project name is required.", "danger")
            return render_template("create_project.html", skills=skills, form=request.form)
        if not desc:
            conn.close()
            flash("Description is required.", "danger")
            return render_template("create_project.html", skills=skills, form=request.form)

        cur.execute(
            "INSERT INTO project (project_name, description, owner_id, status, max_members, created_at, updated_at) "
            "VALUES (?, ?, ?, 'active', ?, ?, ?)",
            (name, desc, session["user_id"], max_members, utcnow(), utcnow()),
        )
        project_id = cur.lastrowid
        for skill_id in selected_skills:
            cur.execute("INSERT OR IGNORE INTO project_skill (project_id, skill_id) VALUES (?, ?)", (project_id, skill_id))

        conn.commit()
        conn.close()
        flash("Project created!", "success")
        return redirect(url_for("home_page"))

    cur.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cur.fetchall()
    conn.close()
    return render_template("create_project.html", skills=skills)


@app.route("/project/<int:project_id>/join", methods=["POST"])
@requires_login
def join_project(project_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT owner_id, project_name, max_members, status FROM project WHERE project_id=?", (project_id,))
    proj = cur.fetchone()
    if not proj:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    if proj["owner_id"] == session["user_id"]:
        conn.close()
        flash("You cannot apply to your own project.", "warning")
        return redirect(url_for("project_detail", project_id=project_id))

    if proj["status"] != "active":
        conn.close()
        flash("This project is not accepting applications right now.", "warning")
        return redirect(url_for("project_detail", project_id=project_id))

    cur.execute("SELECT application_id FROM application WHERE user_id=? AND project_id=?", (session["user_id"], project_id))
    if cur.fetchone():
        conn.close()
        flash("You have already applied to this project.", "info")
        return redirect(url_for("project_detail", project_id=project_id))

    if proj["max_members"] is not None:
        if _member_count(project_id) >= proj["max_members"]:
            conn.close()
            flash("This project's team is already full.", "warning")
            return redirect(url_for("project_detail", project_id=project_id))

    cur.execute(
        "INSERT INTO application (user_id, project_id, status) VALUES (?, ?, 'pending')",
        (session["user_id"], project_id),
    )
    cur.execute(
        "INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at) "
        "VALUES (?, 'application', ?, ?, 0, ?)",
        (proj["owner_id"], f"{session['username']} applied to join \"{proj['project_name']}\"", project_id, utcnow()),
    )
    conn.commit()
    conn.close()
    flash("Application sent! The project owner will review it.", "success")
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/project/<int:project_id>/cancel-application", methods=["POST"])
@requires_login
def cancel_application(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM application WHERE user_id=? AND project_id=? AND status='pending'",
        (session["user_id"], project_id),
    )
    conn.commit()
    conn.close()
    flash("Your application was withdrawn.", "info")
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/edit-project/<int:project_id>", methods=["GET", "POST"])
@requires_login
def edit_project(project_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM project WHERE project_id=?", (project_id,))
    project = cur.fetchone()
    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))
    if project["owner_id"] != session["user_id"]:
        conn.close()
        abort(403)

    accepted_count = _member_count(project_id)

    if request.method == "POST":
        name = request.form.get("project_name", "").strip()[:150]
        desc = request.form.get("description", "").strip()[:3000]
        status = request.form.get("status", "active")
        selected_skills = request.form.getlist("skills")
        max_raw = request.form.get("max_members", "").strip()
        max_members = None
        if max_raw:
            try:
                max_members = int(max_raw)
            except ValueError:
                max_members = None
            if max_members is not None and max_members < accepted_count:
                cur.execute("SELECT * FROM skill ORDER BY skill_name")
                skills = cur.fetchall()
                cur.execute("SELECT skill_id FROM project_skill WHERE project_id=?", (project_id,))
                selected_skill_ids = {row["skill_id"] for row in cur.fetchall()}
                conn.close()
                return render_template(
                    "edit_project.html",
                    project=project,
                    skills=skills,
                    selected_skill_ids=selected_skill_ids,
                    accepted_count=accepted_count,
                    error=f"You already have {accepted_count} accepted member(s) — the limit can't be set below that.",
                )

        if status not in ("active", "paused", "completed"):
            status = "active"

        if not name:
            cur.execute("SELECT * FROM skill ORDER BY skill_name")
            skills = cur.fetchall()
            cur.execute("SELECT skill_id FROM project_skill WHERE project_id=?", (project_id,))
            selected_skill_ids = {row["skill_id"] for row in cur.fetchall()}
            conn.close()
            flash("Project name is required.", "danger")
            return render_template(
                "edit_project.html",
                project=project,
                skills=skills,
                selected_skill_ids=selected_skill_ids,
                accepted_count=accepted_count,
            )

        cur.execute(
            "UPDATE project SET project_name=?, description=?, status=?, max_members=?, updated_at=? WHERE project_id=?",
            (name, desc, status, max_members, utcnow(), project_id),
        )
        cur.execute("DELETE FROM project_skill WHERE project_id=?", (project_id,))
        for skill_id in selected_skills:
            cur.execute("INSERT OR IGNORE INTO project_skill (project_id, skill_id) VALUES (?, ?)", (project_id, skill_id))

        conn.commit()
        conn.close()
        flash("Project updated.", "success")
        return redirect(url_for("project_detail", project_id=project_id))

    cur.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cur.fetchall()
    cur.execute("SELECT skill_id FROM project_skill WHERE project_id=?", (project_id,))
    selected_skill_ids = {row["skill_id"] for row in cur.fetchall()}
    conn.close()
    return render_template(
        "edit_project.html",
        project=project,
        skills=skills,
        selected_skill_ids=selected_skill_ids,
        accepted_count=accepted_count,
    )


@app.route("/delete-project/<int:project_id>", methods=["POST"])
@requires_login
def delete_project(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT owner_id FROM project WHERE project_id=?", (project_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))
    if row["owner_id"] != session["user_id"]:
        conn.close()
        abort(403)
    cur.execute("DELETE FROM project WHERE project_id=?", (project_id,))
    conn.commit()
    conn.close()
    flash("Project deleted.", "success")
    return redirect(url_for("home_page"))


@app.route("/project-requests")
@requires_login
def project_requests():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT a.application_id, a.project_id, p.project_name, p.max_members, p.status, u.username, u.user_id AS applicant_id, "
        "(SELECT COUNT(*) FROM application a2 WHERE a2.project_id = p.project_id AND a2.status='accepted') AS accepted_count "
        "FROM application a JOIN project p ON a.project_id = p.project_id JOIN user u ON a.user_id = u.user_id "
        "WHERE p.owner_id=? AND a.status='pending' ORDER BY p.project_name",
        (session["user_id"],),
    )
    requests = [dict(r) for r in cur.fetchall()]
    for r in requests:
        r["is_full"] = r["max_members"] is not None and r["accepted_count"] >= r["max_members"]
    conn.close()
    return render_template("project_requests.html", requests=requests)


@app.route("/accept-request/<int:application_id>", methods=["POST"])
@requires_login
def accept_request(application_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT p.owner_id, a.user_id, p.project_name, a.project_id, p.max_members FROM application a "
        "JOIN project p ON a.project_id = p.project_id WHERE a.application_id=?",
        (application_id,),
    )
    row = cur.fetchone()
    if not row or row["owner_id"] != session["user_id"]:
        conn.close()
        abort(403)

    if row["max_members"] is not None and _member_count(row["project_id"]) >= row["max_members"]:
        conn.close()
        flash("This project's team is already full.", "warning")
        return redirect(url_for("project_requests"))

    cur.execute("UPDATE application SET status='accepted' WHERE application_id=?", (application_id,))
    cur.execute(
        "INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at) "
        "VALUES (?, 'accepted', ?, ?, 0, ?)",
        (row["user_id"], f"Your application to join \"{row['project_name']}\" has been accepted!", row["project_id"], utcnow()),
    )
    conn.commit()
    conn.close()
    flash("Application accepted.", "success")
    return redirect(url_for("project_requests"))


@app.route("/reject-request/<int:application_id>", methods=["POST"])
@requires_login
def reject_request(application_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT p.owner_id, a.user_id, p.project_name, a.project_id FROM application a "
        "JOIN project p ON a.project_id = p.project_id WHERE a.application_id=?",
        (application_id,),
    )
    row = cur.fetchone()
    if not row or row["owner_id"] != session["user_id"]:
        conn.close()
        abort(403)

    cur.execute("UPDATE application SET status='rejected' WHERE application_id=?", (application_id,))
    cur.execute(
        "INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at) "
        "VALUES (?, 'rejected', ?, ?, 0, ?)",
        (row["user_id"], f"Your application to join \"{row['project_name']}\" was not accepted this time.", row["project_id"], utcnow()),
    )
    conn.commit()
    conn.close()
    flash("Application rejected.", "info")
    return redirect(url_for("project_requests"))


@app.route("/team")
@requires_login
def team_page():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT p.* FROM project p JOIN application a ON p.project_id = a.project_id "
        "WHERE a.user_id=? AND a.status='accepted' ORDER BY p.created_at DESC",
        (session["user_id"],),
    )
    teams = cur.fetchall()
    conn.close()
    return render_template("team.html", teams=teams)


@app.route("/project/<int:project_id>/members")
@requires_login
def project_members(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT p.project_id, p.project_name, p.owner_id FROM project p WHERE p.project_id=?", (project_id,))
    project = cur.fetchone()
    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))
    if not _is_team_member(session["user_id"], project_id):
        conn.close()
        abort(403)
    cur.execute(
        "SELECT u.user_id, u.username FROM application a JOIN user u ON a.user_id = u.user_id "
        "WHERE a.project_id=? AND a.status='accepted' ORDER BY u.username",
        (project_id,),
    )
    members = cur.fetchall()
    conn.close()
    return render_template("project_members.html", project=project, members=members)


@app.route("/chat/<int:project_id>")
@requires_login
def chat(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM project WHERE project_id=?", (project_id,))
    project = cur.fetchone()
    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))
    if not _is_team_member(session["user_id"], project_id):
        conn.close()
        flash("You are not a member of this project.", "warning")
        return redirect(url_for("home_page"))

    cur.execute(
        "SELECT m.*, u.username FROM message m JOIN user u ON m.sender_id = u.user_id "
        "WHERE m.project_id=? ORDER BY m.sent_at ASC LIMIT 200",
        (project_id,),
    )
    messages = cur.fetchall()

    cur.execute(
        "SELECT u.user_id, u.username FROM project p JOIN user u ON p.owner_id = u.user_id WHERE p.project_id=? "
        "UNION SELECT u.user_id, u.username FROM application a JOIN user u ON a.user_id = u.user_id "
        "WHERE a.project_id=? AND a.status='accepted' ORDER BY username",
        (project_id, project_id),
    )
    members = cur.fetchall()
    conn.close()
    return render_template("chat.html", messages=messages, members=members, project=project)


# ---------------------------------------------------------------------------
# HTTP fallback chat API (works even without WebSockets)
# ---------------------------------------------------------------------------
@app.route("/api/chat/<int:project_id>/messages", methods=["GET", "POST"])
@requires_login
def api_chat_messages(project_id):
    if not _is_team_member(session["user_id"], project_id):
        return jsonify({"error": "You are not a member of this project."}), 403

    if request.method == "GET":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT m.message_id, m.sender_id, m.content, m.sent_at, u.username FROM message m "
            "JOIN user u ON m.sender_id = u.user_id WHERE m.project_id=? ORDER BY m.sent_at ASC LIMIT 200",
            (project_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"messages": rows, "user_id": session["user_id"]})

    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()[:2000]
    if not content:
        return jsonify({"error": "Message cannot be empty."}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO message (project_id, sender_id, content, sent_at, is_read) VALUES (?, ?, ?, ?, 0)",
        (project_id, session["user_id"], content, utcnow()),
    )
    conn.commit()
    conn.close()

    payload = {
        "ok": True,
        "message_id": cur.lastrowid,
        "project_id": project_id,
        "sender_id": session["user_id"],
        "username": session["username"],
        "content": content,
        "sent_at": utcnow(),
    }
    socketio.emit("receive_message", payload, room=f"project_{project_id}")
    return jsonify(payload)


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
@app.route("/notifications")
@requires_login
def notifications():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM notification WHERE user_id=? ORDER BY created_at DESC", (session["user_id"],))
    notifications = cur.fetchall()
    cur.execute("UPDATE notification SET is_read=1 WHERE user_id=? AND is_read=0", (session["user_id"],))
    conn.commit()
    conn.close()
    return render_template("notifications.html", notifications=notifications)


@app.route("/notifications/mark-all-read", methods=["POST"])
@requires_login
def mark_all_read():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE notification SET is_read=1 WHERE user_id=?", (session["user_id"],))
    conn.commit()
    conn.close()
    flash("All notifications marked as read.", "info")
    return redirect(url_for("notifications"))


# ---------------------------------------------------------------------------
# Comment API (AJAX modal on home cards)
# ---------------------------------------------------------------------------
@app.route("/api/project/<int:project_id>/comments", methods=["GET"])
@requires_login
def api_get_comments(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT c.comment_id, c.user_id, c.content, c.created_at, u.username "
        "FROM project_comment c JOIN user u ON c.user_id = u.user_id "
        "WHERE c.project_id=? ORDER BY c.created_at DESC",
        (project_id,),
    )
    comments = []
    for row in cur.fetchall():
        c = dict(row)
        c["created_at"] = format_dt(c.get("created_at"))
        comments.append(c)
    conn.close()
    return jsonify({"comments": comments, "user_id": session["user_id"]})


@app.route("/api/project/<int:project_id>/comments", methods=["POST"])
@requires_login
def api_post_comment(project_id):
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()[:2000]
    if not content:
        return jsonify({"error": "Comment cannot be empty."}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO project_comment (project_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
        (project_id, session["user_id"], content, utcnow()),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return jsonify({"ok": True, "comment_id": new_id, "username": session["username"], "user_id": session["user_id"], "content": content, "created_at": "Just now"})


@app.route("/api/comment/<int:comment_id>/delete", methods=["POST"])
@requires_login
def api_delete_comment(comment_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM project_comment WHERE comment_id=?", (comment_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Comment not found."}), 404
    if row["user_id"] != session["user_id"]:
        conn.close()
        return jsonify({"error": "Not authorized."}), 403
    cur.execute("DELETE FROM project_comment WHERE comment_id=?", (comment_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM user")
    total_users = cur.fetchone()["cnt"]
    cur.execute("SELECT COUNT(*) AS cnt FROM project")
    total_projects = cur.fetchone()["cnt"]
    cur.execute("SELECT COUNT(*) AS cnt FROM application")
    total_applications = cur.fetchone()["cnt"]
    cur.execute("SELECT COUNT(*) AS cnt FROM user WHERE status='banned'")
    banned_users = cur.fetchone()["cnt"]
    cur.execute("SELECT COUNT(*) AS cnt FROM user WHERE is_verified=0")
    unverified_users = cur.fetchone()["cnt"]
    conn.close()
    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_projects=total_projects,
        total_applications=total_applications,
        banned_users=banned_users,
        unverified_users=unverified_users,
    )


@app.route("/admin/users")
@admin_required
def admin_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, username, email, status, role, is_verified, created_at FROM user ORDER BY created_at DESC")
    users = cur.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users, current_user_id=session["user_id"])


@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_ban_user(user_id):
    if user_id == session["user_id"]:
        flash("You can't ban your own account.", "warning")
        return redirect(url_for("admin_users"))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT status FROM user WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    if row:
        new_status = "active" if row["status"] == "banned" else "banned"
        cur.execute("UPDATE user SET status=? WHERE user_id=?", (new_status, user_id))
        conn.commit()
        flash("User status updated.", "success")
    conn.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You can't delete your own account.", "warning")
        return redirect(url_for("admin_users"))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM user WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/projects")
@admin_required
def admin_projects():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT p.project_id, p.project_name, p.status, p.max_members, p.created_at, u.username AS owner_name, "
        "(SELECT COUNT(*) FROM application a WHERE a.project_id = p.project_id AND a.status='accepted') AS member_count "
        "FROM project p JOIN user u ON p.owner_id = u.user_id ORDER BY p.created_at DESC"
    )
    projects = cur.fetchall()
    conn.close()
    return render_template("admin_projects.html", projects=projects)


@app.route("/admin/projects/<int:project_id>/delete", methods=["POST"])
@admin_required
def admin_delete_project(project_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM project WHERE project_id=?", (project_id,))
    conn.commit()
    conn.close()
    flash("Project deleted.", "success")
    return redirect(url_for("admin_projects"))


@app.route("/admin/contact-messages")
@admin_required
def admin_contact_messages():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM contact_message ORDER BY created_at DESC")
    messages = cur.fetchall()
    conn.close()
    return render_template("admin_messages.html", messages=messages)


# ---------------------------------------------------------------------------
# Socket.IO — team chat
# ---------------------------------------------------------------------------
@socketio.on("connect")
def handle_socket_connect():
    if not session.get("user_id"):
        return False


@socketio.on("join")
def handle_socket_join(data):
    try:
        project_id = int((data or {}).get("project_id"))
    except (TypeError, ValueError):
        return
    if _is_team_member(session.get("user_id"), project_id):
        join_room(f"project_{project_id}")
        emit("joined", {"project_id": project_id}, to=request.sid)


@socketio.on("send_message")
def handle_socket_message(data):
    user_id = session.get("user_id")
    if not user_id:
        return
    try:
        project_id = int((data or {}).get("project_id"))
    except (TypeError, ValueError):
        return
    content = ((data or {}).get("content") or "").strip()[:2000]
    if not content or not _is_team_member(user_id, project_id):
        return

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO message (project_id, sender_id, content, sent_at, is_read) VALUES (?, ?, ?, ?, 0)",
        (project_id, user_id, content, utcnow()),
    )
    conn.commit()
    conn.close()

    emit(
        "receive_message",
        {
            "message_id": cur.lastrowid,
            "project_id": project_id,
            "sender_id": user_id,
            "username": session.get("username"),
            "content": content,
            "sent_at": utcnow(),
        },
        room=f"project_{project_id}",
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False)