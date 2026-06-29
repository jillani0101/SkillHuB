import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
from db import get_db_connection
from google_auth import google_auth, init_oauth

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"]   = os.getenv("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"]     = None

csrf = CSRFProtect(app)

init_oauth(app)
app.register_blueprint(google_auth)

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
ADMIN_EMAIL   = os.getenv("ADMIN_EMAIL", MAIL_USERNAME)


def send_email(to, subject, body, reply_to=None):
    try:
        msg = MIMEMultipart()
        msg["From"]    = f"SkillHub <{MAIL_USERNAME}>"
        msg["To"]      = to if isinstance(to, str) else ", ".join(to)
        msg["Subject"] = subject
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.ehlo()
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_USERNAME, to if isinstance(to, list) else [to], msg.as_string())
    except Exception as e:
        print(f"[send_email] Failed to send to {to}: {e}")
        raise


def is_valid_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


ts = URLSafeTimedSerializer(app.secret_key)

def generate_confirmation_token(email):
    return ts.dumps(email, salt="email-confirm")

def confirm_token(token, max_age=3600):
    try:
        return ts.loads(token, salt="email-confirm", max_age=max_age)
    except Exception:
        return None

def send_confirmation_email(email):
    try:
        token = generate_confirmation_token(email)
        confirm_url = url_for("confirm_email", token=token, _external=True)
        body = (
            "Welcome to SkillHub!\n\n"
            "Click the link below to verify your email and activate your account:\n\n"
            f"{confirm_url}\n\n"
            "This link expires in 1 hour. If you didn't sign up, you can ignore this email."
        )
        send_email(email, "Confirm your SkillHub account", body)
    except Exception as e:
        print("Failed to send confirmation email:", e)


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("home"))
        if session.get("role") != "admin":
            flash("You are not authorized to view that page.", "danger")
            return redirect(url_for("home_page"))
        return view_func(*args, **kwargs)
    return wrapped


def parse_max_members(raw_value, max_allowed=1000):
    """
    Safely parse a 'max_members' form field into an int (or None).
    Guards against:
      - empty / non-numeric input
      - absurdly large numbers that overflow SQLite's INTEGER column
        (Python ints are arbitrary precision, but isdigit() alone lets
        through huge strings like '999999999999999999999999')
    """
    raw_value = (raw_value or "").strip()
    if not raw_value.isdigit():
        return None
    value = int(raw_value)
    if value <= 0 or value > max_allowed:
        return None
    return value


def row_to_dict_with_datetime(row, field="created_at"):
    """
    Convert a sqlite3.Row to a dict and parse its date field (stored as
    TEXT in SQLite) into a real datetime object so templates can safely
    call .strftime() on it.
    """
    d = dict(row)
    if d.get(field) and isinstance(d[field], str):
        try:
            d[field] = datetime.fromisoformat(d[field])
        except ValueError:
            d[field] = None
    return d


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("home_page"))
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("login.html")

        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user WHERE email=?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["status"] == "banned":
                flash("Your account has been banned. Contact the site administrator.", "danger")
                return render_template("login.html")

            if not user["is_verified"]:
                flash("Please verify your email before logging in.", "danger")
                return render_template("login.html", unverified_email=email)

            session["user_id"]  = user["user_id"]
            session["username"] = user["username"]
            session["role"]     = user["role"] or "user"
            return redirect(url_for("home_page"))

        flash("Invalid email or password.", "danger")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")

        if len(username) < 3 or len(username) > 50:
            flash("Username must be between 3 and 50 characters.", "danger")
            return render_template("register.html")

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")

        conn   = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT user_id FROM user WHERE email=?', (email,))
        if cursor.fetchone():
            conn.close()
            flash("An account with that email already exists.", "danger")
            return render_template("register.html")

        cursor.execute('SELECT user_id FROM user WHERE username=?', (username,))
        if cursor.fetchone():
            conn.close()
            flash("That username is already taken.", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO user (username, email, password, status, is_verified, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (username, email, hashed_password, "active", 1))

        conn.commit()
        conn.close()

        try:
            send_confirmation_email(email)
        except Exception:
            pass

        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("That confirmation link is invalid or has expired.", "danger")
        return redirect(url_for("login"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE email=?', (email,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("Account not found.", "danger")
        return redirect(url_for("register"))

    if not user["is_verified"]:
        cursor.execute('UPDATE user SET is_verified=1 WHERE user_id=?', (user["user_id"],))
        conn.commit()

    conn.close()

    session["user_id"]  = user["user_id"]
    session["username"] = user["username"]
    session["role"]     = user["role"] or "user"
    flash("Email verified! Welcome to SkillHub.", "success")
    return redirect(url_for("home_page"))


@app.route("/resend-confirmation", methods=["POST"])
def resend_confirmation():
    email = request.form.get("email", "").strip().lower()

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE email=?', (email,))
    user = cursor.fetchone()
    conn.close()

    if user and not user["is_verified"]:
        send_confirmation_email(email)

    flash("If that email exists and isn't verified yet, a new confirmation link has been sent.", "success")
    return redirect(url_for("login"))


@app.route("/setup-skills", methods=["GET", "POST"])
def setup_skills():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action")

        if action == "skip":
            conn.close()
            return redirect(url_for("home_page"))

        selected_skills = request.form.getlist("skills")
        for skill_id in selected_skills:
            level = request.form.get(f"level_{skill_id}")
            cursor.execute("""
                INSERT INTO user_skill (user_id, skill_id, level)
                VALUES (?, ?, ?)
            """, (session["user_id"], skill_id, level))

        conn.commit()
        conn.close()
        return redirect(url_for("home_page"))

    cursor.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cursor.fetchall()
    conn.close()

    return render_template("setup_skills.html", skills=skills)


@app.route("/home")
def home_page():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.*,
               u.username AS owner_name,
               (
                   SELECT a.status FROM application a
                   WHERE a.project_id = p.project_id AND a.user_id = ? LIMIT 1
               ) AS application_status,
               (
                   SELECT COUNT(*) FROM project_comment c WHERE c.project_id = p.project_id
               ) AS comment_count,
               (
                   SELECT COUNT(*) FROM application a2
                   WHERE a2.project_id = p.project_id AND a2.status = 'accepted'
               ) AS accepted_count
        FROM project p
        JOIN user u ON p.owner_id = u.user_id
        ORDER BY p.created_at DESC
    """, (session["user_id"],))

    projects = cursor.fetchall()

    if projects:
        project_ids  = [p["project_id"] for p in projects]
        placeholders = ",".join(["?"] * len(project_ids))
        cursor.execute(f"""
            SELECT ps.project_id, s.skill_name
            FROM project_skill ps
            JOIN skill s ON ps.skill_id = s.skill_id
            WHERE ps.project_id IN ({placeholders})
            ORDER BY s.skill_name
        """, tuple(project_ids))

        skills_by_project = {}
        for row in cursor.fetchall():
            skills_by_project.setdefault(row["project_id"], []).append(row["skill_name"])

        projects = [dict(p) for p in projects]
        for p in projects:
            p["required_skills"] = skills_by_project.get(p["project_id"], [])
            p["is_full"] = p["max_members"] is not None and p["accepted_count"] >= p["max_members"]

    cursor.execute("""
        SELECT COUNT(*) AS cnt FROM notification WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],))
    row          = cursor.fetchone()
    unread_count = row["cnt"] if row else 0

    conn.close()

    return render_template(
        "home.html",
        projects=projects,
        user_id=session["user_id"],
        username=session["username"],
        unread_count=unread_count,
        role=session.get("role", "user")
    )


@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM notification WHERE user_id = ? ORDER BY created_at DESC
    """, (session["user_id"],))
    raw_notifs = cursor.fetchall()

    notifs = [row_to_dict_with_datetime(n) for n in raw_notifs]

    cursor.execute("""
        UPDATE notification SET is_read = 1 WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],))
    conn.commit()
    conn.close()

    return render_template("notifications.html", notifications=notifs, username=session["username"])


@app.route("/notifications/mark-all-read")
def mark_all_read():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE notification SET is_read = 1 WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    return redirect(url_for("notifications"))


@app.route("/project/<int:project_id>", methods=["GET", "POST"])
def project_detail(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.*, u.username AS owner_name
        FROM project p JOIN user u ON p.owner_id = u.user_id
        WHERE p.project_id = ?
    """, (project_id,))
    project = cursor.fetchone()

    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()[:2000]
        if content:
            cursor.execute("""
                INSERT INTO project_comment (project_id, user_id, content, created_at)
                VALUES (?, ?, ?, datetime('now'))
            """, (project_id, session["user_id"], content))
            conn.commit()
        return redirect(url_for("project_detail", project_id=project_id))

    cursor.execute("""
        SELECT c.*, u.username FROM project_comment c
        JOIN user u ON c.user_id = u.user_id
        WHERE c.project_id = ? ORDER BY c.created_at DESC
    """, (project_id,))
    # FIX: convert created_at from TEXT (string) to a real datetime object
    # so project_detail.html can safely call .strftime() on it.
    comments = [row_to_dict_with_datetime(c) for c in cursor.fetchall()]

    cursor.execute("""
        SELECT status FROM application WHERE user_id = ? AND project_id = ? LIMIT 1
    """, (session["user_id"], project_id))
    app_row            = cursor.fetchone()
    application_status = app_row["status"] if app_row else None

    cursor.execute("""
        SELECT s.skill_name FROM project_skill ps
        JOIN skill s ON ps.skill_id = s.skill_id
        WHERE ps.project_id = ? ORDER BY s.skill_name
    """, (project_id,))
    required_skills = [row["skill_name"] for row in cursor.fetchall()]

    cursor.execute("""
        SELECT COUNT(*) AS cnt FROM application WHERE project_id = ? AND status = 'accepted'
    """, (project_id,))
    accepted_count = cursor.fetchone()["cnt"]
    is_full        = project["max_members"] is not None and accepted_count >= project["max_members"]

    conn.close()

    return render_template(
        "project_detail.html",
        project=project,
        comments=comments,
        application_status=application_status,
        required_skills=required_skills,
        accepted_count=accepted_count,
        is_full=is_full,
        user_id=session["user_id"],
        username=session["username"]
    )


@app.route("/delete-comment/<int:comment_id>/<int:project_id>", methods=["POST"])
def delete_comment(comment_id, project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM project_comment WHERE comment_id = ?", (comment_id,))
    comment = cursor.fetchone()

    if comment and comment["user_id"] == session["user_id"]:
        cursor.execute("DELETE FROM project_comment WHERE comment_id = ?", (comment_id,))
        conn.commit()

    conn.close()
    return redirect(url_for("project_detail", project_id=project_id))


@app.route("/create-project", methods=["GET", "POST"])
def create_project():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        name            = request.form.get("project_name", "").strip()[:150]
        desc            = request.form.get("description", "").strip()[:3000]
        selected_skills = request.form.getlist("skills")
        # FIX: previously `int(raw) if raw.isdigit() else None` let through
        # absurdly large numbers (e.g. 999999999999999999999999), which
        # Python can store as an int but SQLite's INTEGER column can't,
        # causing OverflowError. parse_max_members() caps it at a sane value.
        max_members     = parse_max_members(request.form.get("max_members", ""))

        if not name:
            flash("Project name is required.", "danger")
            cursor.execute("SELECT * FROM skill ORDER BY skill_name")
            skills = cursor.fetchall()
            conn.close()
            return render_template("create_project.html", skills=skills)

        cursor.execute("""
            INSERT INTO project (project_name, description, owner_id, status, max_members, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (name, desc, session["user_id"], "active", max_members))

        project_id = cursor.lastrowid
        for skill_id in selected_skills:
            cursor.execute("""
                INSERT INTO project_skill (project_id, skill_id) VALUES (?, ?)
            """, (project_id, skill_id))

        conn.commit()
        conn.close()
        return redirect(url_for("home_page"))

    cursor.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cursor.fetchall()
    conn.close()

    return render_template("create_project.html", skills=skills)


@app.route("/join-project/<int:project_id>")
def join_project(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM application WHERE user_id=? AND project_id=?
    """, (session["user_id"], project_id))

    if cursor.fetchone():
        conn.close()
        flash("You have already applied to this project.", "danger")
        return redirect(url_for("project_detail", project_id=project_id))

    cursor.execute("""
        SELECT owner_id, project_name, max_members FROM project WHERE project_id = ?
    """, (project_id,))
    proj = cursor.fetchone()

    if not proj:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    if proj["owner_id"] == session["user_id"]:
        conn.close()
        flash("You cannot apply to your own project.", "danger")
        return redirect(url_for("project_detail", project_id=project_id))

    if proj["max_members"] is not None:
        cursor.execute("""
            SELECT COUNT(*) AS cnt FROM application WHERE project_id=? AND status='accepted'
        """, (project_id,))
        if cursor.fetchone()["cnt"] >= proj["max_members"]:
            conn.close()
            flash("This project's team is already full.", "danger")
            return redirect(url_for("project_detail", project_id=project_id))

    cursor.execute("""
        INSERT INTO application (user_id, project_id, status) VALUES (?, ?, ?)
    """, (session["user_id"], project_id, "pending"))

    cursor.execute("""
        INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
        VALUES (?, 'application', ?, ?, 0, datetime('now'))
    """, (
        proj["owner_id"],
        f"{session['username']} applied to join \"{proj['project_name']}\"",
        project_id
    ))

    conn.commit()
    conn.close()
    return redirect(url_for("home_page"))


@app.route("/team")
def team_page():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.* FROM project p
        WHERE p.owner_id = ?
        UNION
        SELECT p.* FROM project p
        JOIN application a ON p.project_id = a.project_id
        WHERE a.user_id = ? AND a.status = 'accepted'
        ORDER BY created_at DESC
    """, (session["user_id"], session["user_id"]))

    teams = cursor.fetchall()
    conn.close()

    return render_template("team.html", teams=teams)


@app.route("/chat/<int:project_id>")
def chat(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM project WHERE project_id = ?", (project_id,))
    project = cursor.fetchone()

    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    is_owner = project["owner_id"] == session["user_id"]

    cursor.execute("""
        SELECT * FROM application
        WHERE project_id = ? AND user_id = ? AND status = 'accepted'
    """, (project_id, session["user_id"]))
    membership = cursor.fetchone()

    if not is_owner and not membership:
        conn.close()
        flash("You are not a member of this project.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT u.user_id, u.username FROM project p
        JOIN user u ON p.owner_id = u.user_id WHERE p.project_id = ?
        UNION
        SELECT u.user_id, u.username FROM application a
        JOIN user u ON a.user_id = u.user_id
        WHERE a.project_id = ? AND a.status = 'accepted'
    """, (project_id, project_id))
    members = cursor.fetchall()

    conn.close()

    return render_template(
        "chat.html",
        members=members,
        project=project,
        project_id=project_id
    )


@app.route("/edit-project/<int:project_id>", methods=["GET", "POST"])
def edit_project(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM project WHERE project_id=?", (project_id,))
    project = cursor.fetchone()

    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    if project["owner_id"] != session["user_id"]:
        conn.close()
        flash("You are not authorized to edit this project.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT COUNT(*) AS cnt FROM application WHERE project_id=? AND status='accepted'
    """, (project_id,))
    accepted_count = cursor.fetchone()["cnt"]

    if request.method == "POST":
        name            = request.form.get("project_name", "").strip()[:150]
        desc            = request.form.get("description", "").strip()[:3000]
        status          = request.form.get("status", "active")
        selected_skills = request.form.getlist("skills")
        # FIX: same OverflowError guard as create_project()
        max_members     = parse_max_members(request.form.get("max_members", ""))

        if max_members is not None and max_members < accepted_count:
            cursor.execute("SELECT * FROM skill ORDER BY skill_name")
            skills = cursor.fetchall()
            cursor.execute("SELECT skill_id FROM project_skill WHERE project_id=?", (project_id,))
            selected_skill_ids = {row["skill_id"] for row in cursor.fetchall()}
            conn.close()
            return render_template(
                "edit_project.html",
                project=project,
                skills=skills,
                selected_skill_ids=selected_skill_ids,
                accepted_count=accepted_count,
                error=f"You already have {accepted_count} accepted member(s) — the limit can't be set below that."
            )

        cursor.execute("""
            UPDATE project SET project_name=?, description=?, status=?,
            max_members=?, updated_at=datetime('now') WHERE project_id=?
        """, (name, desc, status, max_members, project_id))

        cursor.execute("DELETE FROM project_skill WHERE project_id=?", (project_id,))
        for skill_id in selected_skills:
            cursor.execute("""
                INSERT INTO project_skill (project_id, skill_id) VALUES (?, ?)
            """, (project_id, skill_id))

        conn.commit()
        conn.close()
        return redirect(url_for("home_page"))

    cursor.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cursor.fetchall()

    cursor.execute("SELECT skill_id FROM project_skill WHERE project_id=?", (project_id,))
    selected_skill_ids = {row["skill_id"] for row in cursor.fetchall()}

    conn.close()
    return render_template(
        "edit_project.html",
        project=project,
        skills=skills,
        selected_skill_ids=selected_skill_ids,
        accepted_count=accepted_count
    )


@app.route("/project-requests")
def project_requests():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT a.application_id, a.project_id, p.project_name, p.max_members, u.username,
               (SELECT COUNT(*) FROM application a2
                WHERE a2.project_id = p.project_id AND a2.status = 'accepted') AS accepted_count
        FROM application a
        JOIN project p ON a.project_id = p.project_id
        JOIN user u ON a.user_id = u.user_id
        WHERE p.owner_id=? AND a.status='pending'
        ORDER BY p.project_name
    """, (session["user_id"],))

    requests = [dict(r) for r in cursor.fetchall()]
    for r in requests:
        r["is_full"] = r["max_members"] is not None and r["accepted_count"] >= r["max_members"]

    conn.close()
    return render_template("project_requests.html", requests=requests, username=session["username"])


@app.route("/accept-request/<int:application_id>", methods=["POST"])
def accept_request(application_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.owner_id FROM application a
        JOIN project p ON a.project_id = p.project_id
        WHERE a.application_id=?
    """, (application_id,))
    row = cursor.fetchone()

    if not row or row["owner_id"] != session["user_id"]:
        conn.close()
        flash("Not authorized.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT a.user_id, p.project_name, a.project_id FROM application a
        JOIN project p ON a.project_id = p.project_id WHERE a.application_id = ?
    """, (application_id,))
    app_info = cursor.fetchone()

    cursor.execute("UPDATE application SET status='accepted' WHERE application_id=?", (application_id,))

    if app_info:
        cursor.execute("""
            INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
            VALUES (?, 'accepted', ?, ?, 0, datetime('now'))
        """, (
            app_info["user_id"],
            f"Your application to join \"{app_info['project_name']}\" has been accepted!",
            app_info["project_id"]
        ))

    conn.commit()
    conn.close()
    return redirect(url_for("project_requests"))


@app.route("/reject-request/<int:application_id>", methods=["POST"])
def reject_request(application_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.owner_id FROM application a
        JOIN project p ON a.project_id = p.project_id WHERE a.application_id=?
    """, (application_id,))
    row = cursor.fetchone()

    if not row or row["owner_id"] != session["user_id"]:
        conn.close()
        flash("Not authorized.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT a.user_id, p.project_name, a.project_id FROM application a
        JOIN project p ON a.project_id = p.project_id WHERE a.application_id = ?
    """, (application_id,))
    app_info = cursor.fetchone()

    cursor.execute("UPDATE application SET status='rejected' WHERE application_id=?", (application_id,))

    if app_info:
        cursor.execute("""
            INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
            VALUES (?, 'rejected', ?, ?, 0, datetime('now'))
        """, (
            app_info["user_id"],
            f"Your application to join \"{app_info['project_name']}\" was not accepted this time.",
            app_info["project_id"]
        ))

    conn.commit()
    conn.close()
    return redirect(url_for("project_requests"))


@app.route("/project-members/<int:project_id>")
def project_members(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT u.username FROM application a
        JOIN user u ON a.user_id=u.user_id
        WHERE a.project_id=? AND a.status='accepted'
    """, (project_id,))

    members = cursor.fetchall()
    conn.close()

    return render_template("project_members.html", members=members)


@app.route("/profile")
@app.route("/profile/<int:user_id>")
def profile(user_id=None):
    if "user_id" not in session:
        return redirect(url_for("home"))

    target_id = user_id if user_id is not None else session["user_id"]

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM user WHERE user_id = ?', (target_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("home_page"))

    user = row_to_dict_with_datetime(user)

    cursor.execute("""
        SELECT s.skill_name, us.level FROM user_skill us
        JOIN skill s ON us.skill_id = s.skill_id
        WHERE us.user_id = ? ORDER BY s.skill_name
    """, (target_id,))
    skills = cursor.fetchall()

    cursor.execute("SELECT * FROM project WHERE owner_id = ? ORDER BY created_at DESC", (target_id,))
    projects = cursor.fetchall()

    cursor.execute("""
        SELECT p.* FROM project p JOIN application a ON p.project_id = a.project_id
        WHERE a.user_id = ? AND a.status = 'accepted' ORDER BY p.created_at DESC
    """, (target_id,))
    joined_projects = cursor.fetchall()

    conn.close()

    return render_template(
        "profile.html",
        user=user,
        skills=skills,
        projects=projects,
        joined_projects=joined_projects,
        is_own_profile=(target_id == session["user_id"])
    )


@app.route("/api/project/<int:project_id>/comments", methods=["GET"])
def api_get_comments(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT c.comment_id, c.user_id, c.content,
               strftime('%b %d, %Y · %I:%M %p', c.created_at) AS created_at,
               u.username
        FROM project_comment c JOIN user u ON c.user_id = u.user_id
        WHERE c.project_id = ? ORDER BY c.created_at DESC
    """, (project_id,))

    comments = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({"comments": comments, "user_id": session["user_id"]})


@app.route("/api/project/<int:project_id>/comments", methods=["POST"])
@csrf.exempt
def api_post_comment(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data    = request.get_json()
    content = (data.get("content") or "").strip()[:2000]

    if not content:
        return jsonify({"error": "Comment cannot be empty"}), 400

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO project_comment (project_id, user_id, content, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (project_id, session["user_id"], content))

    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    return jsonify({
        "ok":         True,
        "comment_id": new_id,
        "username":   session["username"],
        "user_id":    session["user_id"],
        "content":    content,
        "created_at": "Just now"
    })


@app.route("/api/comment/<int:comment_id>/delete", methods=["POST"])
def api_delete_comment(comment_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM project_comment WHERE comment_id = ?", (comment_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "Comment not found"}), 404

    if row["user_id"] != session["user_id"]:
        conn.close()
        return jsonify({"error": "Not authorized"}), 403

    cursor.execute("DELETE FROM project_comment WHERE comment_id = ?", (comment_id,))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


# ── CHAT API ─────────────────────────────────────────────────────────────────

@app.route("/api/chat/<int:project_id>/messages", methods=["GET"])
def api_get_messages(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    try:
        conn   = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT m.message_id, m.sender_id, u.username, m.content,
                   strftime('%b %d · %I:%M %p', m.sent_at) AS sent_at
            FROM message m
            JOIN user u ON m.sender_id = u.user_id
            WHERE m.project_id = ?
            ORDER BY m.sent_at ASC
        """, (project_id,))

        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({"messages": messages, "user_id": session["user_id"]})

    except Exception as e:
        print(f"[api_get_messages] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/chat/<int:project_id>/messages", methods=["POST"])
@csrf.exempt
def api_post_message(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    try:
        data    = request.get_json()
        content = (data.get("content") or "").strip()[:2000]

        if not content:
            return jsonify({"error": "Message cannot be empty"}), 400

        conn   = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO message (project_id, sender_id, content)
            VALUES (?, ?, ?)
        """, (project_id, session["user_id"], content))

        conn.commit()
        conn.close()
        return jsonify({"ok": True})

    except Exception as e:
        print(f"[api_post_message] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ── ADMIN ─────────────────────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) AS cnt FROM user')
    total_users = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) AS cnt FROM project")
    total_projects = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) AS cnt FROM application")
    total_applications = cursor.fetchone()["cnt"]

    cursor.execute("SELECT COUNT(*) AS cnt FROM user WHERE status = 'banned'")
    banned_users = cursor.fetchone()["cnt"]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_projects=total_projects,
        total_applications=total_applications,
        banned_users=banned_users,
        username=session["username"]
    )


@app.route("/admin/users")
@admin_required
def admin_users():
    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id, username, email, status, role, created_at FROM user ORDER BY created_at DESC
    """)
    users = cursor.fetchall()
    conn.close()

    return render_template(
        "admin_users.html",
        users=users,
        current_user_id=session["user_id"],
        username=session["username"]
    )


@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_ban_user(user_id):
    if user_id == session["user_id"]:
        return redirect(url_for("admin_users"))

    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT status FROM user WHERE user_id = ?', (user_id,))
    row = cursor.fetchone()

    if row:
        new_status = "active" if row["status"] == "banned" else "banned"
        cursor.execute('UPDATE user SET status = ? WHERE user_id = ?', (new_status, user_id))
        conn.commit()

    conn.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        return redirect(url_for("admin_users"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/projects")
@admin_required
def admin_projects():
    conn   = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.project_id, p.project_name, p.status, p.max_members, p.created_at,
               u.username AS owner_name,
               (SELECT COUNT(*) FROM application a
                WHERE a.project_id = p.project_id AND a.status = 'accepted') AS member_count
        FROM project p JOIN user u ON p.owner_id = u.user_id ORDER BY p.created_at DESC
    """)
    projects = cursor.fetchall()
    conn.close()

    return render_template("admin_projects.html", projects=projects, username=session["username"])


@app.route("/admin/projects/<int:project_id>/delete", methods=["POST"])
@admin_required
def admin_delete_project(project_id):
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM project WHERE project_id = ?", (project_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_projects"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/faq")
def faq():
    return render_template("faq.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name    = request.form.get("name", "").strip()[:100]
        email   = request.form.get("email", "").strip()[:150]
        subject = request.form.get("subject", "").strip()[:200]
        message = request.form.get("message", "").strip()[:3000]

        if not (name and email and subject and message):
            return render_template("contact.html", submitted=False, error="Please fill in all fields.")

        if not is_valid_email(email):
            return render_template("contact.html", submitted=False, error="Please enter a valid email address.")

        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO contact_message (name, email, subject, message, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (name, email, subject, message))
        conn.commit()
        conn.close()

        try:
            send_email(
                ADMIN_EMAIL,
                f"[SkillHub Contact] {subject}",
                f"From: {name} <{email}>\n\n{message}",
                reply_to=email,
            )
        except Exception as e:
            print("Failed to send contact email:", e)

        return render_template("contact.html", submitted=True)

    return render_template("contact.html", submitted=False)


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


def generate_reset_token(email):
    return ts.dumps(email, salt="password-reset")

def confirm_reset_token(token, max_age=1800):
    try:
        return ts.loads(token, salt="password-reset", max_age=max_age)
    except Exception:
        return None


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email or not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("forgot_password.html")

        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM user WHERE email=?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = generate_reset_token(email)
            reset_url = url_for("reset_password", token=token, _external=True)
            body = (
                "You requested a password reset for your SkillHub account.\n\n"
                "Click the link below to set a new password:\n\n"
                f"{reset_url}\n\n"
                "This link expires in 30 minutes. If you didn't request this, you can ignore this email."
            )
            try:
                send_email(email, "Reset your SkillHub password", body)
            except Exception as e:
                print("Failed to send reset email:", e)

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
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("reset_password.html", token=token)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        hashed = generate_password_hash(password)

        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE user SET password=? WHERE email=?', (hashed, email))
        conn.commit()
        conn.close()

        flash("Password updated! You can now sign in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
