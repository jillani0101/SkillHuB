import os
import re
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from db import get_db_connection
from google_auth import google_auth, init_oauth

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# =========================
# SECURITY SETTINGS
# =========================

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"]   = os.getenv("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"]     = None

csrf = CSRFProtect(app)

init_oauth(app)
app.register_blueprint(google_auth)

# FIX: restrict SocketIO CORS to your actual domain (set ALLOWED_ORIGIN in .env)
_allowed_origin = os.getenv("ALLOWED_ORIGIN", "*")
socketio = SocketIO(app, cors_allowed_origins=_allowed_origin)

# =========================
# EMAIL CONFIG
# =========================
app.config["MAIL_SERVER"]         = "smtp.gmail.com"
app.config["MAIL_PORT"]           = 587
app.config["MAIL_USE_TLS"]        = True
app.config["MAIL_USERNAME"]       = os.environ["MAIL_USERNAME"]
app.config["MAIL_PASSWORD"]       = os.environ["MAIL_PASSWORD"]
app.config["MAIL_DEFAULT_SENDER"] = os.environ["MAIL_USERNAME"]

ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]

mail = Mail(app)


# =========================
# HELPERS
# =========================
def is_valid_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


# =========================
# ADMIN ACCESS CONTROL
# =========================
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


# =========================
# LANDING PAGE (public)
# =========================
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("home_page"))
    return render_template("landing.html")


# =========================
# LOGIN
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("login.html")

        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email=%s", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user.get("status") == "banned":
                flash("Your account has been banned. Contact the site administrator.", "danger")
                return render_template("login.html")

            session["user_id"]  = user["user_id"]
            session["username"] = user["username"]
            session["role"]     = user.get("role", "user")
            return redirect(url_for("home_page"))

        flash("Invalid email or password.", "danger")
        return render_template("login.html")

    return render_template("login.html")


# =========================
# REGISTER
# =========================
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
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT user_id FROM user WHERE email=%s", (email,))
        if cursor.fetchone():
            conn.close()
            flash("An account with that email already exists.", "danger")
            return render_template("register.html")

        cursor.execute("SELECT user_id FROM user WHERE username=%s", (username,))
        if cursor.fetchone():
            conn.close()
            flash("That username is already taken.", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO user (username, email, password, status, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """, (username, email, hashed_password, "active"))

        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        session["user_id"]  = user_id
        session["username"] = username
        session["role"]     = "user"

        return redirect(url_for("setup_skills"))

    return render_template("register.html")


# =========================
# SETUP SKILLS
# =========================
@app.route("/setup-skills", methods=["GET", "POST"])
def setup_skills():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

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
                VALUES (%s, %s, %s)
            """, (session["user_id"], skill_id, level))

        conn.commit()
        conn.close()
        return redirect(url_for("home_page"))

    cursor.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cursor.fetchall()
    conn.close()

    return render_template("setup_skills.html", skills=skills)


# =========================
# HOME PAGE
# =========================
@app.route("/home")
def home_page():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.*,
               u.username AS owner_name,
               (
                   SELECT a.status FROM application a
                   WHERE a.project_id = p.project_id AND a.user_id = %s LIMIT 1
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
        placeholders = ",".join(["%s"] * len(project_ids))
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

        for p in projects:
            p["required_skills"] = skills_by_project.get(p["project_id"], [])
            p["is_full"] = p["max_members"] is not None and p["accepted_count"] >= p["max_members"]

    cursor.execute("""
        SELECT COUNT(*) AS cnt FROM notification WHERE user_id = %s AND is_read = 0
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


# =========================
# NOTIFICATIONS PAGE
# =========================
@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM notification WHERE user_id = %s ORDER BY created_at DESC
    """, (session["user_id"],))
    notifs = cursor.fetchall()

    cursor.execute("""
        UPDATE notification SET is_read = 1 WHERE user_id = %s AND is_read = 0
    """, (session["user_id"],))
    conn.commit()
    conn.close()

    return render_template("notifications.html", notifications=notifs, username=session["username"])


# =========================
# MARK ALL NOTIFICATIONS READ
# =========================
@app.route("/notifications/mark-all-read")
def mark_all_read():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE notification SET is_read = 1 WHERE user_id = %s", (session["user_id"],))
    conn.commit()
    conn.close()
    return redirect(url_for("notifications"))


# =========================
# PROJECT DETAIL + COMMENTS
# =========================
@app.route("/project/<int:project_id>", methods=["GET", "POST"])
def project_detail(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.*, u.username AS owner_name
        FROM project p JOIN user u ON p.owner_id = u.user_id
        WHERE p.project_id = %s
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
                VALUES (%s, %s, %s, NOW())
            """, (project_id, session["user_id"], content))
            conn.commit()
        return redirect(url_for("project_detail", project_id=project_id))

    cursor.execute("""
        SELECT c.*, u.username FROM project_comment c
        JOIN user u ON c.user_id = u.user_id
        WHERE c.project_id = %s ORDER BY c.created_at DESC
    """, (project_id,))
    comments = cursor.fetchall()

    cursor.execute("""
        SELECT status FROM application WHERE user_id = %s AND project_id = %s LIMIT 1
    """, (session["user_id"], project_id))
    app_row            = cursor.fetchone()
    application_status = app_row["status"] if app_row else None

    cursor.execute("""
        SELECT s.skill_name FROM project_skill ps
        JOIN skill s ON ps.skill_id = s.skill_id
        WHERE ps.project_id = %s ORDER BY s.skill_name
    """, (project_id,))
    required_skills = [row["skill_name"] for row in cursor.fetchall()]

    cursor.execute("""
        SELECT COUNT(*) AS cnt FROM application WHERE project_id = %s AND status = 'accepted'
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


# =========================
# DELETE COMMENT
# FIX: changed to POST to prevent CSRF via URL
# =========================
@app.route("/delete-comment/<int:comment_id>/<int:project_id>", methods=["POST"])
def delete_comment(comment_id, project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM project_comment WHERE comment_id = %s", (comment_id,))
    comment = cursor.fetchone()

    if comment and comment["user_id"] == session["user_id"]:
        cursor.execute("DELETE FROM project_comment WHERE comment_id = %s", (comment_id,))
        conn.commit()

    conn.close()
    return redirect(url_for("project_detail", project_id=project_id))


# =========================
# CREATE PROJECT
# =========================
@app.route("/create-project", methods=["GET", "POST"])
def create_project():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        name            = request.form.get("project_name", "").strip()[:150]
        desc            = request.form.get("description", "").strip()[:3000]
        selected_skills = request.form.getlist("skills")
        max_members_raw = request.form.get("max_members", "").strip()
        max_members     = int(max_members_raw) if max_members_raw.isdigit() else None

        if not name:
            flash("Project name is required.", "danger")
            cursor.execute("SELECT * FROM skill ORDER BY skill_name")
            skills = cursor.fetchall()
            conn.close()
            return render_template("create_project.html", skills=skills)

        cursor.execute("""
            INSERT INTO project (project_name, description, owner_id, status, max_members, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
        """, (name, desc, session["user_id"], "active", max_members))

        project_id = cursor.lastrowid
        for skill_id in selected_skills:
            cursor.execute("""
                INSERT INTO project_skill (project_id, skill_id) VALUES (%s, %s)
            """, (project_id, skill_id))

        conn.commit()
        conn.close()
        return redirect(url_for("home_page"))

    cursor.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cursor.fetchall()
    conn.close()

    return render_template("create_project.html", skills=skills)


# =========================
# JOIN PROJECT
# =========================
@app.route("/join-project/<int:project_id>")
def join_project(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM application WHERE user_id=%s AND project_id=%s
    """, (session["user_id"], project_id))

    if cursor.fetchone():
        conn.close()
        flash("You have already applied to this project.", "danger")
        return redirect(url_for("project_detail", project_id=project_id))

    cursor.execute("""
        SELECT owner_id, project_name, max_members FROM project WHERE project_id = %s
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
            SELECT COUNT(*) AS cnt FROM application WHERE project_id=%s AND status='accepted'
        """, (project_id,))
        if cursor.fetchone()["cnt"] >= proj["max_members"]:
            conn.close()
            flash("This project's team is already full.", "danger")
            return redirect(url_for("project_detail", project_id=project_id))

    cursor.execute("""
        INSERT INTO application (user_id, project_id, status) VALUES (%s, %s, %s)
    """, (session["user_id"], project_id, "pending"))

    cursor.execute("""
        INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
        VALUES (%s, 'application', %s, %s, 0, NOW())
    """, (
        proj["owner_id"],
        f"{session['username']} applied to join \"{proj['project_name']}\"",
        project_id
    ))

    conn.commit()
    conn.close()
    return redirect(url_for("home_page"))


# =========================
# TEAM PAGE
# =========================
@app.route("/team")
def team_page():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.* FROM project p
        JOIN application a ON p.project_id = a.project_id
        WHERE a.user_id=%s AND a.status='accepted'
    """, (session["user_id"],))

    teams = cursor.fetchall()
    conn.close()

    return render_template("team.html", teams=teams)


# =========================
# CHAT (PROJECT BASED)
# =========================
@app.route("/chat/<int:project_id>")
def chat(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM project WHERE project_id = %s", (project_id,))
    project = cursor.fetchone()

    if not project:
        conn.close()
        flash("Project not found.", "danger")
        return redirect(url_for("home_page"))

    is_owner = project["owner_id"] == session["user_id"]

    cursor.execute("""
        SELECT * FROM application
        WHERE project_id = %s AND user_id = %s AND status = 'accepted'
    """, (project_id, session["user_id"]))
    membership = cursor.fetchone()

    if not is_owner and not membership:
        conn.close()
        flash("You are not a member of this project.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT m.*, u.username FROM message m
        JOIN user u ON m.sender_id = u.user_id
        WHERE m.project_id = %s ORDER BY m.sent_at ASC
    """, (project_id,))
    messages = cursor.fetchall()

    cursor.execute("""
        (SELECT u.user_id, u.username FROM project p
         JOIN user u ON p.owner_id = u.user_id WHERE p.project_id = %s)
        UNION
        (SELECT u.user_id, u.username FROM application a
         JOIN user u ON a.user_id = u.user_id
         WHERE a.project_id = %s AND a.status = 'accepted')
    """, (project_id, project_id))
    members = cursor.fetchall()

    conn.close()

    return render_template(
        "chat.html",
        messages=messages,
        members=members,
        project=project,
        project_id=project_id
    )


# =========================
# SOCKET.IO — JOIN ROOM
# =========================
@socketio.on("join")
def on_join(data):
    project_id = data.get("project_id")
    if project_id and "user_id" in session:
        join_room(f"project_{project_id}")


# =========================
# SOCKET.IO — SEND MESSAGE
# =========================
@socketio.on("send_message")
def on_send_message(data):
    if "user_id" not in session:
        return

    project_id = data.get("project_id")
    content    = (data.get("content") or "").strip()[:2000]

    if not project_id or not content:
        return

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM project WHERE project_id=%s", (project_id,))
    project  = cursor.fetchone()
    is_owner = project and project["owner_id"] == session["user_id"]

    cursor.execute("""
        SELECT * FROM application WHERE project_id=%s AND user_id=%s AND status='accepted'
    """, (project_id, session["user_id"]))
    membership = cursor.fetchone()

    if not is_owner and not membership:
        conn.close()
        return

    cursor.execute("""
        INSERT INTO message (sender_id, content, project_id) VALUES (%s, %s, %s)
    """, (session["user_id"], content, project_id))
    conn.commit()

    cursor.execute("""
        SELECT u.user_id FROM project p JOIN user u ON p.owner_id = u.user_id
        WHERE p.project_id = %s AND u.user_id != %s
        UNION
        SELECT a.user_id FROM application a
        WHERE a.project_id = %s AND a.status = 'accepted' AND a.user_id != %s
    """, (project_id, session["user_id"], project_id, session["user_id"]))
    members = cursor.fetchall()

    notif_msg = f"💬 {session['username']} sent a message in \"{project['project_name']}\""
    for m in members:
        cursor.execute("""
            INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
            VALUES (%s, 'message', %s, %s, 0, NOW())
        """, (m["user_id"], notif_msg, project_id))
    conn.commit()

    emit("receive_message", {
        "sender_id": session["user_id"],
        "username":  session["username"],
        "content":   content
    }, room=f"project_{project_id}")

    conn.close()


# =========================
# EDIT PROJECT
# =========================
@app.route("/edit-project/<int:project_id>", methods=["GET", "POST"])
def edit_project(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM project WHERE project_id=%s", (project_id,))
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
        SELECT COUNT(*) AS cnt FROM application WHERE project_id=%s AND status='accepted'
    """, (project_id,))
    accepted_count = cursor.fetchone()["cnt"]

    if request.method == "POST":
        name            = request.form.get("project_name", "").strip()[:150]
        desc            = request.form.get("description", "").strip()[:3000]
        status          = request.form.get("status", "active")
        selected_skills = request.form.getlist("skills")
        max_members_raw = request.form.get("max_members", "").strip()
        max_members     = int(max_members_raw) if max_members_raw.isdigit() else None

        if max_members is not None and max_members < accepted_count:
            cursor.execute("SELECT * FROM skill ORDER BY skill_name")
            skills = cursor.fetchall()
            cursor.execute("SELECT skill_id FROM project_skill WHERE project_id=%s", (project_id,))
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
            UPDATE project SET project_name=%s, description=%s, status=%s,
            max_members=%s, updated_at=NOW() WHERE project_id=%s
        """, (name, desc, status, max_members, project_id))

        cursor.execute("DELETE FROM project_skill WHERE project_id=%s", (project_id,))
        for skill_id in selected_skills:
            cursor.execute("""
                INSERT INTO project_skill (project_id, skill_id) VALUES (%s, %s)
            """, (project_id, skill_id))

        conn.commit()
        conn.close()
        return redirect(url_for("home_page"))

    cursor.execute("SELECT * FROM skill ORDER BY skill_name")
    skills = cursor.fetchall()

    cursor.execute("SELECT skill_id FROM project_skill WHERE project_id=%s", (project_id,))
    selected_skill_ids = {row["skill_id"] for row in cursor.fetchall()}

    conn.close()
    return render_template(
        "edit_project.html",
        project=project,
        skills=skills,
        selected_skill_ids=selected_skill_ids,
        accepted_count=accepted_count
    )


# =========================
# PROJECT REQUESTS
# =========================
@app.route("/project-requests")
def project_requests():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT a.application_id, a.project_id, p.project_name, p.max_members, u.username,
               (SELECT COUNT(*) FROM application a2
                WHERE a2.project_id = p.project_id AND a2.status = 'accepted') AS accepted_count
        FROM application a
        JOIN project p ON a.project_id = p.project_id
        JOIN user u ON a.user_id = u.user_id
        WHERE p.owner_id=%s AND a.status='pending'
        ORDER BY p.project_name
    """, (session["user_id"],))

    requests = cursor.fetchall()
    for r in requests:
        r["is_full"] = r["max_members"] is not None and r["accepted_count"] >= r["max_members"]

    conn.close()
    return render_template("project_requests.html", requests=requests, username=session["username"])


# =========================
# ACCEPT REQUEST
# FIX: changed to POST to prevent CSRF via URL
# =========================
@app.route("/accept-request/<int:application_id>", methods=["POST"])
def accept_request(application_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.owner_id FROM application a
        JOIN project p ON a.project_id = p.project_id
        WHERE a.application_id=%s
    """, (application_id,))
    row = cursor.fetchone()

    if not row or row["owner_id"] != session["user_id"]:
        conn.close()
        flash("Not authorized.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT a.user_id, p.project_name, a.project_id FROM application a
        JOIN project p ON a.project_id = p.project_id WHERE a.application_id = %s
    """, (application_id,))
    app_info = cursor.fetchone()

    cursor.execute("UPDATE application SET status='accepted' WHERE application_id=%s", (application_id,))

    if app_info:
        cursor.execute("""
            INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
            VALUES (%s, 'accepted', %s, %s, 0, NOW())
        """, (
            app_info["user_id"],
            f"Your application to join \"{app_info['project_name']}\" has been accepted!",
            app_info["project_id"]
        ))

    conn.commit()
    conn.close()
    return redirect(url_for("project_requests"))


# =========================
# REJECT REQUEST
# FIX: changed to POST to prevent CSRF via URL
# =========================
@app.route("/reject-request/<int:application_id>", methods=["POST"])
def reject_request(application_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.owner_id FROM application a
        JOIN project p ON a.project_id = p.project_id WHERE a.application_id=%s
    """, (application_id,))
    row = cursor.fetchone()

    if not row or row["owner_id"] != session["user_id"]:
        conn.close()
        flash("Not authorized.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT a.user_id, p.project_name, a.project_id FROM application a
        JOIN project p ON a.project_id = p.project_id WHERE a.application_id = %s
    """, (application_id,))
    app_info = cursor.fetchone()

    cursor.execute("UPDATE application SET status='rejected' WHERE application_id=%s", (application_id,))

    if app_info:
        cursor.execute("""
            INSERT INTO notification (user_id, notif_type, message, project_id, is_read, created_at)
            VALUES (%s, 'rejected', %s, %s, 0, NOW())
        """, (
            app_info["user_id"],
            f"Your application to join \"{app_info['project_name']}\" was not accepted this time.",
            app_info["project_id"]
        ))

    conn.commit()
    conn.close()
    return redirect(url_for("project_requests"))


# =========================
# PROJECT MEMBERS
# =========================
@app.route("/project-members/<int:project_id>")
def project_members(project_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT u.username FROM application a
        JOIN user u ON a.user_id=u.user_id
        WHERE a.project_id=%s AND a.status='accepted'
    """, (project_id,))

    members = cursor.fetchall()
    conn.close()

    return render_template("project_members.html", members=members)


# =========================
# USER PROFILE
# =========================
@app.route("/profile")
@app.route("/profile/<int:user_id>")
def profile(user_id=None):
    if "user_id" not in session:
        return redirect(url_for("home"))

    target_id = user_id if user_id is not None else session["user_id"]

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM user WHERE user_id = %s", (target_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("User not found.", "danger")
        return redirect(url_for("home_page"))

    cursor.execute("""
        SELECT s.skill_name, us.level FROM user_skill us
        JOIN skill s ON us.skill_id = s.skill_id
        WHERE us.user_id = %s ORDER BY s.skill_name
    """, (target_id,))
    skills = cursor.fetchall()

    cursor.execute("SELECT * FROM project WHERE owner_id = %s ORDER BY created_at DESC", (target_id,))
    projects = cursor.fetchall()

    cursor.execute("""
        SELECT p.* FROM project p JOIN application a ON p.project_id = a.project_id
        WHERE a.user_id = %s AND a.status = 'accepted' ORDER BY p.created_at DESC
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


# =========================
# API: GET COMMENTS
# =========================
@app.route("/api/project/<int:project_id>/comments", methods=["GET"])
def api_get_comments(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.comment_id, c.user_id, c.content,
               DATE_FORMAT(c.created_at, '%%b %%d, %%Y · %%h:%%i %%p') AS created_at,
               u.username
        FROM project_comment c JOIN user u ON c.user_id = u.user_id
        WHERE c.project_id = %s ORDER BY c.created_at DESC
    """, (project_id,))

    comments = cursor.fetchall()
    conn.close()

    return jsonify({"comments": comments, "user_id": session["user_id"]})


# =========================
# API: POST COMMENT
# =========================
@app.route("/api/project/<int:project_id>/comments", methods=["POST"])
def api_post_comment(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data    = request.get_json()
    content = (data.get("content") or "").strip()[:2000]

    if not content:
        return jsonify({"error": "Comment cannot be empty"}), 400

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        INSERT INTO project_comment (project_id, user_id, content, created_at)
        VALUES (%s, %s, %s, NOW())
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


# =========================
# API: DELETE COMMENT
# =========================
@app.route("/api/comment/<int:comment_id>/delete", methods=["POST"])
def api_delete_comment(comment_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT user_id FROM project_comment WHERE comment_id = %s", (comment_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "Comment not found"}), 404

    if row["user_id"] != session["user_id"]:
        conn.close()
        return jsonify({"error": "Not authorized"}), 403

    cursor.execute("DELETE FROM project_comment WHERE comment_id = %s", (comment_id,))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


# =========================
# ADMIN DASHBOARD
# =========================
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS cnt FROM user")
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


# =========================
# ADMIN: MANAGE USERS
# =========================
@app.route("/admin/users")
@admin_required
def admin_users():
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

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


# =========================
# ADMIN: BAN / UNBAN USER
# FIX: changed to POST to prevent CSRF via URL
# =========================
@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@admin_required
def admin_ban_user(user_id):
    if user_id == session["user_id"]:
        return redirect(url_for("admin_users"))

    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT status FROM user WHERE user_id = %s", (user_id,))
    row = cursor.fetchone()

    if row:
        new_status = "active" if row["status"] == "banned" else "banned"
        cursor.execute("UPDATE user SET status = %s WHERE user_id = %s", (new_status, user_id))
        conn.commit()

    conn.close()
    return redirect(url_for("admin_users"))


# =========================
# ADMIN: DELETE USER
# FIX: changed to POST to prevent CSRF via URL
# =========================
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    if user_id == session["user_id"]:
        return redirect(url_for("admin_users"))

    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user WHERE user_id = %s", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_users"))


# =========================
# ADMIN: MANAGE PROJECTS
# =========================
@app.route("/admin/projects")
@admin_required
def admin_projects():
    conn   = get_db_connection()
    cursor = conn.cursor(dictionary=True)

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


# =========================
# ADMIN: DELETE PROJECT
# FIX: changed to POST to prevent CSRF via URL
# =========================
@app.route("/admin/projects/<int:project_id>/delete", methods=["POST"])
@admin_required
def admin_delete_project(project_id):
    conn   = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM project WHERE project_id = %s", (project_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_projects"))


# =========================
# STATIC / INFO PAGES
# =========================
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
            VALUES (%s, %s, %s, %s, NOW())
        """, (name, email, subject, message))
        conn.commit()
        conn.close()

        try:
            msg = Message(
                subject=f"[SkillHub Contact] {subject}",
                recipients=[ADMIN_EMAIL],
                reply_to=email,
                body=f"From: {name} <{email}>\n\n{message}"
            )
            mail.send(msg)
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


# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    socketio.run(app, debug=False)