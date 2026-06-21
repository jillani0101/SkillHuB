import os
import re
import secrets
from flask import Blueprint, redirect, url_for, session, flash
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash
from db import get_db_connection

google_auth = Blueprint("google_auth", __name__)
oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name="google",
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

def _make_username(base):
    base = re.sub(r"[^a-zA-Z0-9_]", "", base).lower()[:40] or "user"
    conn = get_db_connection()
    cursor = conn.cursor()
    candidate = base
    suffix = 0
    while True:
        cursor.execute('SELECT user_id FROM "user" WHERE username=%s', (candidate,))
        if not cursor.fetchone():
            break
        suffix += 1
        candidate = f"{base}{suffix}"
    conn.close()
    return candidate

@google_auth.route("/login/google")
def login_google():
    redirect_uri = url_for("google_auth.google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@google_auth.route("/login/google/callback")
def google_callback():
    token = oauth.google.authorize_access_token()
    info = token.get("userinfo")
    if not info or not info.get("email_verified"):
        flash("Google login failed.", "danger")
        return redirect(url_for("login"))

    email = info["email"].strip().lower()
    name = info.get("name", email.split("@")[0])
    google_id = info["sub"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM "user" WHERE email=%s', (email,))
    user = cursor.fetchone()

    if user:
        if user.get("status") == "banned":
            conn.close()
            flash("Your account has been banned. Contact the site administrator.", "danger")
            return redirect(url_for("login"))
        if not user.get("google_id"):
            cursor.execute('UPDATE "user" SET google_id=%s WHERE user_id=%s', (google_id, user["user_id"]))
            conn.commit()
        conn.close()
        session["user_id"] = user["user_id"]
        session["username"] = user["username"]
        session["role"] = user.get("role", "user")
        return redirect(url_for("home_page"))

    username = _make_username(name or email.split("@")[0])
    placeholder_password = generate_password_hash(secrets.token_urlsafe(24))
    cursor.execute("""
        INSERT INTO "user" (username, email, password, status, role, google_id, is_verified, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, 1, NOW()) RETURNING user_id
    """, (username, email, placeholder_password, "active", "user", google_id))
    conn.commit()
    new_user_id = cursor.fetchone()["user_id"]
    conn.close()

    session["user_id"] = new_user_id
    session["username"] = username
    session["role"] = "user"
    return redirect(url_for("setup_skills"))
