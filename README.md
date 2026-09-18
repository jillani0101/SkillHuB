# SkillHub

SkillHub is a web-based platform that connects students and developers based on their skills, enabling them to collaborate on projects, build teams, and communicate effectively.

## Features

- **Skill-based profiles** — pick your skills and level, then get matched with projects that need them.
- **Projects & applications** — post a project, list the skills it needs, review applicants, and build a team.
- **Team chat** — real-time Socket.IO chat with an HTTP polling fallback, so it works anywhere.
- **Notifications** — application updates and project activity, with an unread badge in the navbar.
- **Email verification & password reset** — delivered via Resend with SMTP fallback.
- **Google Sign-In** — one-click OAuth login.
- **Comments** — lightweight discussion on every project.
- **Admin dashboard** — manage users, projects, and contact messages.
- **Rate limiting** — login attempts and email resend cooldowns to slow down abuse.

## Tech stack

- Python 3 + Flask
- SQLite (auto-created schema via `db.py`, no external DB needed)
- Flask-SocketIO (chat) + Flask-WTF (CSRF)
- Authlib (Google OAuth)
- Resend + Gmail SMTP (email)
- Single design-system stylesheet (no framework)

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
# Windows: .venv\Scripts\activate   |   macOS/Linux: source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env   # then fill in your secrets (keep .env out of git)

# 4. Run
python app.py          # http://localhost:5000
```

The database is created automatically as `skillhub.db` in the project root the first time the app starts. To wipe and rebuild it, delete the file (or run `python init_db.py`).

## Environment variables (`.env`)

| Variable | Required | Purpose |
| -------- | -------- | ------- |
| `SECRET_KEY` | yes | Flask session signing key |
| `MAIL_USERNAME` | no | Gmail address used for SMTP fallback |
| `MAIL_PASSWORD` | no | Gmail app password for SMTP fallback |
| `ADMIN_EMAIL` | no | Receives contact-form submissions |
| `RESEND_API_KEY` | no | Preferred email provider (falls back to SMTP) |
| `GOOGLE_CLIENT_ID` | no | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | no | Google OAuth client secret |
| `DATABASE_PATH` | no | Override of the SQLite database file location |
| `COOKIE_SECURE` | no | Set `1` to force HTTPS-only cookies (deployment) |
| `PORT` | no | Port for `python app.py` (default 5000) |

## Deployment (PythonAnywhere / Heroku / Render)

The app is WSGI-ready:

```bash
# PythonAnywhere: point your WSGI config at wsgi.py (it loads .env and exposes `application`)
gunicorn -k eventlet -w 1 wsgi:application
```

- **PythonAnywhere** does not support `pip install` in SAAS parts? If you run on a free plan, install the requirements in a virtualenv and set the WSGI file to:

  ```python
  import sys
  sys.path.insert(0, "/home/<username>/<project>")
  from wsgi import application
  ```

- Use `Procfile` (Heroku/Render): `web: gunicorn -k eventlet -w 1 wsgi:application`.

> **Note:** Set `COOKIE_SECURE=1` and `SESSION_COOKIE_SAMESITE` as appropriate in production behind HTTPS.

## Layout

```
app.py                 Flask application (routes, mailer, Socket.IO)
db.py                  SQLite connection + schema
google_auth.py         Google OAuth blueprint
init_db.py             Rebuilds the database schema
wsgi.py                WSGI entry point (loads .env)
templates/             Jinja2 templates (base + pages)
static/style.css       Design system
```