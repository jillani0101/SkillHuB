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
- PostgreSQL (schema auto-created via `db.py`)
- Flask-SocketIO (chat, with HTTP fallback) + Flask-WTF (CSRF)
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
# DATABASE_URL is required — use a hosted Postgres (e.g. Neon / Supabase).

# 4. Run
python app.py          # http://localhost:5000
```

The schema (tables + seed skills) is created automatically in PostgreSQL on first use.

## Environment variables (`.env`)

| Variable | Required | Purpose |
| -------- | -------- | ------- |
| `SECRET_KEY` | yes | Flask session signing key |
| `DATABASE_URL` | yes | PostgreSQL connection string (`postgres://user:pass@host:5432/dbname`) |
| `MAIL_USERNAME` | no | Gmail address used for SMTP fallback |
| `MAIL_PASSWORD` | no | Gmail app password for SMTP fallback |
| `ADMIN_EMAIL` | no | Receives contact-form submissions |
| `RESEND_API_KEY` | no | Preferred email provider (falls back to SMTP) |
| `GOOGLE_CLIENT_ID` | no | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | no | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | no | Exact OAuth callback URL to send Google; auto-detected when blank |
| `COOKIE_SECURE` | no | Set `1` to force HTTPS-only cookies (deployment) |
| `PORT` | no | Port for `python app.py` (default 5000) |

## Deployment (Vercel)

```bash
npx vercel          # preview
npx vercel --prod   # production
```

- `vercel.json` routes every request to `api/index.py`, which loads the Flask app.
- Set all secrets + `DATABASE_URL` as environment variables in the Vercel project settings. The app reads the env from Vercel directly (no `.env` is uploaded).
- Set `COOKIE_SECURE=1` and `GOOGLE_REDIRECT_URI=https://<your-project>.vercel.app/login/google/callback` in production.
- **Socket.IO note:** Vercel serverless functions don't support WebSockets, but chat has an HTTP polling fallback that keeps working.
- **Google console:** make sure the exact `GOOGLE_REDIRECT_URI` is listed under Credentials → OAuth 2.0 Client ID → Authorized redirect URIs.

## Layout

```
app.py                 Flask application (routes, mailer, Socket.IO)
db.py                  PostgreSQL connection + schema
google_auth.py         Google OAuth blueprint
api/index.py           Vercel serverless entry point
vercel.json            Vercel build/routing config
init_db.py             Legacy SQLite helper (kept for reference)
wsgi.py                WSGI entry point (loads .env)
templates/             Jinja2 templates (base + pages)
static/style.css       Design system
```