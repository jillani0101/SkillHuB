import os
import sys

# Make the project root importable and the current working directory so the
# Flask app (templates, static) and db.py resolve correctly inside the
# serverless function.
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _APP_DIR)
os.chdir(_APP_DIR)

# Vercel's Python runtime exposes the Flask app via a module-level `app`.
from app import app