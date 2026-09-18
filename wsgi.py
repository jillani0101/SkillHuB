import os
from pathlib import Path

from dotenv import load_dotenv

# Ensure the environment is loaded before the app is imported
# (works on PythonAnywhere and other WSGI hosts).
load_dotenv(Path(__file__).resolve().parent / ".env")

from app import app as application  # noqa: E402