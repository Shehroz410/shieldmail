import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "cyber-shield-email-sec-scanner-key-2026")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "email_scanner.db"))
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
