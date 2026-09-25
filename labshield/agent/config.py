"""
LabShield agent configuration.
Teacher fills exam details before starting; secrets live here only.
"""

import os

# Project root directory absolute path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))



# Exam metadata — teacher sets these before running the agent
EXAM_QUESTION = ""  # exam question text entered by teacher
STUDENT_NAME = ""  # optional student identifier

# Paths relative to labshield/ project root
DB_PATH = "data/labshield.db"
LOG_PATH = "logs/errors.log"

# HMAC secret for tamper-proof log signing (change in production)
HMAC_SECRET = "labshield-secret-change-this"

# Clipboard paste threshold — pastes above this char count are flagged
CLIPBOARD_FLAG_THRESHOLD = 100

# Keystroke velocity measurement window in seconds
KEYSTROKE_WINDOW = 5

# Keys per second above this rate triggers paste-velocity suspicion
KEYSTROKE_VELOCITY_THRESHOLD = 20

# Gemini API key — get from https://aistudio.google.com/app/apikey
GEMINI_API_KEY = ""

# Dashboard login password — teacher changes this before each exam
DASHBOARD_PASSWORD = "labshield123"

# Flask session signing secret — change in production
FLASK_SECRET_KEY = "labshield-flask-secret-change-this"

# Flag file written by dashboard /api/end to request agent shutdown
SHUTDOWN_FLAG_PATH = "data/agent_shutdown.flag"
