import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# File paths
ENCRYPTION_KEY_FILE = BASE_DIR / 'encryption_key.key'
ENCRYPTED_DATA_FILE = BASE_DIR / 'encrypted_data.json'
LOG_FILE = BASE_DIR / 'app.log'
STYLE_FILE = BASE_DIR / 'style.css'

# Security settings
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes in seconds
PASSKEY_MIN_LENGTH = 8
PASSKEY_REQUIREMENTS = {
    'min_length': 8,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_numbers': True,
    'require_special': True
}

# Encryption settings
KEY_ROTATION_DAYS = 30
SALT_LENGTH = 32
ITERATIONS = 100000

# UI settings
THEME = {
    'primaryColor': '#2563eb',
    'backgroundColor': '#f8fafc',
    'secondaryBackgroundColor': '#ffffff',
    'textColor': '#1e293b',
    'font': 'Inter',
    'successColor': '#10b981',
    'errorColor': '#ef4444',
    'warningColor': '#f59e0b',
    'borderColor': '#e2e8f0'
}

# Layout settings
PAGE_CONFIG = {
    'page_title': 'Secure Data Encryption',
    'page_icon': '🔐',
    'layout': 'wide',
    'initial_sidebar_state': 'expanded',
    'menu_items': {
        'Get Help': 'https://github.com/yourusername/secure-encryption-app',
        'Report a bug': 'https://github.com/yourusername/secure-encryption-app/issues',
        'About': 'A secure data encryption application built with Streamlit'
    }
}

# Create necessary directories
os.makedirs(BASE_DIR, exist_ok=True) 