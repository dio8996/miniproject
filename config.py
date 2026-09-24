"""
ZeroAttack – Configuration Module
Handles environment variables, database connection settings, and security keys.
"""

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask settings
    SECRET_KEY = os.getenv("SECRET_KEY", "zeroattack-super-secret-system-key-2026")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    PORT = int(os.getenv("PORT", 5000))

    # MySQL Database credentials
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", 3306))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "password123")
    DB_NAME = os.getenv("DB_NAME", "zeroattack_db")

    # Security & Encryption settings
    # 32-byte key for AES-256 (base64 encoded or raw string)
    ENCRYPTION_KEY = os.getenv(
        "ENCRYPTION_KEY", 
        "k7Fq8xZ9p2L5mV3jH1wQ0eR4tY6uI8oP9sA3dF5gH7j="
    )

    # Anomaly Detection thresholds
    REQUEST_FREQUENCY_THRESHOLD = int(os.getenv("REQUEST_FREQ_THRESHOLD", 20))  # requests per minute
    SUSPICIOUS_AGENT_SENSITIVITY = float(os.getenv("AGENT_SENSITIVITY", 1.5))
    AUTO_BLOCK_RISK_THRESHOLD = int(os.getenv("AUTO_BLOCK_RISK_THRESHOLD", 80)) # Score >= 80 blocks IP
    BLOCK_DURATION_MINUTES = int(os.getenv("BLOCK_DURATION_MINUTES", 30))

    # JWT / Session settings
    TOKEN_EXPIRATION_HOURS = int(os.getenv("TOKEN_EXP_HOURS", 8))
