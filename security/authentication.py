"""
ZeroAttack – Authentication Module
Handles secure password hashing, token validation, and session management.
"""

from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask import request, jsonify, session
from config import Config

def hash_password(password: str) -> str:
    """Hashes password with PBKDF2/scrypt using secure salt."""
    return generate_password_hash(password, method="scrypt")

def verify_password(password_hash: str, password: str) -> bool:
    """Safely compares input against stored password hash."""
    return check_password_hash(password_hash, password)

def generate_jwt_token(user_id: int, username: str, role: str) -> str:
    """Generates a signed JWT authentication token."""
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=Config.TOKEN_EXPIRATION_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")

def decode_jwt_token(token: str) -> dict:
    """Decodes and validates a JWT token."""
    try:
        return jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def login_required(f):
    """Decorator to enforce authenticated session or JWT header."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check Flask session
        if "user" in session:
            return f(*args, **kwargs)

        # 2. Check Authorization Bearer header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            decoded = decode_jwt_token(token)
            if decoded:
                session["user"] = decoded
                return f(*args, **kwargs)

        return jsonify({"error": "Authentication required. Please log in."}), 401
    return decorated_function
