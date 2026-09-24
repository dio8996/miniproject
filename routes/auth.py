"""
ZeroAttack – Authentication Routes
Handles user registration, login, logout, and current user inspection.
"""

from flask import Blueprint, request, jsonify, session
from security.authentication import hash_password, verify_password, generate_jwt_token
from database.db import db_manager
import datetime

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Demo accounts check for testing convenience
    demo_users = {
        "admin": {"role": "ADMIN", "email": "admin@zeroattack.sec", "id": 1},
        "analyst": {"role": "SECURITY ANALYST", "email": "analyst@zeroattack.sec", "id": 2},
        "viewer": {"role": "VIEWER", "email": "viewer@zeroattack.sec", "id": 3}
    }

    user_info = None
    if username.lower() in demo_users:
        demo = demo_users[username.lower()]
        # Demo users accept any password with standard default or matching demo
        user_info = {
            "id": demo["id"],
            "username": username,
            "email": demo["email"],
            "role": demo["role"]
        }
    else:
        # Check database
        conn = db_manager.get_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT id, username, email, password_hash, role, is_active FROM users WHERE username = %s", (username,))
                    row = cursor.fetchone()
                    if row and verify_password(row["password_hash"], password):
                        if not row["is_active"]:
                            return jsonify({"error": "Account is disabled. Contact your administrator."}), 403
                        user_info = {
                            "id": row["id"],
                            "username": row["username"],
                            "email": row["email"],
                            "role": row["role"]
                        }
            finally:
                conn.close()

    if not user_info:
        return jsonify({"error": "Invalid username or password"}), 401

    token = generate_jwt_token(user_info["id"], user_info["username"], user_info["role"])
    session["user"] = user_info

    # Record login in audit logs
    db_manager.in_memory_audit_logs.append({
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": user_info["username"],
        "action": "LOGIN",
        "target": "SESSION",
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"User authenticated with role {user_info['role']}"
    })

    return jsonify({
        "message": "Authentication successful",
        "user": user_info,
        "token": token
    })

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    requested_role = data.get("role", "VIEWER").upper()

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    if requested_role not in ["ADMIN", "SECURITY ANALYST", "VIEWER"]:
        requested_role = "VIEWER"

    hashed = hash_password(password)

    conn = db_manager.get_connection()
    if conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                    (username, email, hashed, requested_role)
                )
                conn.commit()
                user_id = cursor.lastrowid
        except Exception as e:
            return jsonify({"error": f"Registration failed: {str(e)}"}), 409
        finally:
            conn.close()
    else:
        user_id = len(db_manager.in_memory_users) + 10
        db_manager.in_memory_users.append({
            "id": user_id,
            "username": username,
            "email": email,
            "role": requested_role
        })

    return jsonify({
        "message": "User registered successfully",
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "role": requested_role
        }
    }), 201

@auth_bp.route("/me", methods=["GET"])
def current_user():
    user = session.get("user")
    if not user:
        return jsonify({"authenticated": False, "user": None})
    return jsonify({"authenticated": True, "user": user})

@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = session.pop("user", None)
    if user:
        db_manager.in_memory_audit_logs.append({
            "id": len(db_manager.in_memory_audit_logs) + 1,
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "username": user.get("username", "user"),
            "action": "LOGOUT",
            "target": "SESSION",
            "ip_address": request.remote_addr or "127.0.0.1",
            "details": "User terminated active session"
        })
    return jsonify({"message": "Logged out successfully"})
