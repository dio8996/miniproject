"""
ZeroAttack – User & Role Management Routes
RBAC administration for ADMIN, SECURITY ANALYST, and VIEWER roles.
"""

from flask import Blueprint, request, jsonify, session
from security.authorization import roles_required
from database.db import db_manager
import datetime

users_bp = Blueprint("users", __name__, url_prefix="/api/users")

@users_bp.route("", methods=["GET"])
@roles_required("ADMIN")
def list_users():
    users_list = [
        {"id": 1, "username": "admin", "email": "admin@zeroattack.sec", "role": "ADMIN", "is_active": True, "last_login": "Just now"},
        {"id": 2, "username": "analyst", "email": "analyst@zeroattack.sec", "role": "SECURITY ANALYST", "is_active": True, "last_login": "2 hours ago"},
        {"id": 3, "username": "viewer", "email": "viewer@zeroattack.sec", "role": "VIEWER", "is_active": True, "last_login": "Yesterday"},
    ]
    return jsonify({
        "users": users_list + db_manager.in_memory_users
    })

@users_bp.route("/audit-logs", methods=["GET"])
def get_audit_logs():
    return jsonify({
        "total": len(db_manager.in_memory_audit_logs),
        "logs": db_manager.in_memory_audit_logs
    })
