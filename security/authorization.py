"""
ZeroAttack – Authorization Module (Role-Based Access Control)
Enforces permissions for ADMIN, SECURITY ANALYST, and VIEWER roles.
"""

from functools import wraps
from flask import session, jsonify

ROLE_HIERARCHY = {
    "ADMIN": 3,
    "SECURITY ANALYST": 2,
    "VIEWER": 1
}

PERMISSIONS = {
    "ADMIN": [
        "full_system_management",
        "manage_users",
        "manage_rules",
        "view_all_events",
        "manage_blocked_ips",
        "view_reports",
        "override_mitigation",
        "decrypt_sensitive_records",
        "trigger_simulation",
        "export_data"
    ],
    "SECURITY ANALYST": [
        "view_live_incidents",
        "investigate_attacks",
        "view_alerts",
        "view_reports",
        "review_security_events",
        "decrypt_sensitive_records",
        "trigger_simulation",
        "export_data"
    ],
    "VIEWER": [
        "view_dashboard",
        "view_statistics",
        "view_historical_info"
    ]
}

def get_current_user():
    """Retrieves authenticated user details from session."""
    return session.get("user", {
        "id": 0,
        "username": "guest",
        "role": "VIEWER"
    })

def has_permission(role: str, permission: str) -> bool:
    """Checks if a given role possesses a required capability."""
    allowed = PERMISSIONS.get(role, [])
    return permission in allowed

def roles_required(*allowed_roles):
    """
    Decorator to restrict route execution to specific roles.
    Example: @roles_required('ADMIN', 'SECURITY ANALYST')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get("user")
            if not user:
                return jsonify({"error": "Unauthorized: Session expired or invalid"}), 401
            
            user_role = user.get("role", "VIEWER")
            if user_role not in allowed_roles:
                return jsonify({
                    "error": "Forbidden: Insufficient privileges for role",
                    "user_role": user_role,
                    "required_roles": list(allowed_roles)
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
