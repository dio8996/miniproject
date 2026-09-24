"""
ZeroAttack – Blocked IP Management Routes
Allows administrators and security analysts to view, quarantine, and unblock source IP addresses.
"""

from flask import Blueprint, request, jsonify, session
from security.authorization import roles_required
from database.db import db_manager
import datetime

ips_bp = Blueprint("ips", __name__, url_prefix="/api/ips")

@ips_bp.route("", methods=["GET"])
def get_blocked_ips():
    return jsonify({
        "total": len(db_manager.in_memory_blocked_ips),
        "blocked_ips": db_manager.in_memory_blocked_ips
    })

@ips_bp.route("/block", methods=["POST"])
@roles_required("ADMIN")
def manually_block_ip():
    data = request.get_json() or {}
    ip_address = data.get("ip_address", "").strip()
    reason = data.get("reason", "Manual administrative quarantine").strip()
    duration_minutes = int(data.get("duration_minutes", 60))
    risk_score = int(data.get("risk_score", 85))

    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    # Check if already present
    existing = next((b for b in db_manager.in_memory_blocked_ips if b["ip_address"] == ip_address), None)
    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(minutes=duration_minutes)

    user = session.get("user", {})
    username = user.get("username", "admin")

    if existing:
        existing["status"] = "ACTIVE"
        existing["reason"] = reason
        existing["risk_score"] = risk_score
        existing["expires_at"] = expires_at.isoformat()
        existing["blocked_by"] = username
        entry = existing
    else:
        entry = {
            "id": len(db_manager.in_memory_blocked_ips) + 1,
            "ip_address": ip_address,
            "reason": reason,
            "risk_score": risk_score,
            "blocked_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "status": "ACTIVE",
            "blocked_by": username
        }
        db_manager.in_memory_blocked_ips.insert(0, entry)

    # Audit log
    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "action": "IP_BLOCK",
        "target": ip_address,
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"IP quarantined for {duration_minutes}m: {reason}"
    })

    return jsonify({"success": True, "entry": entry}), 201

@ips_bp.route("/<string:ip_address>/unblock", methods=["POST"])
@roles_required("ADMIN")
def unblock_ip(ip_address):
    entry = next((b for b in db_manager.in_memory_blocked_ips if b["ip_address"] == ip_address), None)
    if not entry:
        return jsonify({"error": "IP record not found"}), 404

    entry["status"] = "WHITELISTED"
    
    user = session.get("user", {})
    username = user.get("username", "admin")

    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "action": "IP_UNBLOCK",
        "target": ip_address,
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"IP {ip_address} unblocked and whitelisted"
    })

    return jsonify({"success": True, "entry": entry})
