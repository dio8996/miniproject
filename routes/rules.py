"""
ZeroAttack – Detection Rules Management Routes
Allows authorized administrators to create, update, toggle, and delete attack signatures.
"""

from flask import Blueprint, request, jsonify, session
from security.authorization import roles_required
from database.db import db_manager
import datetime

rules_bp = Blueprint("rules", __name__, url_prefix="/api/rules")

@rules_bp.route("", methods=["GET"])
def get_rules():
    return jsonify({
        "total": len(db_manager.in_memory_rules),
        "rules": db_manager.in_memory_rules
    })

@rules_bp.route("", methods=["POST"])
@roles_required("ADMIN")
def create_rule():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    attack_type = data.get("attack_type", "SQL Injection")
    pattern = data.get("pattern", "").strip()
    target_field = data.get("target_field", "ALL")
    severity = data.get("severity", "MEDIUM")
    risk_weight = int(data.get("risk_weight", 50))
    description = data.get("description", "")

    if not name or not pattern:
        return jsonify({"error": "Rule name and regex pattern are required"}), 400

    new_rule = {
        "id": len(db_manager.in_memory_rules) + 1,
        "name": name,
        "attack_type": attack_type,
        "pattern": pattern,
        "target_field": target_field,
        "description": description,
        "severity": severity,
        "risk_weight": risk_weight,
        "is_active": True
    }
    db_manager.in_memory_rules.append(new_rule)

    # Audit log
    user = session.get("user", {})
    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": user.get("username", "admin"),
        "action": "RULE_CREATE",
        "target": name,
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"Created {attack_type} rule with severity {severity}"
    })

    return jsonify({"success": True, "rule": new_rule}), 201

@rules_bp.route("/<int:rule_id>/toggle", methods=["PATCH"])
@roles_required("ADMIN")
def toggle_rule(rule_id):
    rule = next((r for r in db_manager.in_memory_rules if r["id"] == rule_id), None)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    rule["is_active"] = not rule["is_active"]
    status_str = "ENABLED" if rule["is_active"] else "DISABLED"

    user = session.get("user", {})
    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": user.get("username", "admin"),
        "action": "RULE_TOGGLE",
        "target": rule["name"],
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"Rule {rule['name']} set to {status_str}"
    })

    return jsonify({"success": True, "rule": rule})

@rules_bp.route("/<int:rule_id>", methods=["DELETE"])
@roles_required("ADMIN")
def delete_rule(rule_id):
    rule = next((r for r in db_manager.in_memory_rules if r["id"] == rule_id), None)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    db_manager.in_memory_rules = [r for r in db_manager.in_memory_rules if r["id"] != rule_id]

    user = session.get("user", {})
    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": user.get("username", "admin"),
        "action": "RULE_DELETE",
        "target": rule["name"],
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"Rule {rule['name']} permanently removed"
    })

    return jsonify({"success": True, "message": "Rule deleted"})
