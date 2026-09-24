"""
ZeroAttack – Security Events & Inspection Routes
Core engine integration for live request inspection, rule matching,
anomaly scoring, payload encryption, and forensic retrieval.
"""

from flask import Blueprint, request, jsonify, session
from detection.rule_engine import RuleEngine
from detection.anomaly_detector import AnomalyDetector
from detection.risk_scoring import RiskScorer
from security.encryption import SecurityEncryptionService
from security.authorization import roles_required
from database.db import db_manager
import datetime
import json

events_bp = Blueprint("events", __name__, url_prefix="/api/events")

rule_engine = RuleEngine()
anomaly_detector = AnomalyDetector()
risk_scorer = RiskScorer()
crypto_service = SecurityEncryptionService()

@events_bp.route("/analyze", methods=["POST"])
def analyze_request():
    """
    Main ZeroAttack live inspection endpoint.
    Processes: IP, Method, URL, Parameters, User-Agent, Frequency, Body.
    Returns calculated risk, severity, matched signatures, and mitigation decision.
    """
    data = request.get_json() or {}
    source_ip = data.get("source_ip", request.remote_addr or "127.0.0.1")
    method = data.get("method", "GET").upper()
    url = data.get("url", "/")
    parameters = data.get("parameters", "")
    user_agent = data.get("user_agent", request.headers.get("User-Agent", ""))
    frequency = data.get("frequency", 1)
    body = data.get("body", "")

    # Check if IP is currently blocked
    is_blocked = False
    for b in db_manager.in_memory_blocked_ips:
        if b["ip_address"] == source_ip and b.get("status") == "ACTIVE":
            is_blocked = True
            break

    # 1. Rule-based detection
    rule_results = rule_engine.inspect_request({
        "url": url,
        "method": method,
        "parameters": parameters,
        "user_agent": user_agent,
        "body": body
    })

    # 2. Anomaly detection
    anomaly_results = anomaly_detector.analyze_behavior({
        "source_ip": source_ip,
        "url": url,
        "user_agent": user_agent,
        "parameters": parameters,
        "method": method,
        "frequency": frequency
    })

    # 3. Composite Risk Scoring
    risk_assessment = risk_scorer.calculate_risk(
        rule_results,
        anomaly_results,
        is_ip_previously_flagged=is_blocked
    )

    # 4. Encrypt sensitive security payload (Architectural Flow)
    raw_forensic_packet = {
        "source_ip": source_ip,
        "method": method,
        "url": url,
        "parameters": parameters,
        "user_agent": user_agent,
        "body": body,
        "inspection_timestamp": datetime.datetime.utcnow().isoformat()
    }
    encrypted_record = crypto_service.encrypt_payload(raw_forensic_packet)

    # 5. Persist Security Event
    event_id = len(db_manager.in_memory_events) + 1
    new_event = {
        "id": event_id,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "request_method": method,
        "request_url": url,
        "user_agent": user_agent,
        "attack_type": risk_assessment["attack_type"],
        "detection_method": risk_assessment["detection_method"],
        "risk_score": risk_assessment["risk_score"],
        "severity": risk_assessment["severity"],
        "action_taken": risk_assessment["action_taken"],
        "status": "DETECTED" if risk_assessment["risk_score"] > 25 else "RESOLVED",
        "detection_reason": risk_assessment["detection_reason"],
        "encrypted_payload": encrypted_record,
        "breakdown": risk_assessment["breakdown"],
        "matched_indicators": rule_results["matched_indicators"],
        "anomaly_flags": anomaly_results["flags"]
    }
    db_manager.in_memory_events.insert(0, new_event)

    # 6. Automated Mitigation Trigger (Auto-block high-risk IPs)
    mitigation_applied = False
    if risk_assessment["should_block_ip"] and not is_blocked:
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        blocked_entry = {
            "id": len(db_manager.in_memory_blocked_ips) + 1,
            "ip_address": source_ip,
            "reason": f"Auto-blocked: {risk_assessment['attack_type']} (Risk Score: {risk_assessment['risk_score']})",
            "risk_score": risk_assessment["risk_score"],
            "blocked_at": datetime.datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
            "status": "ACTIVE",
            "blocked_by": "SYSTEM_AUTO_BLOCK"
        }
        db_manager.in_memory_blocked_ips.insert(0, blocked_entry)
        mitigation_applied = True

        # Audit log for mitigation
        db_manager.in_memory_audit_logs.insert(0, {
            "id": len(db_manager.in_memory_audit_logs) + 1,
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "username": "SYSTEM",
            "action": "AUTO_IP_BLOCK",
            "target": source_ip,
            "ip_address": source_ip,
            "details": f"Automated quarantine triggered for {risk_assessment['severity']} incident (Risk: {risk_assessment['risk_score']})"
        })

    # Return comprehensive analysis to frontend
    return jsonify({
        "success": True,
        "event_id": event_id,
        "source_ip": source_ip,
        "risk_score": risk_assessment["risk_score"],
        "severity": risk_assessment["severity"],
        "attack_type": risk_assessment["attack_type"],
        "detection_method": risk_assessment["detection_method"],
        "action_taken": risk_assessment["action_taken"],
        "detection_reason": risk_assessment["detection_reason"],
        "mitigation_applied": mitigation_applied,
        "rule_matches": rule_results["matched_indicators"],
        "anomaly_analysis": anomaly_results,
        "encryption_applied": True,
        "cipher_preview": encrypted_record[:40] + "..." if encrypted_record else ""
    })

@events_bp.route("", methods=["GET"])
def list_events():
    """Returns security incidents with optional filtering."""
    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    search = request.args.get("search", "").lower()

    filtered = db_manager.in_memory_events
    if severity:
        filtered = [e for e in filtered if e["severity"] == severity.upper()]
    if attack_type:
        filtered = [e for e in filtered if e["attack_type"] == attack_type]
    if search:
        filtered = [
            e for e in filtered if (
                search in e["source_ip"].lower() or 
                search in e["request_url"].lower() or 
                search in e["attack_type"].lower()
            )
        ]

    return jsonify({
        "total": len(filtered),
        "events": filtered[:100]
    })

@events_bp.route("/<int:event_id>", methods=["GET"])
def get_event_details(event_id):
    """Retrieves full forensic details for a single incident."""
    event = next((e for e in db_manager.in_memory_events if e["id"] == event_id), None)
    if not event:
        return jsonify({"error": "Event not found"}), 404
    return jsonify({"event": event})

@events_bp.route("/<int:event_id>/decrypt", methods=["POST"])
@roles_required("ADMIN", "SECURITY ANALYST")
def decrypt_event_payload(event_id):
    """
    Decryption flow: Authorized analysts/admins can decrypt encrypted payload records.
    """
    event = next((e for e in db_manager.in_memory_events if e["id"] == event_id), None)
    if not event or not event.get("encrypted_payload"):
        return jsonify({"error": "No encrypted payload found for this event"}), 404

    decrypted_json_str = crypto_service.decrypt_payload(event["encrypted_payload"])
    
    # Audit decryption action
    user = session.get("user", {})
    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": user.get("username", "analyst"),
        "action": "DECRYPT_PAYLOAD",
        "target": f"EVENT_#{event_id}",
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"Forensic decryption authorized for IP {event.get('source_ip')}"
    })

    return jsonify({
        "event_id": event_id,
        "encrypted_ciphertext": event["encrypted_payload"],
        "decrypted_plaintext": decrypted_json_str,
        "cryptographic_flow": {
            "plain_data": "Raw HTTP request params, body, headers",
            "encryption_module": "AES-256-GCM 96-bit Nonce + 128-bit MAC",
            "encrypted_record": "Base64 database ciphertext",
            "authorized_decryption": f"Decrypted by role {user.get('role', 'ADMIN')}"
        }
    })

@events_bp.route("/<int:event_id>/status", methods=["PATCH"])
@roles_required("ADMIN", "SECURITY ANALYST")
def update_event_status(event_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    valid_statuses = ["DETECTED", "INVESTIGATING", "MITIGATED", "RESOLVED", "FALSE_POSITIVE"]
    if new_status not in valid_statuses:
        return jsonify({"error": "Invalid status"}), 400

    event = next((e for e in db_manager.in_memory_events if e["id"] == event_id), None)
    if not event:
        return jsonify({"error": "Event not found"}), 404

    event["status"] = new_status
    user = session.get("user", {})
    db_manager.in_memory_audit_logs.insert(0, {
        "id": len(db_manager.in_memory_audit_logs) + 1,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "username": user.get("username", "analyst"),
        "action": "UPDATE_EVENT_STATUS",
        "target": f"EVENT_#{event_id}",
        "ip_address": request.remote_addr or "127.0.0.1",
        "details": f"Status updated to {new_status}"
    })

    return jsonify({"success": True, "event": event})
