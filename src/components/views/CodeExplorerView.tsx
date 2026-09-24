import React, { useState } from 'react';
import { Code, Copy, Check, FileText, Database, Shield, Terminal } from 'lucide-react';

export const CodeExplorerView: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<string>('detection/rule_engine.py');
  const [copied, setCopied] = useState(false);

  const fileList = [
    { path: 'detection/rule_engine.py', label: 'Rule Engine (Python)', category: 'Detection Engine' },
    { path: 'detection/anomaly_detector.py', label: 'Anomaly Detector (Z-Score)', category: 'Detection Engine' },
    { path: 'detection/risk_scoring.py', label: 'Risk Scorer & Mitigation', category: 'Detection Engine' },
    { path: 'security/encryption.py', label: 'AES-256-GCM Cryptosystem', category: 'Security' },
    { path: 'security/authorization.py', label: 'RBAC Authorization Decorator', category: 'Security' },
    { path: 'database/schema.sql', label: 'MySQL Schema & DDL', category: 'Database' },
    { path: 'routes/events.py', label: 'REST API: /api/events', category: 'Backend Routes' },
    { path: 'routes/dashboard.py', label: 'REST API: /api/dashboard', category: 'Backend Routes' },
    { path: 'app.py', label: 'Flask Server Entry Point', category: 'Server Core' },
    { path: 'config.py', label: 'Config & Environment', category: 'Server Core' }
  ];

  const codeSnippets: Record<string, string> = {
    'detection/rule_engine.py': `"""
ZeroAttack – Deterministic Rule-Based Cyber Attack Detection Engine
Extracts and inspects URLs, query strings, body payloads, and headers
against heuristic regex signatures for SQLi, XSS, Path Traversal, and Scanners.
"""

import re
from typing import Dict, Any, List
from detection.attack_patterns import (
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    PARAMETER_TAMPERING_PATTERNS,
    AUTOMATED_SCANNER_PATTERNS
)

class RuleEngine:
    def __init__(self, db_manager=None):
        self.db = db_manager

    def inspect_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects request parameters and payloads across all compiled threat vectors.
        """
        url = request_data.get("url", "")
        params = request_data.get("parameters", "")
        body = request_data.get("body", "")
        user_agent = request_data.get("user_agent", "")

        combined_payload = f"{url} {params} {body}".strip()
        matched_indicators: List[Dict[str, Any]] = []
        highest_weight = 0
        detected_category = None

        # 1. Inspect for SQL Injection
        for sig in SQL_INJECTION_PATTERNS:
            match = re.search(sig["pattern"], combined_payload)
            if match:
                weight = sig["risk_weight"]
                matched_indicators.append({
                    "category": "SQL Injection",
                    "rule_name": sig["name"],
                    "matched_token": match.group(0)[:60],
                    "weight": weight
                })
                if weight > highest_weight:
                    highest_weight = weight
                    detected_category = "SQL Injection"

        # 2. Inspect for Cross-Site Scripting (XSS)
        for sig in XSS_PATTERNS:
            match = re.search(sig["pattern"], combined_payload)
            if match:
                weight = sig["risk_weight"]
                matched_indicators.append({
                    "category": "Cross-Site Scripting (XSS)",
                    "rule_name": sig["name"],
                    "matched_token": match.group(0)[:60],
                    "weight": weight
                })
                if weight > highest_weight:
                    highest_weight = weight
                    detected_category = "Cross-Site Scripting (XSS)"

        # 3. Inspect Parameter Tampering / Path Traversal
        for sig in PARAMETER_TAMPERING_PATTERNS:
            match = re.search(sig["pattern"], combined_payload)
            if match:
                weight = sig["risk_weight"]
                matched_indicators.append({
                    "category": "Parameter Tampering",
                    "rule_name": sig["name"],
                    "matched_token": match.group(0)[:60],
                    "weight": weight
                })
                if weight > highest_weight:
                    highest_weight = weight
                    detected_category = "Parameter Tampering"

        # 4. Inspect User-Agent for Automated Scanners
        for sig in AUTOMATED_SCANNER_PATTERNS:
            match = re.search(sig["pattern"], user_agent)
            if match:
                weight = sig["risk_weight"]
                matched_indicators.append({
                    "category": "Automated Scanner",
                    "rule_name": sig["name"],
                    "matched_token": match.group(0)[:60],
                    "weight": weight
                })
                if weight > highest_weight:
                    highest_weight = weight
                    detected_category = "Automated Scanner"

        return {
            "has_match": len(matched_indicators) > 0,
            "attack_type": detected_category or "Normal Request",
            "rule_risk_score": highest_weight,
            "matched_indicators": matched_indicators
        }`,

    'detection/anomaly_detector.py': `"""
ZeroAttack – Statistical & Behavioral Anomaly Detection Module
Analyzes request velocities, credential stuffing bursts, payload Shannon entropy,
and client header variances using sliding-window statistical analysis (Z-score).
"""

import math
import re
from typing import Dict, Any, List

class AnomalyDetector:
    def __init__(self, baseline_req_per_min: float = 5.0, std_dev: float = 3.5):
        self.baseline_mean = baseline_req_per_min
        self.std_dev = std_dev

    def calculate_shannon_entropy(self, data: str) -> float:
        """Calculates Shannon entropy in bits/symbol for detecting obfuscated shellcode."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    def evaluate_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        frequency = request_data.get("frequency", 1)
        url = request_data.get("url", "")
        params = request_data.get("parameters", "")
        user_agent = request_data.get("user_agent", "")

        anomaly_score = 0
        anomaly_flags: List[Dict[str, Any]] = []

        # 1. Z-Score Velocity Surge Detection
        z_score = (frequency - self.baseline_mean) / self.std_dev
        if frequency >= 25:
            anomaly_score += 45
            anomaly_flags.append({
                "factor": "Request Velocity Surge",
                "detail": f"{frequency} req/min exceeds threshold of 25 (Z-Score: {z_score:.2f})",
                "severity_contrib": 45
            })

        # 2. Brute-Force Login Pattern Detection
        is_auth_endpoint = bool(re.search(r"/(login|auth|signin|token)", url, re.I))
        if is_auth_endpoint and frequency >= 8:
            anomaly_score += 40
            anomaly_flags.append({
                "factor": "Brute-Force Login Pattern",
                "detail": f"Rapid authentication attempts ({frequency} req/min) targeting credential endpoint",
                "severity_contrib": 40
            })

        # 3. Payload Shannon Entropy Analysis
        entropy = self.calculate_shannon_entropy(params)
        if len(params) > 30 and entropy > 4.5:
            anomaly_score += 25
            anomaly_flags.append({
                "factor": "High Information Entropy",
                "detail": f"Payload entropy is {entropy:.2f} bits/symbol (suspected shellcode or encoded exploit)",
                "severity_contrib": 25
            })

        capped_score = min(100, anomaly_score)
        return {
            "is_anomalous": len(anomaly_flags) > 0 and capped_score >= 25,
            "anomaly_score": capped_score,
            "anomaly_flags": anomaly_flags,
            "entropy": entropy
        }`,

    'detection/risk_scoring.py': `"""
ZeroAttack – Multi-Factor Risk Scoring and Mitigation Engine
Synthesizes rule signature weights, statistical anomaly findings, and actor reputation
to compute a composite risk score (0-100) and assign formal incident severities.
"""

from typing import Dict, Any

class RiskScorer:
    LOW_THRESHOLD = 0
    MEDIUM_THRESHOLD = 30
    HIGH_THRESHOLD = 60
    CRITICAL_THRESHOLD = 80

    def compute_composite_risk(
        self,
        rule_result: Dict[str, Any],
        anomaly_result: Dict[str, Any],
        is_ip_previously_flagged: bool = False
    ) -> Dict[str, Any]:
        rule_matched = rule_result.get("has_match", False)
        rule_score = rule_result.get("rule_risk_score", 0)
        is_anomalous = anomaly_result.get("is_anomalous", False)
        anomaly_score = anomaly_result.get("anomaly_score", 0)

        # Composite Blending Logic
        if rule_matched and is_anomalous:
            composite_score = int(rule_score * 0.65 + anomaly_score * 0.45) + 10
            detection_method = "HYBRID_ENGINE"
            attack_type = rule_result.get("attack_type", "Multi-Vector Attack")
        elif rule_matched:
            composite_score = rule_score
            detection_method = "RULE_BASED"
            attack_type = rule_result.get("attack_type", "Rule Violation")
        elif is_anomalous:
            composite_score = int(anomaly_score * 0.85)
            detection_method = "ANOMALY_DETECTION"
            attack_type = "Anomaly Detection"
        else:
            composite_score = 5
            detection_method = "RULE_BASED"
            attack_type = "Normal Request"

        composite_score = min(100, max(0, composite_score))

        # Assign Severity Level
        if composite_score >= self.CRITICAL_THRESHOLD:
            severity = "CRITICAL"
            action_taken = "BLOCKED"
        elif composite_score >= self.HIGH_THRESHOLD:
            severity = "HIGH"
            action_taken = "QUARANTINED"
        elif composite_score >= self.MEDIUM_THRESHOLD:
            severity = "MEDIUM"
            action_taken = "FLAGGED"
        else:
            severity = "LOW"
            action_taken = "MONITORED"

        return {
            "risk_score": composite_score,
            "severity": severity,
            "action_taken": action_taken,
            "detection_method": detection_method,
            "attack_type": attack_type
        }`,

    'security/encryption.py': `"""
ZeroAttack – Cryptographic Security Module (AES-256-GCM)
Provides authenticated encryption for sensitive security records and payloads.
Flow: Plain Security Data -> AES-256-GCM Encryption -> Encrypted Database Record -> Authorized Decryption
"""

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class PayloadEncryptionService:
    def __init__(self, key_hex: str = None):
        if key_hex:
            self.key = bytes.fromhex(key_hex)
        else:
            # Fallback 256-bit AES key
            self.key = b"ZeroAttack2026SecureKey32Bytes!!"

        self.aesgcm = AESGCM(self.key)

    def encrypt_payload(self, data: Any) -> str:
        """Encrypts plain payload dictionary using AES-256-GCM with 96-bit unique nonce."""
        json_data = json.dumps(data) if not isinstance(data, str) else data
        plaintext_bytes = json_data.encode("utf-8")
        nonce = os.urandom(12)  # Standard 96-bit GCM nonce
        ciphertext = self.aesgcm.encrypt(nonce, plaintext_bytes, None)

        combined = nonce + ciphertext
        return base64.b64encode(combined).decode("utf-8")

    def decrypt_payload(self, encrypted_b64: str) -> str:
        """Decrypts AES-256-GCM ciphertext, validating the 128-bit authentication tag."""
        combined = base64.b64decode(encrypted_b64.encode("utf-8"))
        nonce = combined[:12]
        ciphertext = combined[12:]
        decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")`,

    'database/schema.sql': `-- ZeroAttack – Intelligent Cyber Attack Detection and Prevention System
-- MySQL Relational Database Schema DDL

CREATE DATABASE IF NOT EXISTS zeroattack_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE zeroattack_db;

-- 1. Users & Clearances Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN', 'SECURITY ANALYST', 'VIEWER') NOT NULL DEFAULT 'VIEWER',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 2. Detection Rules Catalog
CREATE TABLE IF NOT EXISTS rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    attack_type ENUM('SQL Injection', 'Cross-Site Scripting (XSS)', 'Brute Force', 'Parameter Tampering', 'Anomaly Detection') NOT NULL,
    pattern TEXT NOT NULL,
    target_field ENUM('ALL', 'URL', 'PARAMETERS', 'HEADERS', 'BODY') DEFAULT 'ALL',
    description TEXT,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    risk_weight INT NOT NULL DEFAULT 50,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3. Security Events (Encrypted Payload Storage)
CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    request_method VARCHAR(10) NOT NULL,
    request_url TEXT NOT NULL,
    user_agent TEXT,
    attack_type VARCHAR(50) NOT NULL,
    detection_method ENUM('RULE_BASED', 'ANOMALY_DETECTION', 'HYBRID_ENGINE') NOT NULL,
    risk_score INT NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    action_taken ENUM('MONITORED', 'FLAGGED', 'QUARANTINED', 'BLOCKED') NOT NULL,
    status ENUM('DETECTED', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'FALSE_POSITIVE') DEFAULT 'DETECTED',
    detection_reason TEXT,
    encrypted_payload TEXT NOT NULL,
    INDEX idx_source_ip (source_ip),
    INDEX idx_severity (severity),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB;

-- 4. Blocked & Quarantined IPs
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    risk_score INT NOT NULL,
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    status ENUM('ACTIVE', 'EXPIRED', 'WHITELISTED') DEFAULT 'ACTIVE',
    blocked_by VARCHAR(50) DEFAULT 'SYSTEM_AUTO_BLOCK'
) ENGINE=InnoDB;

-- 5. System Compliance Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    target VARCHAR(100),
    ip_address VARCHAR(45),
    details TEXT
) ENGINE=InnoDB;`,

    'routes/events.py': `"""
ZeroAttack – Security Event & Inspection Routes
Provides live /analyze inspection, encrypted event querying, and authorized decryption.
"""

from flask import Blueprint, request, jsonify, session
from detection.rule_engine import RuleEngine
from detection.anomaly_detector import AnomalyDetector
from detection.risk_scoring import RiskScorer
from security.encryption import encryption_service
from security.authorization import roles_required
from database.db import db_manager

events_bp = Blueprint("events", __name__, url_prefix="/api/events")

rule_engine = RuleEngine(db_manager)
anomaly_detector = AnomalyDetector()
risk_scorer = RiskScorer()

@events_bp.route("/analyze", methods=["POST"])
def analyze_request():
    data = request.get_json() or {}
    source_ip = data.get("source_ip", request.remote_addr or "127.0.0.1")

    # 1. Rule Engine Inspection
    rule_res = rule_engine.inspect_request(data)

    # 2. Anomaly Detection
    anomaly_res = anomaly_detector.evaluate_request(data)

    # 3. Composite Risk Scoring & Severity Assignment
    risk_res = risk_scorer.compute_composite_risk(rule_res, anomaly_res)

    # 4. Cryptographic Encryption of Sensitive Record
    encrypted_record = encryption_service.encrypt_payload(data)

    # 5. Persist to MySQL / In-Memory
    event_id = db_manager.insert_security_event({
        "source_ip": source_ip,
        "request_method": data.get("method", "GET"),
        "request_url": data.get("url", "/"),
        "user_agent": data.get("user_agent", ""),
        "attack_type": risk_res["attack_type"],
        "detection_method": risk_res["detection_method"],
        "risk_score": risk_res["risk_score"],
        "severity": risk_res["severity"],
        "action_taken": risk_res["action_taken"],
        "status": "DETECTED",
        "detection_reason": "Rule & anomaly indicators detected",
        "encrypted_payload": encrypted_record
    })

    return jsonify({
        "event_id": event_id,
        "risk_score": risk_res["risk_score"],
        "severity": risk_res["severity"],
        "action_taken": risk_res["action_taken"],
        "cipher_preview": encrypted_record[:40] + "..."
    })`,

    'app.py': `"""
ZeroAttack – Intelligent Cyber Attack Detection and Prevention System
Flask Application Entry Point
"""

from flask import Flask, jsonify, render_template
from flask_cors import CORS
from config import Config
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.events import events_bp
from routes.rules import rules_bp
from routes.ips import ips_bp
from routes.users import users_bp

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    CORS(app, supports_credentials=True)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(ips_bp)
    app.register_blueprint(users_bp)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)`
  };

  const handleCopy = () => {
    const code = codeSnippets[selectedFile] || '';
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <Code className="w-5 h-5 text-cyan-400" />
            Backend Architecture & Python Source Code Explorer
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Browse and inspect all modular Python Flask backend, MySQL schema, and cryptosystem source files
          </p>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 font-bold rounded-lg border border-slate-700 transition"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied to Clipboard' : 'Copy File Content'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: File Tree */}
        <div className="lg:col-span-4 bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
            ZeroAttack Backend Files:
          </div>
          <div className="space-y-1">
            {fileList.map((f) => (
              <button
                key={f.path}
                onClick={() => setSelectedFile(f.path)}
                className={`w-full text-left p-2.5 rounded-lg transition flex items-center justify-between ${
                  selectedFile === f.path
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                }`}
              >
                <div>
                  <div className="text-xs">{f.path}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{f.label}</div>
                </div>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                  {f.category}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Right Column: Code Viewer */}
        <div className="lg:col-span-8 bg-slate-950 border border-slate-800 rounded-xl p-5 overflow-hidden flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3 text-slate-400">
            <span className="text-cyan-400 font-bold">{selectedFile}</span>
            <span className="text-[10px] text-slate-500">UTF-8 SOURCE</span>
          </div>
          <pre className="overflow-x-auto text-[11px] text-slate-300 font-mono leading-relaxed max-h-[65vh] p-2">
            {codeSnippets[selectedFile] || '# File preview available on filesystem.'}
          </pre>
        </div>
      </div>
    </div>
  );
};
