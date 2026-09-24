"""
ZeroAttack – Database Connection & Execution Manager
Handles MySQL connection pooling with PyMySQL.
Provides automatic fallback to an in-memory thread-safe store if MySQL is offline,
ensuring local evaluation and testing without complex local service dependencies.
"""

import pymysql
import os
import json
import datetime
from config import Config

class DatabaseManager:
    def __init__(self):
        self.use_mysql = False
        self.in_memory_events = []
        self.in_memory_rules = []
        self.in_memory_blocked_ips = []
        self.in_memory_audit_logs = []
        self.in_memory_users = []
        self._test_connection()
        self._seed_default_in_memory_data()

    def _test_connection(self):
        """Attempts to connect to MySQL database."""
        try:
            conn = pymysql.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                database=Config.DB_NAME,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=2
            )
            conn.close()
            self.use_mysql = True
            print(f"[ZeroAttack DB] Connected successfully to MySQL at {Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}")
        except Exception as e:
            self.use_mysql = False
            print(f"[ZeroAttack DB] MySQL not available ({str(e)}). Running in high-performance in-memory persistence mode.")

    def get_connection(self):
        if not self.use_mysql:
            return None
        return pymysql.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )

    def _seed_default_in_memory_data(self):
        """Populates in-memory storage with realistic demonstration records."""
        now = datetime.datetime.utcnow()
        self.in_memory_rules = [
            {"id": 1, "name": "Classic SQL Injection (OR 1=1)", "attack_type": "SQL Injection", "pattern": r"(?i)((\%27)|('))\s*(or|and)\s+(\d+|\'\w+\')\s*=\s*(\d+|\'\w+\')", "target_field": "ALL", "severity": "CRITICAL", "risk_weight": 85, "is_active": True},
            {"id": 2, "name": "SQL UNION SELECT Exploitation", "attack_type": "SQL Injection", "pattern": r"(?i)\bunion\s+(all\s+)?select\b", "target_field": "ALL", "severity": "CRITICAL", "risk_weight": 90, "is_active": True},
            {"id": 3, "name": "Stored & Reflected Script Tags (XSS)", "attack_type": "Cross-Site Scripting (XSS)", "pattern": r"(?i)<\s*script[^>]*>", "target_field": "ALL", "severity": "HIGH", "risk_weight": 75, "is_active": True},
            {"id": 4, "name": "Directory / Path Traversal Attack", "attack_type": "Parameter Tampering", "pattern": r"(?i)(\.\./|\.\.\\|/etc/passwd)", "target_field": "URL", "severity": "HIGH", "risk_weight": 75, "is_active": True},
            {"id": 5, "name": "Brute-Force Credential Stuffing", "attack_type": "Brute Force", "pattern": r"BURST_BURST", "target_field": "HEADERS", "severity": "CRITICAL", "risk_weight": 85, "is_active": True}
        ]

        self.in_memory_blocked_ips = [
            {
                "id": 1,
                "ip_address": "198.51.100.42",
                "reason": "Automated SQL Injection (UNION SELECT + schema dump attempt)",
                "risk_score": 92,
                "blocked_at": (now - datetime.timedelta(minutes=14)).isoformat(),
                "expires_at": (now + datetime.timedelta(minutes=16)).isoformat(),
                "status": "ACTIVE",
                "blocked_by": "SYSTEM_AUTO_BLOCK"
            },
            {
                "id": 2,
                "ip_address": "203.0.113.89",
                "reason": "Brute-force credential stuffing burst (34 attempts/min)",
                "risk_score": 88,
                "blocked_at": (now - datetime.timedelta(minutes=22)).isoformat(),
                "expires_at": (now + datetime.timedelta(minutes=8)).isoformat(),
                "status": "ACTIVE",
                "blocked_by": "SYSTEM_AUTO_BLOCK"
            }
        ]

        self.in_memory_audit_logs = [
            {"id": 1, "timestamp": (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"), "username": "admin", "action": "SYSTEM_INIT", "target": "ENGINE", "ip_address": "127.0.0.1", "details": "ZeroAttack Core Rules Engine Initialized"},
            {"id": 2, "timestamp": (now - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"), "username": "admin", "action": "IP_BLOCK", "target": "198.51.100.42", "ip_address": "127.0.0.1", "details": "Automated mitigation applied to critical risk score (92)"}
        ]

db_manager = DatabaseManager()
