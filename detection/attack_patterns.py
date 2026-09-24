"""
ZeroAttack – Attack Patterns & Signatures
Catalog of regex patterns and indicators for SQL Injection, XSS, Path Traversal,
Command Injection, and Scanner Fingerprints.
"""

import re

# Comprehensive signatures for rule-based analysis
SQL_INJECTION_PATTERNS = [
    # Classic boolean tautology (e.g. ' OR '1'='1, 1' or 1=1 --)
    (r"(?i)(\%27|'|\"|`)\s*(or|and)\s*(\d+|\w+|\'\w+\')\s*=\s*(\d+|\w+|\'\w+\')", "SQLi: Boolean-based Tautology", 85),
    # Union Select data extraction
    (r"(?i)\bunion\s+(all\s+)?select\b", "SQLi: UNION SELECT Extraction", 90),
    # Comment truncation markers (--, /*, #)
    (r"(--\s*$|/\*.*?\*/|#\s*$)", "SQLi: Query Comment Truncation", 60),
    # Stacked commands / execution
    (r"(?i);\s*(drop|insert|update|delete|truncate|alter|exec|execute|grant)\b", "SQLi: Stacked Query Execution", 95),
    # Time-based blind functions
    (r"(?i)\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+\s*,|waitfor\s+delay\b)", "SQLi: Time-based Blind Primitive", 85),
    # Schema exploration queries
    (r"(?i)\b(information_schema|sys\.tables|table_name|column_name)\b", "SQLi: Database Schema Reconnaissance", 75),
]

XSS_PATTERNS = [
    # Explicit script tags
    (r"(?i)<\s*script[^>]*>.*?(<\s*/\s*script\s*>)?", "XSS: Raw Script Tag Injection", 80),
    # Inline DOM event handlers (onerror, onload, onmouseover, onclick, etc.)
    (r"(?i)\bon(load|error|click|mouseover|mouseenter|focus|blur|submit|keydown|keyup)\s*=", "XSS: DOM Event Handler Injection", 75),
    # JavaScript pseudo-protocols
    (r"(?i)javascript:\s*[^\s'\"]+", "XSS: JavaScript URI Protocol Scheme", 75),
    # Cookie/DOM extraction and eval primitives
    (r"(?i)\b(document\.cookie|document\.location|window\.location|eval\s*\(|alert\s*\(|prompt\s*\()", "XSS: Document DOM Access & Dialog Primitive", 70),
    # SVG/IMG payload variations with inline execution
    (r"(?i)<\s*(img|svg|iframe|embed|object|video|audio)\b[^>]*?(src|href|data|onload|onerror)\s*=", "XSS: Tag Attribute Hijack", 75),
]

PARAMETER_TAMPERING_PATTERNS = [
    # Directory & Path Traversal
    (r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)", "Tampering: Directory Traversal Path Token", 80),
    # Critical system files access
    (r"(?i)(/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini|windows/system32)", "Tampering: Operating System Sensitive File Probe", 90),
    # Privilege Escalation parameter tampering
    (r"(?i)\b(is_admin|isAdmin|role|privilege|superuser|is_superuser|debug_mode)\s*=\s*(1|true|admin|root|system)\b", "Tampering: Administrative Role Override", 65),
    # Price or financial manipulation flags
    (r"(?i)\b(price|discount|amount|credits)\s*=\s*(-|\$0|0\.00|null)\b", "Tampering: Zero/Negative Value Manipulation", 60),
]

SCANNER_USER_AGENTS = [
    (r"(?i)(sqlmap|nikto|acunetix|nessus|nmap|dirbuster|gobuster|wpscan|masscan|zaproxy|burpcollaborator)", "Scanner: Automated Security Toolkit User-Agent", 70),
    (r"(?i)(curl/|python-requests/|go-http-client/|postmanruntime/|httpclient|java/)", "Scanner: Headless Programmatic Client User-Agent", 30),
]
