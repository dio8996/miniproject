"""
ZeroAttack – Rule Engine
Inspects HTTP request URLs, parameters, headers, and payloads against security rules.
"""

import re
import urllib.parse
from typing import Dict, Any, List
from detection.attack_patterns import (
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    PARAMETER_TAMPERING_PATTERNS,
    SCANNER_USER_AGENTS,
)

class RuleEngine:
    def __init__(self, custom_rules: List[Dict[str, Any]] = None):
        self.custom_rules = custom_rules or []

    def inspect_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main inspection entry point.
        Analyzes:
          - IP Address
          - HTTP Method
          - Request URL
          - Parameters / Query string / Body
          - Headers / User-Agent
        """
        url = request_data.get("url", "")
        method = request_data.get("method", "GET").upper()
        params = request_data.get("parameters", "")
        headers = request_data.get("headers", {})
        user_agent = request_data.get("user_agent", "")
        body = request_data.get("body", "")

        # Unquote/decode URL & parameters to catch obfuscation techniques (e.g. %27, %3Cscript%3E)
        decoded_url = urllib.parse.unquote(url)
        decoded_params = urllib.parse.unquote(str(params))
        combined_payload = f"{url} {decoded_url} {params} {decoded_params} {body}".strip()

        matched_indicators = []
        highest_rule_score = 0
        detected_attack_type = "None"

        # 1. SQL Injection Inspection
        for regex_pattern, label, weight in SQL_INJECTION_PATTERNS:
            match = re.search(regex_pattern, combined_payload)
            if match:
                matched_indicators.append({
                    "type": "SQL Injection",
                    "label": label,
                    "matched_text": match.group(0)[:80],
                    "weight": weight
                })
                if weight > highest_rule_score:
                    highest_rule_score = weight
                    detected_attack_type = "SQL Injection"

        # 2. XSS Inspection
        for regex_pattern, label, weight in XSS_PATTERNS:
            match = re.search(regex_pattern, combined_payload)
            if match:
                matched_indicators.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "label": label,
                    "matched_text": match.group(0)[:80],
                    "weight": weight
                })
                if weight > highest_rule_score:
                    highest_rule_score = weight
                    detected_attack_type = "Cross-Site Scripting (XSS)"

        # 3. Parameter Tampering & Path Traversal
        for regex_pattern, label, weight in PARAMETER_TAMPERING_PATTERNS:
            match = re.search(regex_pattern, combined_payload)
            if match:
                matched_indicators.append({
                    "type": "Parameter Tampering",
                    "label": label,
                    "matched_text": match.group(0)[:80],
                    "weight": weight
                })
                if weight > highest_rule_score:
                    highest_rule_score = weight
                    detected_attack_type = "Parameter Tampering"

        # 4. Scanner & Automated User-Agent Inspection
        for regex_pattern, label, weight in SCANNER_USER_AGENTS:
            match = re.search(regex_pattern, user_agent)
            if match:
                matched_indicators.append({
                    "type": "Scanner Fingerprint",
                    "label": label,
                    "matched_text": match.group(0)[:80],
                    "weight": weight
                })
                if weight > highest_rule_score:
                    highest_rule_score = weight
                    detected_attack_type = "Scanner Fingerprint"

        # 5. Dynamic Custom Rules from DB
        for rule in self.custom_rules:
            if not rule.get("is_active", True):
                continue
            rule_pattern = rule.get("pattern", "")
            target_field = rule.get("target_field", "ALL").upper()
            
            test_content = combined_payload
            if target_field == "URL":
                test_content = f"{url} {decoded_url}"
            elif target_field == "PARAMETERS":
                test_content = f"{params} {decoded_params}"
            elif target_field == "HEADERS":
                test_content = f"{user_agent} {str(headers)}"

            try:
                match = re.search(rule_pattern, test_content)
                if match:
                    weight = int(rule.get("risk_weight", 50))
                    matched_indicators.append({
                        "rule_id": rule.get("id"),
                        "type": rule.get("attack_type", "Custom Rule"),
                        "label": rule.get("name", "Custom Signature Match"),
                        "matched_text": match.group(0)[:80],
                        "weight": weight
                    })
                    if weight > highest_rule_score:
                        highest_rule_score = weight
                        detected_attack_type = rule.get("attack_type", "Custom Rule")
            except re.error:
                continue

        # Heuristic check for sensitive paths or method irregularities
        is_post_login = "/login" in url.lower() or "/auth" in url.lower()
        if is_post_login and method == "GET":
            matched_indicators.append({
                "type": "Method Irregularity",
                "label": "Authentication endpoint called via GET method",
                "matched_text": method,
                "weight": 20
            })

        has_matched = len(matched_indicators) > 0

        return {
            "has_matched": has_matched,
            "detected_attack_type": detected_attack_type if has_matched else "Normal Request",
            "rule_risk_score": highest_rule_score,
            "matched_indicators": matched_indicators,
            "inspected_length": len(combined_payload)
        }
