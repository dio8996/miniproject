"""
ZeroAttack – Risk Scoring Module
Blends rule engine signature scores, behavioral anomaly scores, and threat multipliers.
Computes composite risk score (0-100) and severity band (LOW, MEDIUM, HIGH, CRITICAL).
"""

from typing import Dict, Any, Tuple

class RiskScorer:
    def __init__(self, auto_block_threshold: int = 80):
        self.auto_block_threshold = auto_block_threshold

    def calculate_risk(
        self,
        rule_result: Dict[str, Any],
        anomaly_result: Dict[str, Any],
        is_ip_previously_flagged: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates final risk score using weighted composite heuristic:
        Risk = w1 * RuleRisk + w2 * AnomalyScore + Multipliers (Reputation, Compound Threats)
        """
        rule_score = rule_result.get("rule_risk_score", 0)
        anomaly_score = anomaly_result.get("anomaly_score", 0)
        has_rule_match = rule_result.get("has_matched", False)
        is_anomalous = anomaly_result.get("is_anomalous", False)
        attack_type = rule_result.get("detected_attack_type", "Normal Request")

        # Base scoring blend
        if has_rule_match and is_anomalous:
            # Compound threat (e.g. SQLi carried out inside an automated burst)
            composite_score = int((rule_score * 0.65) + (anomaly_score * 0.45)) + 10
            detection_method = "HYBRID_ENGINE"
        elif has_rule_match:
            composite_score = rule_score
            detection_method = "RULE_BASED"
        elif is_anomalous:
            composite_score = int(anomaly_score * 0.85)
            detection_method = "ANOMALY_DETECTION"
            if attack_type == "Normal Request":
                attack_type = "Behavioral Anomaly"
        else:
            composite_score = 5  # Routine baseline request score
            detection_method = "RULE_BASED"

        # Apply previous IP history multiplier
        if is_ip_previously_flagged:
            composite_score += 15

        # Normalize bounded 0-100
        final_risk_score = min(100, max(0, composite_score))

        # Assign severity classification
        severity, action_taken = self._classify_severity(final_risk_score, has_rule_match, is_anomalous)

        # Formulate human-readable detection reason
        reasons = []
        if has_rule_match:
            for ind in rule_result.get("matched_indicators", [])[:3]:
                reasons.append(f"{ind.get('label')} (pattern match: '{ind.get('matched_text')}')")
        if is_anomalous:
            for flag in anomaly_result.get("flags", [])[:2]:
                reasons.append(f"{flag.get('factor')}: {flag.get('detail')}")

        detection_reason = "; ".join(reasons) if reasons else "No malicious patterns or anomalies identified."

        should_block_ip = final_risk_score >= self.auto_block_threshold

        return {
            "risk_score": final_risk_score,
            "severity": severity,
            "attack_type": attack_type,
            "detection_method": detection_method,
            "action_taken": "BLOCKED" if should_block_ip else action_taken,
            "should_block_ip": should_block_ip,
            "detection_reason": detection_reason,
            "breakdown": {
                "rule_component": rule_score,
                "anomaly_component": anomaly_score,
                "reputation_penalty": 15 if is_ip_previously_flagged else 0
            }
        }

    def _classify_severity(self, score: int, has_rule: bool, has_anomaly: bool) -> Tuple[str, str]:
        """
        LOW: Minor or unusual activity (0 - 29)
        MEDIUM: Repeated failed requests or suspicious parameter behavior (30 - 59)
        HIGH: Strong evidence of malicious activity (60 - 79)
        CRITICAL: Highly suspicious SQL injection or automated brute-force behavior (80 - 100)
        """
        if score >= 80:
            return "CRITICAL", "BLOCKED"
        elif score >= 60:
            return "HIGH", "QUARANTINED"
        elif score >= 30:
            return "MEDIUM", "FLAGGED"
        else:
            return "LOW", "MONITORED"
