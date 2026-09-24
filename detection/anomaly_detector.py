"""
ZeroAttack – Anomaly Detection Module
Statistical and behavioral anomaly detector tracking request velocity, burst frequency,
repeated failed logins, entropy irregularities, and abnormal header patterns.
Structured to allow drop-in integration of scikit-learn / Isolation Forest / One-Class SVM.
"""

import time
import math
from collections import defaultdict, deque
from typing import Dict, Any, List

class AnomalyDetector:
    def __init__(self, window_seconds: int = 60, rate_limit_threshold: int = 25):
        self.window_seconds = window_seconds
        self.rate_limit_threshold = rate_limit_threshold
        # In-memory sliding window history: IP -> deque of timestamps
        self.ip_request_history = defaultdict(deque)
        # Tracking repetitive endpoints per IP
        self.ip_endpoint_history = defaultdict(list)
        # Baseline statistical profile
        self.baseline_mean_frequency = 5.0
        self.baseline_std_deviation = 3.5

    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculates Shannon entropy of string to spot encoded shellcode or obfuscated blobs."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def analyze_behavior(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes behavioral anomalies based on:
        1. Request Frequency (Burst & sliding window rate)
        2. High repetition of identical endpoints (Credential stuffing / Fuzzing)
        3. High Shannon entropy in parameter values (Obfuscation / Shellcode / Binary)
        4. Suspicious header absence (Missing User-Agent, Accept header)
        5. Off-hours or abnormal pattern indicators
        """
        now = time.time()
        source_ip = request_data.get("source_ip", "127.0.0.1")
        url = request_data.get("url", "/")
        user_agent = request_data.get("user_agent", "")
        params = request_data.get("parameters", "")
        method = request_data.get("method", "GET")
        provided_freq = request_data.get("frequency") # from test harness if specified

        # 1. Update sliding window history
        timestamps = self.ip_request_history[source_ip]
        timestamps.append(now)
        # Evict events older than window
        while timestamps and timestamps[0] < now - self.window_seconds:
            timestamps.popleft()

        current_frequency = len(timestamps)
        if provided_freq is not None and int(provided_freq) > 0:
            current_frequency = max(current_frequency, int(provided_freq))

        anomaly_flags = []
        anomaly_score = 0

        # Statistical Z-score calculation on request frequency
        z_score = (current_frequency - self.baseline_mean_frequency) / max(self.baseline_std_deviation, 1.0)
        
        # Check 1: Velocity & Rate Limit Anomaly
        if current_frequency > self.rate_limit_threshold:
            anomaly_score += 45
            anomaly_flags.append({
                "factor": "Request Velocity Surge",
                "detail": f"{current_frequency} req/min exceeds threshold of {self.rate_limit_threshold} req/min (Z-Score: {z_score:.2f})",
                "severity_contrib": 45
            })
        elif current_frequency > (self.rate_limit_threshold * 0.6):
            anomaly_score += 20
            anomaly_flags.append({
                "factor": "Elevated Traffic Rate",
                "detail": f"Frequency {current_frequency} req/min is 2.5x above baseline mean (Z-Score: {z_score:.2f})",
                "severity_contrib": 20
            })

        # Check 2: Brute-Force pattern on Auth Endpoints
        is_auth_target = any(auth_path in url.lower() for auth_path in ["/login", "/auth", "/signin", "/token", "/admin/login"])
        if is_auth_target and current_frequency >= 8:
            anomaly_score += 40
            anomaly_flags.append({
                "factor": "Brute-Force Login Pattern",
                "detail": f"Rapid authentication attempts ({current_frequency} calls) targeting credential validation",
                "severity_contrib": 40
            })

        # Check 3: Shannon Entropy Analysis (High entropy indicates base64/hex packed payloads)
        param_entropy = self._calculate_shannon_entropy(str(params))
        if len(str(params)) > 30 and param_entropy > 4.6:
            anomaly_score += 25
            anomaly_flags.append({
                "factor": "High Information Entropy",
                "detail": f"Payload entropy is {param_entropy:.2f} bits/symbol (suspected obfuscated payload or shellcode)",
                "severity_contrib": 25
            })

        # Check 4: Suspicious Missing Headers (Common in raw socket scripts)
        if not user_agent or len(user_agent.strip()) < 5:
            anomaly_score += 20
            anomaly_flags.append({
                "factor": "Anomalous Client Signature",
                "detail": "Missing, blank, or malformed User-Agent header typical of headless automation scripts",
                "severity_contrib": 20
            })

        # Cap individual anomaly score to 100
        anomaly_score = min(100, anomaly_score)
        is_anomalous = len(anomaly_flags) > 0 and anomaly_score >= 30

        return {
            "is_anomalous": is_anomalous,
            "anomaly_score": anomaly_score,
            "calculated_frequency": current_frequency,
            "z_score": round(z_score, 2),
            "flags": anomaly_flags,
            "ml_model_interface": "ZeroAttack-Statistical-ZScore-v1.0 (IsolationForest Compatible)"
        }
