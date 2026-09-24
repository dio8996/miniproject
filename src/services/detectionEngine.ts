import {
  RequestAnalysisInput,
  SecurityEvent,
  MatchedIndicator,
  AnomalyFlag,
  SeverityLevel,
  AttackCategory,
  DetectionMethod,
  ActionTaken,
  DetectionRule,
  BlockedIp,
  AuditLogEntry,
  User,
  UserRole
} from '../types/security';
import {
  INITIAL_EVENTS,
  INITIAL_RULES,
  INITIAL_BLOCKED_IPS,
  INITIAL_AUDIT_LOGS,
  INITIAL_USERS
} from './seedData';

// --- Shannon Entropy Calculator ---
function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// --- Encrypted Record Generator (AES-256-GCM Simulation) ---
function simulateAes256GcmEncrypt(data: any): string {
  const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
  // Generate simulated 96-bit Nonce and ciphertext
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let nonce = '';
  for (let i = 0; i < 16; i++) {
    nonce += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  // Base64 encode the payload with AES prefix
  const b64 = btoa(unescape(encodeURIComponent(jsonStr))).substring(0, 48);
  const tag = Math.random().toString(16).substring(2, 14);
  return `U2FsdGVkX1+${b64}$${tag}`;
}

export class ZeroAttackEngine {
  private events: SecurityEvent[] = [];
  private rules: DetectionRule[] = [];
  private blockedIps: BlockedIp[] = [];
  private auditLogs: AuditLogEntry[] = [];
  private users: User[] = [];
  private currentUser: User = INITIAL_USERS[0]; // Admin by default

  constructor() {
    this.loadState();
  }

  private loadState() {
    try {
      const storedEvents = localStorage.getItem('zeroattack_events');
      this.events = storedEvents ? JSON.parse(storedEvents) : [...INITIAL_EVENTS];

      const storedRules = localStorage.getItem('zeroattack_rules');
      this.rules = storedRules ? JSON.parse(storedRules) : [...INITIAL_RULES];

      const storedIps = localStorage.getItem('zeroattack_blocked_ips');
      this.blockedIps = storedIps ? JSON.parse(storedIps) : [...INITIAL_BLOCKED_IPS];

      const storedLogs = localStorage.getItem('zeroattack_audit_logs');
      this.auditLogs = storedLogs ? JSON.parse(storedLogs) : [...INITIAL_AUDIT_LOGS];

      const storedUsers = localStorage.getItem('zeroattack_users');
      this.users = storedUsers ? JSON.parse(storedUsers) : [...INITIAL_USERS];

      const storedRole = localStorage.getItem('zeroattack_active_role');
      if (storedRole) {
        const found = this.users.find(u => u.role === storedRole);
        if (found) this.currentUser = found;
      }
    } catch {
      this.events = [...INITIAL_EVENTS];
      this.rules = [...INITIAL_RULES];
      this.blockedIps = [...INITIAL_BLOCKED_IPS];
      this.auditLogs = [...INITIAL_AUDIT_LOGS];
      this.users = [...INITIAL_USERS];
      this.currentUser = INITIAL_USERS[0];
    }
  }

  private persistState() {
    try {
      localStorage.setItem('zeroattack_events', JSON.stringify(this.events));
      localStorage.setItem('zeroattack_rules', JSON.stringify(this.rules));
      localStorage.setItem('zeroattack_blocked_ips', JSON.stringify(this.blockedIps));
      localStorage.setItem('zeroattack_audit_logs', JSON.stringify(this.auditLogs));
      localStorage.setItem('zeroattack_users', JSON.stringify(this.users));
    } catch (e) {
      console.warn('Storage persistence warning:', e);
    }
  }

  public getCurrentUser(): User {
    return this.currentUser;
  }

  public setCurrentRole(role: UserRole) {
    const user = this.users.find(u => u.role === role) || {
      id: 99,
      username: role.toLowerCase().replace(' ', '_'),
      email: `${role.toLowerCase().replace(' ', '_')}@zeroattack.sec`,
      role,
      isActive: true,
      lastLogin: new Date().toISOString()
    };
    this.currentUser = user;
    try {
      localStorage.setItem('zeroattack_active_role', role);
    } catch {}
    this.addAuditLog('ROLE_SWITCH', `Switched active session clearance to ${role}`);
  }

  // --- RULE ENGINE INSPECTION ---
  private runRuleEngine(input: RequestAnalysisInput): {
    matched: boolean;
    attackType: AttackCategory;
    score: number;
    indicators: MatchedIndicator[];
  } {
    const combinedPayload = `${input.url} ${decodeURIComponent(input.url || '')} ${input.parameters} ${decodeURIComponent(input.parameters || '')} ${input.body || ''}`;
    const indicators: MatchedIndicator[] = [];
    let highestScore = 0;
    let detectedType: AttackCategory = 'Normal Request';

    // 1. SQL Injection Signatures
    const sqliRegexes = [
      { pattern: /(%27|'|"|`)\s*(or|and)\s*(\d+|\w+|'\w+')\s*=\s*(\d+|\w+|'\w+')/i, label: "SQLi: Boolean Tautology (OR 1=1)", weight: 85 },
      { pattern: /\bunion\s+(all\s+)?select\b/i, label: "SQLi: UNION SELECT Extraction", weight: 90 },
      { pattern: /(--\s*$|\/\*.*?\*\/|#\s*$)/i, label: "SQLi: Comment Delimiter Truncation", weight: 60 },
      { pattern: /;\s*(drop|insert|update|delete|truncate|exec)\b/i, label: "SQLi: Stacked Query Execution", weight: 95 },
      { pattern: /\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+\s*,|waitfor\s+delay\b)/i, label: "SQLi: Time-based Blind Primitive", weight: 85 },
      { pattern: /\b(information_schema|sys\.tables|table_name|column_name)\b/i, label: "SQLi: Database Schema Reconnaissance", weight: 75 }
    ];

    for (const { pattern, label, weight } of sqliRegexes) {
      const match = combinedPayload.match(pattern);
      if (match) {
        indicators.push({ type: 'SQL Injection', label, matchedText: match[0].substring(0, 60), weight });
        if (weight > highestScore) {
          highestScore = weight;
          detectedType = 'SQL Injection';
        }
      }
    }

    // 2. XSS Signatures
    const xssRegexes = [
      { pattern: /<\s*script[^>]*>.*?(<\s*\/\s*script\s*>)?/i, label: "XSS: Raw Script Tag Injection", weight: 80 },
      { pattern: /\bon(load|error|click|mouseover|mouseenter|focus|blur|submit)\s*=/i, label: "XSS: DOM Event Handler Hijack", weight: 75 },
      { pattern: /javascript:\s*[^\s'"]+/i, label: "XSS: JavaScript URI Scheme", weight: 75 },
      { pattern: /\b(document\.cookie|document\.location|window\.location|eval\s*\(|alert\s*\()/i, label: "XSS: DOM Access & Dialog Primitives", weight: 70 },
      { pattern: /<\s*(img|svg|iframe|embed|object)\b[^>]*?(src|href|onload|onerror)\s*=/i, label: "XSS: Tag Attribute Code Vector", weight: 75 }
    ];

    for (const { pattern, label, weight } of xssRegexes) {
      const match = combinedPayload.match(pattern);
      if (match) {
        indicators.push({ type: 'Cross-Site Scripting (XSS)', label, matchedText: match[0].substring(0, 60), weight });
        if (weight > highestScore) {
          highestScore = weight;
          detectedType = 'Cross-Site Scripting (XSS)';
        }
      }
    }

    // 3. Parameter Tampering & Path Traversal
    const tamperingRegexes = [
      { pattern: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)/i, label: "Tampering: Directory Traversal Path Token", weight: 80 },
      { pattern: /(\/etc\/passwd|\/etc\/shadow|win\.ini|windows\/system32)/i, label: "Tampering: OS Sensitive File Probe", weight: 90 },
      { pattern: /\b(is_admin|isAdmin|role|privilege|superuser)\s*=\s*(1|true|admin|root)/i, label: "Tampering: Administrative Role Override", weight: 65 }
    ];

    for (const { pattern, label, weight } of tamperingRegexes) {
      const match = combinedPayload.match(pattern);
      if (match) {
        indicators.push({ type: 'Parameter Tampering', label, matchedText: match[0].substring(0, 60), weight });
        if (weight > highestScore) {
          highestScore = weight;
          detectedType = 'Parameter Tampering';
        }
      }
    }

    // 4. Scanner Toolkits
    const scannerRegexes = [
      { pattern: /(sqlmap|nikto|acunetix|nessus|nmap|dirbuster|gobuster|wpscan|masscan)/i, label: "Scanner: Automated Security Toolkit", weight: 70 }
    ];

    for (const { pattern, label, weight } of scannerRegexes) {
      const match = input.userAgent.match(pattern);
      if (match) {
        indicators.push({ type: 'Anomaly Detection', label, matchedText: match[0].substring(0, 60), weight });
        if (weight > highestScore) {
          highestScore = weight;
          detectedType = 'Anomaly Detection';
        }
      }
    }

    // 5. Active User-Configured Rules
    for (const rule of this.rules) {
      if (!rule.isActive) continue;
      try {
        const customReg = new RegExp(rule.pattern, 'i');
        const match = combinedPayload.match(customReg);
        if (match) {
          indicators.push({
            type: rule.attackType,
            label: `Custom: ${rule.name}`,
            matchedText: match[0].substring(0, 60),
            weight: rule.riskWeight
          });
          if (rule.riskWeight > highestScore) {
            highestScore = rule.riskWeight;
            detectedType = rule.attackType;
          }
        }
      } catch {}
    }

    return {
      matched: indicators.length > 0,
      attackType: detectedType,
      score: highestScore,
      indicators
    };
  }

  // --- STATISTICAL ANOMALY DETECTOR ---
  private runAnomalyDetector(input: RequestAnalysisInput): {
    isAnomalous: boolean;
    anomalyScore: number;
    flags: AnomalyFlag[];
  } {
    const flags: AnomalyFlag[] = [];
    let anomalyScore = 0;
    const freq = input.frequency || 1;
    const baselineMean = 5.0;
    const stdDev = 3.5;
    const zScore = (freq - baselineMean) / stdDev;

    // Velocity Check
    if (freq >= 25) {
      anomalyScore += 45;
      flags.push({
        factor: 'Request Velocity Surge',
        detail: `${freq} req/min exceeds threshold of 25 req/min (Z-Score: ${zScore.toFixed(2)})`,
        severityContrib: 45
      });
    } else if (freq >= 15) {
      anomalyScore += 20;
      flags.push({
        factor: 'Elevated Traffic Rate',
        detail: `Frequency ${freq} req/min is well above baseline mean (Z-Score: ${zScore.toFixed(2)})`,
        severityContrib: 20
      });
    }

    // Brute-force auth check
    const isAuth = /\/(login|auth|signin|token|admin\/login)/i.test(input.url);
    if (isAuth && freq >= 8) {
      anomalyScore += 40;
      flags.push({
        factor: 'Brute-Force Login Pattern',
        detail: `Rapid authentication requests (${freq} attempts) targeting credential verification`,
        severityContrib: 40
      });
    }

    // Shannon entropy check
    const entropy = calculateShannonEntropy(input.parameters || '');
    if ((input.parameters || '').length > 30 && entropy > 4.5) {
      anomalyScore += 25;
      flags.push({
        factor: 'High Information Entropy',
        detail: `Payload entropy is ${entropy.toFixed(2)} bits/symbol (suspected obfuscated payload or shellcode)`,
        severityContrib: 25
      });
    }

    // Missing / Malformed User-Agent
    if (!input.userAgent || input.userAgent.trim().length < 5) {
      anomalyScore += 20;
      flags.push({
        factor: 'Anomalous Client Signature',
        detail: 'Missing or malformed User-Agent header typical of automated socket scripts',
        severityContrib: 20
      });
    }

    const cappedScore = Math.min(100, anomalyScore);
    return {
      isAnomalous: flags.length > 0 && cappedScore >= 25,
      anomalyScore: cappedScore,
      flags
    };
  }

  // --- COMPOSITE RISK SCORING ---
  public analyzeRequest(input: RequestAnalysisInput): SecurityEvent {
    const isBlocked = this.blockedIps.some(b => b.ipAddress === input.sourceIp && b.status === 'ACTIVE');

    // 1. Run Rule Engine
    const ruleRes = this.runRuleEngine(input);

    // 2. Run Anomaly Detector
    const anomalyRes = this.runAnomalyDetector(input);

    // 3. Composite Risk Calculation
    let compositeScore = 5;
    let detectionMethod: DetectionMethod = 'RULE_BASED';
    let attackType: AttackCategory = ruleRes.attackType;

    if (ruleRes.matched && anomalyRes.isAnomalous) {
      compositeScore = Math.min(100, Math.floor(ruleRes.score * 0.65 + anomalyRes.anomalyScore * 0.45) + 10);
      detectionMethod = 'HYBRID_ENGINE';
    } else if (ruleRes.matched) {
      compositeScore = ruleRes.score;
      detectionMethod = 'RULE_BASED';
    } else if (anomalyRes.isAnomalous) {
      compositeScore = Math.floor(anomalyRes.anomalyScore * 0.85);
      detectionMethod = 'ANOMALY_DETECTION';
      if (attackType === 'Normal Request') {
        attackType = anomalyRes.flags.some(f => f.factor.includes('Brute-Force')) ? 'Brute Force' : 'Anomaly Detection';
      }
    }

    if (isBlocked) {
      compositeScore = Math.min(100, compositeScore + 15);
    }

    // Severity mapping
    let severity: SeverityLevel = 'LOW';
    let actionTaken: ActionTaken = 'MONITORED';

    if (compositeScore >= 80) {
      severity = 'CRITICAL';
      actionTaken = 'BLOCKED';
    } else if (compositeScore >= 60) {
      severity = 'HIGH';
      actionTaken = 'QUARANTINED';
    } else if (compositeScore >= 30) {
      severity = 'MEDIUM';
      actionTaken = 'FLAGGED';
    }

    // Build detection reason string
    const reasons: string[] = [];
    ruleRes.indicators.forEach(i => reasons.push(`${i.label} ('${i.matchedText}')`));
    anomalyRes.flags.forEach(f => reasons.push(`${f.factor}: ${f.detail}`));
    const detectionReason = reasons.length > 0 ? reasons.join('; ') : 'No malicious patterns or anomalies identified.';

    // Encrypt security record
    const encryptedPayload = simulateAes256GcmEncrypt({
      sourceIp: input.sourceIp,
      method: input.method,
      url: input.url,
      parameters: input.parameters,
      userAgent: input.userAgent,
      frequency: input.frequency,
      body: input.body,
      timestamp: new Date().toISOString()
    });

    const newEvent: SecurityEvent = {
      id: Date.now() + Math.floor(Math.random() * 100),
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      sourceIp: input.sourceIp,
      requestMethod: input.method,
      requestUrl: input.url,
      userAgent: input.userAgent,
      attackType,
      detectionMethod,
      riskScore: compositeScore,
      severity,
      actionTaken,
      status: compositeScore > 25 ? 'DETECTED' : 'RESOLVED',
      detectionReason,
      encryptedPayload,
      rawPayload: {
        method: input.method,
        url: input.url,
        parameters: input.parameters,
        userAgent: input.userAgent,
        frequency: input.frequency,
        body: input.body
      },
      matchedIndicators: ruleRes.indicators,
      anomalyFlags: anomalyRes.flags,
      decryptedPlaintext: JSON.stringify(input, null, 2)
    };

    // Auto-quarantine if high risk and not already blocked
    if ((compositeScore >= 80 || severity === 'CRITICAL') && !isBlocked) {
      const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString().replace('T', ' ').substring(0, 19);
      this.blockedIps.unshift({
        id: Date.now(),
        ipAddress: input.sourceIp,
        reason: `Auto-blocked: ${attackType} (Risk Score: ${compositeScore})`,
        riskScore: compositeScore,
        blockedAt: newEvent.timestamp,
        expiresAt: expires,
        status: 'ACTIVE',
        blockedBy: 'SYSTEM_AUTO_BLOCK'
      });

      this.addAuditLog('AUTO_IP_BLOCK', `Automated IPS quarantined IP ${input.sourceIp} for 30m`);
    }

    this.events.unshift(newEvent);
    this.persistState();
    return newEvent;
  }

  // --- QUERY GETTERS & ACTIONS ---
  public getEvents(): SecurityEvent[] {
    return this.events;
  }

  public getEventById(id: number): SecurityEvent | undefined {
    return this.events.find(e => e.id === id);
  }

  public updateEventStatus(id: number, status: SecurityEvent['status']) {
    const ev = this.events.find(e => e.id === id);
    if (ev) {
      ev.status = status;
      this.addAuditLog('UPDATE_EVENT_STATUS', `Event #${id} status changed to ${status}`);
      this.persistState();
    }
  }

  public getBlockedIps(): BlockedIp[] {
    return this.blockedIps;
  }

  public blockIp(ip: string, reason: string, score: number = 85, durationMins: number = 30) {
    const existing = this.blockedIps.find(b => b.ipAddress === ip);
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const expires = new Date(Date.now() + durationMins * 60 * 1000).toISOString().replace('T', ' ').substring(0, 19);

    if (existing) {
      existing.status = 'ACTIVE';
      existing.reason = reason;
      existing.riskScore = score;
      existing.blockedAt = now;
      existing.expiresAt = expires;
      existing.blockedBy = this.currentUser.username;
    } else {
      this.blockedIps.unshift({
        id: Date.now(),
        ipAddress: ip,
        reason,
        riskScore: score,
        blockedAt: now,
        expiresAt: expires,
        status: 'ACTIVE',
        blockedBy: this.currentUser.username
      });
    }

    this.addAuditLog('MANUAL_IP_BLOCK', `IP ${ip} quarantined for ${durationMins}m by ${this.currentUser.username}`);
    this.persistState();
  }

  public unblockIp(ip: string) {
    const entry = this.blockedIps.find(b => b.ipAddress === ip);
    if (entry) {
      entry.status = 'WHITELISTED';
      this.addAuditLog('IP_UNBLOCK', `IP ${ip} whitelisted by ${this.currentUser.username}`);
      this.persistState();
    }
  }

  public getRules(): DetectionRule[] {
    return this.rules;
  }

  public addRule(rule: Omit<DetectionRule, 'id' | 'createdAt'>) {
    const newRule: DetectionRule = {
      ...rule,
      id: Date.now(),
      createdAt: new Date().toISOString().replace('T', ' ').substring(0, 19)
    };
    this.rules.unshift(newRule);
    this.addAuditLog('RULE_CREATE', `Created rule signature "${newRule.name}" (${newRule.attackType})`);
    this.persistState();
    return newRule;
  }

  public toggleRule(id: number) {
    const rule = this.rules.find(r => r.id === id);
    if (rule) {
      rule.isActive = !rule.isActive;
      this.addAuditLog('RULE_TOGGLE', `Rule "${rule.name}" set to ${rule.isActive ? 'ENABLED' : 'DISABLED'}`);
      this.persistState();
    }
  }

  public deleteRule(id: number) {
    const rule = this.rules.find(r => r.id === id);
    if (rule) {
      this.rules = this.rules.filter(r => r.id !== id);
      this.addAuditLog('RULE_DELETE', `Deleted rule "${rule.name}"`);
      this.persistState();
    }
  }

  public getUsers(): User[] {
    return this.users;
  }

  public getAuditLogs(): AuditLogEntry[] {
    return this.auditLogs;
  }

  public addAuditLog(action: string, details: string) {
    this.auditLogs.unshift({
      id: Date.now() + Math.floor(Math.random() * 50),
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      username: this.currentUser.username,
      action,
      target: 'SYSTEM',
      ipAddress: '127.0.0.1',
      details
    });
    this.persistState();
  }

  public resetDemoData() {
    this.events = [...INITIAL_EVENTS];
    this.rules = [...INITIAL_RULES];
    this.blockedIps = [...INITIAL_BLOCKED_IPS];
    this.auditLogs = [...INITIAL_AUDIT_LOGS];
    this.users = [...INITIAL_USERS];
    this.currentUser = INITIAL_USERS[0];
    this.persistState();
  }

  public getMetrics() {
    const totalRequests = Math.max(this.events.length * 5 + 240, 240);
    const detectedAttacks = this.events.filter(e => e.attackType !== 'Normal Request').length;
    const blockedCount = this.blockedIps.filter(b => b.status === 'ACTIVE').length;
    const criticalCount = this.events.filter(e => e.severity === 'CRITICAL').length;

    let riskLevel: 'NORMAL (LOW)' | 'MODERATE (HIGH)' | 'ELEVATED (CRITICAL)' = 'NORMAL (LOW)';
    let systemStatus: 'NOMINAL_MONITORING' | 'HEIGHTENED_ALERT' | 'ACTIVE_MITIGATION' = 'NOMINAL_MONITORING';

    if (criticalCount > 0 || blockedCount >= 2) {
      riskLevel = 'ELEVATED (CRITICAL)';
      systemStatus = 'ACTIVE_MITIGATION';
    } else if (detectedAttacks > 2) {
      riskLevel = 'MODERATE (HIGH)';
      systemStatus = 'HEIGHTENED_ALERT';
    }

    return {
      totalRequests,
      detectedAttacks,
      blockedIpsCount: blockedCount,
      criticalEventsCount: criticalCount,
      currentRiskLevel: riskLevel,
      systemStatus
    };
  }
}

export const securityEngine = new ZeroAttackEngine();
