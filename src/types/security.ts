export type UserRole = 'ADMIN' | 'SECURITY ANALYST' | 'VIEWER';

export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  isActive: boolean;
  lastLogin: string;
}

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AttackCategory = 
  | 'SQL Injection'
  | 'Cross-Site Scripting (XSS)'
  | 'Brute Force'
  | 'Parameter Tampering'
  | 'Anomaly Detection'
  | 'Normal Request';

export type DetectionMethod = 'RULE_BASED' | 'ANOMALY_DETECTION' | 'HYBRID_ENGINE';

export type ActionTaken = 'MONITORED' | 'FLAGGED' | 'QUARANTINED' | 'BLOCKED';

export type EventStatus = 'DETECTED' | 'INVESTIGATING' | 'MITIGATED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface MatchedIndicator {
  type: string;
  label: string;
  matchedText: string;
  weight: number;
}

export interface AnomalyFlag {
  factor: string;
  detail: string;
  severityContrib: number;
}

export interface SecurityEvent {
  id: number;
  timestamp: string;
  sourceIp: string;
  requestMethod: string;
  requestUrl: string;
  userAgent: string;
  attackType: AttackCategory;
  detectionMethod: DetectionMethod;
  riskScore: number;
  severity: SeverityLevel;
  actionTaken: ActionTaken;
  status: EventStatus;
  detectionReason: string;
  encryptedPayload: string;
  rawPayload: {
    method: string;
    url: string;
    parameters: string;
    userAgent: string;
    frequency: number;
    body?: string;
  };
  matchedIndicators: MatchedIndicator[];
  anomalyFlags: AnomalyFlag[];
  decryptedPlaintext?: string;
}

export interface BlockedIp {
  id: number;
  ipAddress: string;
  reason: string;
  riskScore: number;
  blockedAt: string;
  expiresAt: string;
  status: 'ACTIVE' | 'EXPIRED' | 'WHITELISTED';
  blockedBy: string;
}

export interface DetectionRule {
  id: number;
  name: string;
  attackType: AttackCategory;
  pattern: string;
  targetField: 'ALL' | 'URL' | 'PARAMETERS' | 'HEADERS' | 'BODY';
  description: string;
  severity: SeverityLevel;
  riskWeight: number;
  isActive: boolean;
  createdAt: string;
}

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  username: string;
  action: string;
  target: string;
  ipAddress: string;
  details: string;
}

export interface SystemMetrics {
  totalRequests: number;
  detectedAttacks: number;
  blockedIpsCount: number;
  criticalEventsCount: number;
  currentRiskLevel: 'NORMAL (LOW)' | 'MODERATE (HIGH)' | 'ELEVATED (CRITICAL)';
  systemStatus: 'NOMINAL_MONITORING' | 'HEIGHTENED_ALERT' | 'ACTIVE_MITIGATION';
}

export interface RequestAnalysisInput {
  sourceIp: string;
  method: string;
  url: string;
  parameters: string;
  userAgent: string;
  frequency: number;
  body?: string;
}
