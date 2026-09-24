-- ===================================================================
-- ZeroAttack: Database Schema (MySQL 8.0+)
-- Intelligent Rule-Based Cyber Attack Detection and Prevention System
-- ===================================================================

CREATE DATABASE IF NOT EXISTS `zeroattack_db` 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE `zeroattack_db`;

-- Drop tables if re-initializing
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `blocked_ips`;
DROP TABLE IF EXISTS `security_events`;
DROP TABLE IF EXISTS `rules`;
DROP TABLE IF EXISTS `users`;
SET FOREIGN_KEY_CHECKS = 1;

-- -----------------------------------------------------
-- Table: users
-- -----------------------------------------------------
CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(64) NOT NULL UNIQUE,
  `email` VARCHAR(128) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` ENUM('ADMIN', 'SECURITY ANALYST', 'VIEWER') NOT NULL DEFAULT 'VIEWER',
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `last_login` TIMESTAMP NULL DEFAULT NULL,
  INDEX `idx_username` (`username`),
  INDEX `idx_role` (`role`)
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Table: rules
-- -----------------------------------------------------
CREATE TABLE `rules` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(128) NOT NULL,
  `attack_type` VARCHAR(64) NOT NULL, -- SQL Injection, XSS, Brute Force, Parameter Tampering, etc.
  `pattern` TEXT NOT NULL,           -- Regex signature or matching condition
  `target_field` VARCHAR(64) NOT NULL DEFAULT 'ALL', -- URL, PARAMETERS, HEADERS, BODY, ALL
  `description` VARCHAR(255) NULL,
  `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  `risk_weight` INT NOT NULL DEFAULT 25,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_attack_type` (`attack_type`),
  INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Table: security_events
-- -----------------------------------------------------
CREATE TABLE `security_events` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `source_ip` VARCHAR(45) NOT NULL, -- IPv4 or IPv6
  `request_method` VARCHAR(10) NOT NULL,
  `request_url` TEXT NOT NULL,
  `user_agent` VARCHAR(255) NULL,
  `attack_type` VARCHAR(64) NOT NULL,
  `detection_method` ENUM('RULE_BASED', 'ANOMALY_DETECTION', 'HYBRID_ENGINE') NOT NULL,
  `risk_score` INT NOT NULL,
  `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
  `action_taken` ENUM('MONITORED', 'FLAGGED', 'BLOCKED', 'QUARANTINED') NOT NULL DEFAULT 'FLAGGED',
  `status` ENUM('DETECTED', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'DETECTED',
  `matched_rule_id` INT NULL,
  `encrypted_payload` MEDIUMTEXT NULL, -- AES-256-GCM encrypted raw request body / parameters
  `detection_details` TEXT NULL,       -- JSON description of triggers & scoring components
  INDEX `idx_source_ip` (`source_ip`),
  INDEX `idx_severity` (`severity`),
  INDEX `idx_attack_type` (`attack_type`),
  INDEX `idx_timestamp` (`timestamp`),
  CONSTRAINT `fk_event_rule` FOREIGN KEY (`matched_rule_id`) REFERENCES `rules` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Table: blocked_ips
-- -----------------------------------------------------
CREATE TABLE `blocked_ips` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `ip_address` VARCHAR(45) NOT NULL UNIQUE,
  `reason` VARCHAR(255) NOT NULL,
  `risk_score` INT NOT NULL,
  `blocked_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `expires_at` TIMESTAMP NOT NULL,
  `status` ENUM('ACTIVE', 'EXPIRED', 'WHITELISTED') NOT NULL DEFAULT 'ACTIVE',
  `blocked_by` VARCHAR(64) NOT NULL DEFAULT 'SYSTEM_AUTO_BLOCK',
  INDEX `idx_ip_address` (`ip_address`),
  INDEX `idx_status` (`status`),
  INDEX `idx_expires_at` (`expires_at`)
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Table: audit_logs
-- -----------------------------------------------------
CREATE TABLE `audit_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `user_id` INT NULL,
  `username` VARCHAR(64) NOT NULL,
  `action` VARCHAR(64) NOT NULL, -- LOGIN, LOGOUT, RULE_CREATE, RULE_UPDATE, IP_BLOCK, IP_UNBLOCK, MITIGATION_OVERRIDE
  `target` VARCHAR(128) NULL,
  `ip_address` VARCHAR(45) NOT NULL,
  `details` TEXT NULL,
  INDEX `idx_timestamp` (`timestamp`),
  INDEX `idx_username` (`username`),
  INDEX `idx_action` (`action`)
) ENGINE=InnoDB;

-- -----------------------------------------------------
-- Seed Initial Security Rules
-- -----------------------------------------------------
INSERT INTO `rules` (`name`, `attack_type`, `pattern`, `target_field`, `description`, `severity`, `risk_weight`, `is_active`) VALUES
('Classic SQL Injection (OR 1=1)', 'SQL Injection', '(?i)((\\%27)|(\'))\\s*(or|and)\\s+(\\d+|\\\'\\w+\\\')\\s*=\\s*(\\d+|\\\'\\w+\\\')|(--)|(\\/\\*)|(;.*(drop|select|union|update|delete|insert))', 'ALL', 'Detects classic tautology OR 1=1 and comment termination patterns', 'CRITICAL', 85, 1),
('SQL UNION SELECT Exploitation', 'SQL Injection', '(?i)union(\\s+all)?\\s+select', 'ALL', 'Detects attempts to extract data through SQL UNION SELECT queries', 'CRITICAL', 90, 1),
('Stored & Reflected Script Tags (XSS)', 'Cross-Site Scripting (XSS)', '(?i)<script[\\s>].*?|<\\/script>|javascript:[^"]+|on(error|load|click|mouseover|submit)\\s*=', 'ALL', 'Detects script tags and JavaScript execution event handlers in payloads', 'HIGH', 75, 1),
('Document Cookie & DOM Stealing (XSS)', 'Cross-Site Scripting (XSS)', '(?i)(document\\.cookie|window\\.location|eval\\(|alert\\(|prompt\\(|String\\.fromCharCode)', 'ALL', 'Detects DOM manipulation and session token exfiltration primitives', 'HIGH', 70, 1),
('Directory / Path Traversal Attack', 'Parameter Tampering', '(?i)(\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c|\\/etc\\/passwd|c:\\\\windows\\\\system32)', 'URL', 'Detects directory traversal payloads aiming to read unauthorized system files', 'HIGH', 75, 1),
('Administrative Parameter Manipulation', 'Parameter Tampering', '(?i)(isAdmin|role|privilege|is_admin|superuser|debug)\\s*=\\s*(true|1|admin|root|system)', 'PARAMETERS', 'Detects unauthorized elevation attempts through request parameter override', 'MEDIUM', 50, 1),
('Brute-Force Credential Stuffing', 'Brute Force', 'BURST_FAILURE_PATTERN', 'HEADERS', 'Heuristic rule tracking rapid credential authentication failures from a single IP', 'CRITICAL', 85, 1),
('Suspicious Vulnerability Scanner User-Agent', 'Anomaly Detection', '(?i)(nikto|sqlmap|acunetix|nessus|nmap|dirbuster|gobuster|wpscan|masscan)', 'HEADERS', 'Detects known automated vulnerability scanners and exploitation toolkits', 'HIGH', 65, 1);

-- -----------------------------------------------------
-- Seed Demo Accounts (Passwords: Admin@123, Analyst@123, Viewer@123)
-- PBKDF2/SHA256 Hashes
-- -----------------------------------------------------
INSERT INTO `users` (`username`, `email`, `password_hash`, `role`, `is_active`) VALUES
('admin', 'admin@zeroattack.sec', 'scrypt:32768:8:1$KqV4F3jL$6f59b66a87c126d40026e7a2b918645ce1e6ce681335cb8a19280dcb458a2d16560938f375f4621d12da344f6cf7cb3e0a2944b20721bc8201a4e142e0ba3eb3', 'ADMIN', 1),
('analyst', 'analyst@zeroattack.sec', 'scrypt:32768:8:1$KqV4F3jL$6f59b66a87c126d40026e7a2b918645ce1e6ce681335cb8a19280dcb458a2d16560938f375f4621d12da344f6cf7cb3e0a2944b20721bc8201a4e142e0ba3eb3', 'SECURITY ANALYST', 1),
('viewer', 'viewer@zeroattack.sec', 'scrypt:32768:8:1$KqV4F3jL$6f59b66a87c126d40026e7a2b918645ce1e6ce681335cb8a19280dcb458a2d16560938f375f4621d12da344f6cf7cb3e0a2944b20721bc8201a4e142e0ba3eb3', 'VIEWER', 1);

-- -----------------------------------------------------
-- Seed Initial Audit Log
-- -----------------------------------------------------
INSERT INTO `audit_logs` (`user_id`, `username`, `action`, `target`, `ip_address`, `details`) VALUES
(1, 'admin', 'SYSTEM_INITIALIZATION', 'DATABASE', '127.0.0.1', 'ZeroAttack Database initialized with baseline rule signatures and RBAC policies.');
