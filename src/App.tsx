/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Sidebar, NavView } from './components/Sidebar';
import { Header } from './components/Header';
import { DashboardView } from './components/views/DashboardView';
import { LiveMonitorView } from './components/views/LiveMonitorView';
import { AttackEventsView } from './components/views/AttackEventsView';
import { AttackDetailsModal } from './components/views/AttackDetailsModal';
import { IpManagementView } from './components/views/IpManagementView';
import { DetectionRulesView } from './components/views/DetectionRulesView';
import { UsersRolesView } from './components/views/UsersRolesView';
import { ReportsView } from './components/views/ReportsView';
import { AuditLogsView } from './components/views/AuditLogsView';
import { SettingsView } from './components/views/SettingsView';
import { CodeExplorerView } from './components/views/CodeExplorerView';

import { securityEngine } from './services/detectionEngine';
import {
  SecurityEvent,
  BlockedIp,
  DetectionRule,
  AuditLogEntry,
  UserRole,
  SystemMetrics,
  RequestAnalysisInput
} from './types/security';

export default function App() {
  const [currentView, setCurrentView] = useState<NavView>('dashboard');
  const [userRole, setUserRole] = useState<UserRole>(securityEngine.getCurrentUser().role);
  const [events, setEvents] = useState<SecurityEvent[]>(securityEngine.getEvents());
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>(securityEngine.getBlockedIps());
  const [rules, setRules] = useState<DetectionRule[]>(securityEngine.getRules());
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(securityEngine.getAuditLogs());
  const [metrics, setMetrics] = useState<SystemMetrics>(securityEngine.getMetrics());
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Sync state helper
  const refreshEngineState = () => {
    setEvents([...securityEngine.getEvents()]);
    setBlockedIps([...securityEngine.getBlockedIps()]);
    setRules([...securityEngine.getRules()]);
    setAuditLogs([...securityEngine.getAuditLogs()]);
    setMetrics(securityEngine.getMetrics());
  };

  const handleRoleChange = (newRole: UserRole) => {
    securityEngine.setCurrentRole(newRole);
    setUserRole(newRole);
    refreshEngineState();
  };

  const handleAnalyzeRequest = (input: RequestAnalysisInput): SecurityEvent => {
    const newEvent = securityEngine.analyzeRequest(input);
    refreshEngineState();
    return newEvent;
  };

  const handleUpdateStatus = (id: number, status: SecurityEvent['status']) => {
    securityEngine.updateEventStatus(id, status);
    if (selectedEvent && selectedEvent.id === id) {
      setSelectedEvent({ ...selectedEvent, status });
    }
    refreshEngineState();
  };

  const handleBlockIp = (ip: string, reason: string, score: number, duration: number) => {
    securityEngine.blockIp(ip, reason, score, duration);
    refreshEngineState();
  };

  const handleUnblockIp = (ip: string) => {
    securityEngine.unblockIp(ip);
    refreshEngineState();
  };

  const handleAddRule = (rule: Omit<DetectionRule, 'id' | 'createdAt'>) => {
    securityEngine.addRule(rule);
    refreshEngineState();
  };

  const handleToggleRule = (id: number) => {
    securityEngine.toggleRule(id);
    refreshEngineState();
  };

  const handleDeleteRule = (id: number) => {
    securityEngine.deleteRule(id);
    refreshEngineState();
  };

  const handleResetDemo = () => {
    securityEngine.resetDemoData();
    setUserRole('ADMIN');
    refreshEngineState();
  };

  const getBreadcrumb = () => {
    switch (currentView) {
      case 'dashboard':
        return { title: 'Security Operations Center (SOC)', subtitle: 'Real-Time Threat Intelligence' };
      case 'monitor':
        return { title: 'Live Security Monitor', subtitle: 'Packet Inspector & Simulator' };
      case 'events':
        return { title: 'Attack Incidents', subtitle: 'Forensic Detection Logs' };
      case 'ips':
        return { title: 'IP Management', subtitle: 'Host Quarantine & Firewall' };
      case 'rules':
        return { title: 'Detection Rules', subtitle: 'Heuristic & Regex Signatures' };
      case 'users':
        return { title: 'Users & Roles', subtitle: 'Role-Based Access Control (RBAC)' };
      case 'reports':
        return { title: 'Threat Intelligence Reports', subtitle: 'Executive Posture & CSV/JSON Export' };
      case 'audit':
        return { title: 'Compliance Audit Logs', subtitle: 'System Operator Traceability' };
      case 'settings':
        return { title: 'Engine Settings', subtitle: 'Defense Parameters & Cryptography' };
      case 'code':
        return { title: 'Backend Source Code', subtitle: 'Python Flask / MySQL / AES-256' };
      default:
        return { title: 'ZeroAttack', subtitle: 'Cyber Defense' };
    }
  };

  const recentCritical = events.filter(e => e.severity === 'CRITICAL' || e.severity === 'HIGH').slice(0, 5);
  const breadcrumb = getBreadcrumb();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 font-sans antialiased selection:bg-cyan-500 selection:text-slate-950">
      {/* Sidebar Navigation */}
      <Sidebar
        currentView={currentView}
        onSelectView={(v) => setCurrentView(v)}
        userRole={userRole}
        blockedCount={blockedIps.filter(b => b.status === 'ACTIVE').length}
        criticalCount={events.filter(e => e.severity === 'CRITICAL').length}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Universal SaaS Header */}
        <Header
          title={breadcrumb.title}
          subtitle={breadcrumb.subtitle}
          metrics={metrics}
          userRole={userRole}
          onRoleChange={handleRoleChange}
          onOpenSimulator={() => setCurrentView('monitor')}
          recentCriticalEvents={recentCritical}
          onSelectEvent={(ev) => setSelectedEvent(ev)}
        />

        {/* Viewport View Switcher */}
        <main className="flex-1 overflow-y-auto">
          {currentView === 'dashboard' && (
            <DashboardView
              metrics={metrics}
              events={events}
              blockedIps={blockedIps}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              onNavigateToMonitor={() => setCurrentView('monitor')}
              onNavigateToIps={() => setCurrentView('ips')}
              onNavigateToEvents={() => setCurrentView('events')}
            />
          )}

          {currentView === 'monitor' && (
            <LiveMonitorView
              onAnalyze={handleAnalyzeRequest}
              onOpenDetails={(ev) => setSelectedEvent(ev)}
            />
          )}

          {currentView === 'events' && (
            <AttackEventsView
              events={events}
              onSelectEvent={(ev) => setSelectedEvent(ev)}
              onNavigateToMonitor={() => setCurrentView('monitor')}
            />
          )}

          {currentView === 'ips' && (
            <IpManagementView
              blockedIps={blockedIps}
              userRole={userRole}
              onBlockIp={handleBlockIp}
              onUnblockIp={handleUnblockIp}
            />
          )}

          {currentView === 'rules' && (
            <DetectionRulesView
              rules={rules}
              userRole={userRole}
              onAddRule={handleAddRule}
              onToggleRule={handleToggleRule}
              onDeleteRule={handleDeleteRule}
            />
          )}

          {currentView === 'users' && (
            <UsersRolesView
              users={securityEngine.getUsers()}
              currentRole={userRole}
              onSelectRole={handleRoleChange}
            />
          )}

          {currentView === 'reports' && (
            <ReportsView
              events={events}
              blockedIps={blockedIps}
            />
          )}

          {currentView === 'audit' && (
            <AuditLogsView
              logs={auditLogs}
            />
          )}

          {currentView === 'settings' && (
            <SettingsView
              userRole={userRole}
              onResetDemo={handleResetDemo}
            />
          )}

          {currentView === 'code' && (
            <CodeExplorerView />
          )}
        </main>
      </div>

      {/* Forensic Deep Dive / Decryption Modal */}
      {selectedEvent && (
        <AttackDetailsModal
          event={selectedEvent}
          userRole={userRole}
          onClose={() => setSelectedEvent(null)}
          onUpdateStatus={handleUpdateStatus}
        />
      )}
    </div>
  );
}
