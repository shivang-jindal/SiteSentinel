/**
 * Alert email templates (Part F / F3.6).
 *
 * Templates are plain text only. No HTML is generated and no target page
 * content is ever interpolated into an alert, because response bodies are never
 * stored in the first place (Part F / F7).
 */

export interface IncidentAlertContext {
  organizationName: string;
  incidentTitle: string;
  severity: 'minor' | 'major' | 'critical';
  monitorNames: string[];
  /** Operator-facing failure category, never a page body. */
  failureSummary: string | null;
  startedAt: string;
  statusPageUrl: string | null;
  dashboardUrl: string;
  isRecovery: boolean;
  resolvedAt: string | null;
}

export interface TestAlertContext {
  organizationName: string;
  channelName: string;
  requestedBy: string;
}

export interface SslAlertContext {
  organizationName: string;
  monitorName: string;
  host: string;
  expiresAt: string;
  daysRemaining: number;
  warningLevelDays: number;
  dashboardUrl: string;
}

export interface InvitationContext {
  organizationName: string;
  inviterName: string;
  acceptUrl: string;
  role: string;
}

const SEVERITY_WORDS: Record<IncidentAlertContext['severity'], string> = {
  minor: 'MINOR',
  major: 'MAJOR',
  critical: 'CRITICAL',
};

export function renderIncidentAlert(context: IncidentAlertContext): {
  subject: string;
  text: string;
} {
  const monitors = context.monitorNames.length > 0 ? context.monitorNames.join(', ') : 'the affected monitors';
  if (context.isRecovery) {
    return {
      subject: `[RESOLVED] ${context.organizationName}: ${context.incidentTitle}`,
      text: [
        `${context.organizationName} - incident resolved`,
        '',
        `Incident:  ${context.incidentTitle}`,
        `Monitors:  ${monitors}`,
        `Started:   ${context.startedAt}`,
        `Resolved:  ${context.resolvedAt ?? new Date().toISOString()}`,
        '',
        context.statusPageUrl ? `Public status page: ${context.statusPageUrl}` : '',
        context.statusPageUrl ? `Dashboard:            ${context.dashboardUrl}` : `Dashboard: ${context.dashboardUrl}`,
        '',
        'This message reports that SiteSentinel observed the configured threshold of',
        'successful checks. It does not guarantee the service is reachable from every',
        'network or region.',
      ]
        .filter((line) => line !== '')
        .join('\n'),
    };
  }

  return {
    subject: `[${SEVERITY_WORDS[context.severity]}] ${context.organizationName}: ${context.incidentTitle}`,
    text: [
      `${context.organizationName} - monitoring incident detected`,
      '',
      `Severity:  ${SEVERITY_WORDS[context.severity]}`,
      `Incident:  ${context.incidentTitle}`,
      `Monitors:  ${monitors}`,
      `Detected:  ${context.startedAt}`,
      context.failureSummary ? `Observed:  ${context.failureSummary}` : '',
      '',
      context.statusPageUrl ? `Public status page: ${context.statusPageUrl}` : '',
      `Dashboard: ${context.dashboardUrl}`,
      '',
      'SiteSentinel reports what the probe observed from its own deployment',
      'location. It cannot prove availability from every user network.',
    ]
        .filter((line) => line !== '')
        .join('\n'),
  };
}

export function renderSslAlert(context: SslAlertContext): { subject: string; text: string } {
  return {
    subject: `[SSL] ${context.organizationName}: ${context.monitorName} expires in ${context.daysRemaining} day(s)`,
    text: [
      `${context.organizationName} - SSL certificate expiry warning`,
      '',
      `Monitor:     ${context.monitorName}`,
      `Host:        ${context.host}`,
      `Expires at:  ${context.expiresAt}`,
      `Days left:   ${context.daysRemaining}`,
      `Warning level crossed: ${context.warningLevelDays} day(s)`,
      '',
      `Dashboard: ${context.dashboardUrl}`,
      '',
      'This expiry date comes from a real TLS handshake performed by SiteSentinel.',
    ].join('\n'),
  };
}

export function renderChannelTest(context: TestAlertContext): { subject: string; text: string } {
  return {
    subject: `[Test] SiteSentinel alert channel "${context.channelName}"`,
    text: [
      `${context.organizationName} - alert channel test`,
      '',
      `Channel:   ${context.channelName}`,
      `Requested: ${context.requestedBy}`,
      '',
      'You are receiving this because somebody asked SiteSentinel to verify this',
      'alert channel. No incident was open when this message was generated.',
      '',
      'Receiving this message means the provider accepted it. It does not confirm',
      'delivery to an inbox.',
    ].join('\n'),
  };
}

export function renderInvitation(context: InvitationContext): { subject: string; text: string } {
  return {
    subject: `You have been invited to ${context.organizationName} on SiteSentinel`,
    text: [
      `${context.inviterName} invited you to join ${context.organizationName} as ${context.role}.`,
      '',
      `Accept the invitation: ${context.acceptUrl}`,
      '',
      'The link expires in 7 days and can only be used once.',
    ].join('\n'),
  };
}

export function renderPasswordReset(appUrl: string, token: string): { subject: string; text: string } {
  return {
    subject: 'Reset your SiteSentinel password',
    text: [
      'A password reset was requested for your SiteSentinel account.',
      '',
      `Reset link: ${appUrl}/reset-password?token=${token}`,
      '',
      'The link expires in 60 minutes. If you did not request it, you can ignore this message.',
    ].join('\n'),
  };
}

/** Webhook payload delivered to a signed alert webhook (Part F / F3.6). */
export function renderWebhookPayload(eventType: string, data: Record<string, unknown>): string {
  return JSON.stringify({ event: eventType, occurredAt: new Date().toISOString(), data });
}