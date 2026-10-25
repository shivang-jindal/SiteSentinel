/**
 * Service container. One instance per process; every service is stateless apart
 * from its database handle and configuration.
 */

import type { Permission, Role } from '@sitesentinel/shared';
import { permissionsForRole } from '@sitesentinel/shared';
import type { Logger } from 'pino';

import type { AppConfig } from './config.js';
import type { AppDatabase } from './db/client.js';
import { DisabledEmailAdapter } from './integrations/email/disabled.js';
import { LogEmailAdapter } from './integrations/email/log.js';
import { SmtpEmailAdapter } from './integrations/email/smtp.js';
import type { EmailAdapter } from './integrations/email/types.js';
import { JobQueue } from './jobs/queue.js';
import { AlertService } from './services/alert.service.js';
import { AuditService } from './services/audit.service.js';
import { AuthService } from './services/auth.service.js';
import { DashboardService } from './services/dashboard.service.js';
import { EmailService } from './services/email.service.js';
import { ExportService } from './services/export.service.js';
import { IncidentService } from './services/incident.service.js';
import { MaintenanceService } from './services/maintenance.service.js';
import { MonitorService } from './services/monitor.service.js';
import { OrganizationService } from './services/organization.service.js';
import { ProbeService } from './services/probe.service.js';
import { StatusPageService } from './services/status-page.service.js';

export interface Services {
  config: AppConfig;
  logger: Logger;
  db: AppDatabase;
  audit: AuditService;
  auth: AuthService;
  organizations: OrganizationService;
  monitors: MonitorService;
  probes: ProbeService;
  incidents: IncidentService;
  alerts: AlertService;
  maintenance: MaintenanceService;
  statusPages: StatusPageService;
  dashboard: DashboardService;
  exports: ExportService;
  email: EmailService;
  emailAdapter: EmailAdapter;
  jobs: JobQueue;
  permissionsFor: (role: Role) => Permission[];
}

export function createServices(options: {
  db: AppDatabase;
  config: AppConfig;
  logger: Logger;
}): Services {
  const { db, config, logger } = options;

  const adapter = createEmailAdapter(config);
  const audit = new AuditService(db);
  const jobs = new JobQueue(db);
  const auth = new AuthService(db, config.session.ttlHours, config.firebase.projectId);
  const organizations = new OrganizationService(db, audit);
  const monitors = new MonitorService(db, audit);
  const incidents = new IncidentService(db, audit);
  const maintenance = new MaintenanceService(db, audit);
  const email = new EmailService(
    db,
    adapter,
    config.email.from ?? 'SiteSentinel <no-reply@sitesentinel.local>',
  );
  const alerts = new AlertService(
    db,
    audit,
    jobs,
    email,
    maintenance,
    config.encryptionKey,
    config.appUrl,
  );
  const probes = new ProbeService(db, incidents, alerts, maintenance, organizations, logger);
  const statusPages = new StatusPageService(db, audit, config.appUrl);
  const dashboard = new DashboardService(db, organizations, incidents, maintenance, probes, adapter);
  const exports = new ExportService(db, audit);

  return {
    config,
    logger,
    db,
    audit,
    auth,
    organizations,
    monitors,
    probes,
    incidents,
    alerts,
    maintenance,
    statusPages,
    dashboard,
    exports,
    email,
    emailAdapter: adapter,
    jobs,
    permissionsFor: permissionsForRole,
  };
}

export function createEmailAdapter(config: AppConfig): EmailAdapter {
  switch (config.email.provider) {
    case 'smtp':
      return new SmtpEmailAdapter({
        host: config.email.host ?? 'localhost',
        port: config.email.port ?? 587,
        secure: config.email.secure,
        user: config.email.user,
        password: config.email.password,
      });
    case 'log':
      return new LogEmailAdapter(`${process.cwd()}/server/.data/outbox`);
    case 'disabled':
    default:
      return new DisabledEmailAdapter();
  }
}