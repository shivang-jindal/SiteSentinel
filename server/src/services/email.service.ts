/**
 * Email outbox (Part F / F3.6, Part A / A2).
 *
 * Every message is persisted before an attempt is made, so an operator can see
 * exactly what was queued, what the provider accepted and what failed.
 *
 * Status vocabulary, deliberately narrow:
 *   queued -> sent    the provider accepted the message for delivery
 *          -> failed  the provider rejected it (temporary or permanent)
 *
 * "sent" never means "delivered": SMTP returns no delivery receipt, so
 * SiteSentinel never claims one.
 */

import { desc, eq, sql } from 'drizzle-orm';

import type { AppDatabase } from '../db/client.js';
import { emailMessages } from '../db/schema.js';
import { notFound } from '../errors.js';
import type { EmailAdapter } from '../integrations/email/types.js';

export interface QueueResult {
  messageId: string;
  deduplicated: boolean;
}

export interface DeliverResult {
  status: 'sent' | 'failed';
  retryable: boolean;
  message: string;
  providerMessageId: string | null;
  failureCode: string | null;
}

export class EmailService {
  constructor(
    private readonly db: AppDatabase,
    private readonly adapter: EmailAdapter,
    private readonly fromAddress: string,
  ) {}

  get provider(): EmailAdapter {
    return this.adapter;
  }

  get from(): string {
    return this.fromAddress;
  }

  /** Persist a message without sending it. */
  async queue(input: {
    organizationId: string | null;
    templateType: string;
    to: string;
    subject: string;
    bodyText: string;
    relatedIncidentId?: string | null;
    idempotencyKey?: string | null;
  }): Promise<QueueResult> {
    if (input.idempotencyKey) {
      const existing = await this.db
        .select({ id: emailMessages.id })
        .from(emailMessages)
        .where(eq(emailMessages.idempotencyKey, input.idempotencyKey))
        .limit(1);
      const found = existing[0];
      if (found) return { messageId: found.id, deduplicated: true };
    }

    const inserted = await this.db
      .insert(emailMessages)
      .values({
        organizationId: input.organizationId,
        templateType: input.templateType,
        toAddress: input.to,
        fromAddress: this.fromAddress,
        subject: input.subject,
        bodyText: input.bodyText,
        status: 'queued',
        relatedIncidentId: input.relatedIncidentId ?? null,
        idempotencyKey: input.idempotencyKey ?? null,
      })
      .returning({ id: emailMessages.id });

    const row = inserted[0];
    if (!row) return { messageId: '', deduplicated: true };
    return { messageId: row.id, deduplicated: false };
  }

  async deliver(messageId: string): Promise<DeliverResult> {
    const rows = await this.db.select().from(emailMessages).where(eq(emailMessages.id, messageId)).limit(1);
    const row = rows[0];
    if (!row) throw notFound('Email message');

    const result = await this.adapter.send({
      to: row.toAddress,
      from: row.fromAddress,
      subject: row.subject,
      text: row.bodyText ?? '',
      ...(row.idempotencyKey ? { idempotencyKey: row.idempotencyKey } : {}),
    });

    if (result.accepted) {
      await this.db
        .update(emailMessages)
        .set({
          status: 'sent',
          providerMessageId: result.providerMessageId ?? null,
          sentAt: new Date(),
          failureCode: null,
          safeFailureMessage: null,
        })
        .where(eq(emailMessages.id, messageId));
      return {
        status: 'sent',
        retryable: false,
        message: result.message,
        providerMessageId: result.providerMessageId ?? null,
        failureCode: null,
      };
    }

    const failureCode = result.failureCode ?? 'provider_error';
    const retryable = failureCode === 'temporary' || failureCode === 'provider_error';
    await this.db
      .update(emailMessages)
      .set({
        status: 'failed',
        failureCode,
        safeFailureMessage: result.message.slice(0, 300),
      })
      .where(eq(emailMessages.id, messageId));

    return {
      status: 'failed',
      retryable,
      message: result.message,
      providerMessageId: null,
      failureCode,
    };
  }

  async outbox(organizationId: string, limit = 50) {
    return this.db
      .select({
        id: emailMessages.id,
        templateType: emailMessages.templateType,
        toAddress: emailMessages.toAddress,
        subject: emailMessages.subject,
        status: emailMessages.status,
        providerMessageId: emailMessages.providerMessageId,
        failureCode: emailMessages.failureCode,
        safeFailureMessage: emailMessages.safeFailureMessage,
        sentAt: emailMessages.sentAt,
        createdAt: emailMessages.createdAt,
      })
      .from(emailMessages)
      .where(eq(emailMessages.organizationId, organizationId))
      .orderBy(desc(emailMessages.createdAt))
      .limit(Math.min(Math.max(limit, 1), 200));
  }

  async stats(organizationId: string) {
    const rows = await this.db
      .select({ status: emailMessages.status, count: sql<number>`count(*)::int` })
      .from(emailMessages)
      .where(eq(emailMessages.organizationId, organizationId))
      .groupBy(emailMessages.status);
    return Object.fromEntries(rows.map((row) => [row.status, row.count])) as Record<string, number>;
  }
}