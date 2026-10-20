ALTER TABLE "monitor_checks" ADD COLUMN "tls_issuer" text;--> statement-breakpoint
ALTER TABLE "monitor_checks" ADD COLUMN "tls_subject" text;--> statement-breakpoint
ALTER TABLE "monitor_checks" ADD COLUMN "tls_serial_number" text;--> statement-breakpoint
ALTER TABLE "monitor_checks" ADD COLUMN "tls_protocol" text;--> statement-breakpoint
ALTER TABLE "monitor_checks" ADD COLUMN "tls_chain_valid" boolean;--> statement-breakpoint
ALTER TABLE "monitor_checks" ADD COLUMN "tls_chain_error" text;--> statement-breakpoint
ALTER TABLE "monitor_checks" ADD COLUMN "tls_self_signed" boolean;