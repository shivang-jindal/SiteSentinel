# SiteSentinel

> **Uptime, Endpoint, SSL & Status-Page Monitoring for Small Teams**

[![CI](https://github.com/shivang-jindal/SiteSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/shivang-jindal/SiteSentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4-lightgrey)](https://expressjs.com/)
[![Drizzle ORM](https://img.shields.io/badge/Drizzle-ORM-brightgreen)](https://orm.drizzle.team/)

---

## Features

- **Multi-Protocol Probes**: HTTP/HTTPS, TCP, SSL/TLS, DNS
- **SSRF-Hardened**: IPv4/IPv6 allow/deny lists, NAT64/loopback protection
- **Incidents**: Auto-open/close, severity, escalation policies
- **Alert Channels**: Email, webhook, PagerDuty, Slack
- **Status Pages**: Public/private, custom domains, branding
- **Maintenance Windows**: Scheduled, suppressed alerts
- **SSL/TLS**: Expiry tracking, chain validation, OCSP
- **118 Tests**: Engine, SSRF, probe tests (all passing)

---

## Quick Start

```bash
git clone https://github.com/shivang-jindal/SiteSentinel.git
cd SiteSentinel
npm install
npm run dev
```

Configure `.env` (copy `.env.example`):
```env
DATABASE_URL="postgresql://..."  # or omit for PGlite
ENCRYPTION_KEY="64-char-hex-key"
SESSION_SECRET="random-string"
EMAIL_PROVIDER="smtp|disabled|log"
```

---

## Architecture

```
SiteSentinel/
├── client/          # React 18 + Vite 6 + Tailwind v4
├── server/          # Express 4 + Drizzle ORM + PGlite
├── shared/          # Shared types, Zod schemas, SSRF utils
└── scripts/         # Dev, migration, verification
```

**Stack**: React 18 · Vite 6 · TypeScript · Tailwind v4 · React Router · TanStack Query  
**Backend**: Express 4 · Zod · Drizzle ORM · PGlite (embedded PostgreSQL)  
**Auth**: Argon2id · opaque 256-bit tokens · HTTP-only cookies  
**Probes**: SSRF-hardened HTTP/TCP/SSL/DNS · IPv4/IPv6 allow/deny  
**Jobs**: DB-backed queue (`FOR UPDATE SKIP LOCKED`) · separate worker

---

## Configuration

All settings via environment variables (see `.env.example`):

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | No | PostgreSQL URL (omit for PGlite) |
| `ENCRYPTION_KEY` | Yes | 64-char hex (32 bytes) |
| `SESSION_SECRET` | Yes | Random string |
| `EMAIL_PROVIDER` | Yes | `smtp` \| `disabled` \| `log` |

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start dev servers (client + server) |
| `npm run build` | Production build |
| `npm run verify` | Typecheck + Lint + Test + Build |
| `npm test` | Unit/integration tests (118 passing) |
| `npm run db:generate` | Generate Drizzle migrations |
| `npm run db:migrate` | Run migrations |
| `npm run smoke` | Smoke test against running instance |

---

## Deployment

```bash
npm run build
# Deploy server/ + client/dist/ to your platform
```

Requires: Node 20+, PostgreSQL (or PGlite for embedded).

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) • [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) • [SECURITY.md](SECURITY.md)