# Mailtest — email authentication & deliverability analyzer

**Live demo:** <https://demo.mailtest.justfortesting.xyz> &nbsp;·&nbsp;
Built by [Justin Willmore](https://www.linkedin.com/in/justin-willmore-7bb87950/)

Send any email to a public address and, within a few seconds, see a full breakdown of SPF, DKIM, and DMARC alignment, content heuristics, sending-platform fingerprinting, and an aggregate 0–100 deliverability score — plus the raw envelope, the full MIME tree, and every auth header with verdict reasoning.

> **Interview TL;DR** — this is a self-hosted system I designed, wrote, and deployed end-to-end: public MX on a VPS, home-networked Docker stack reachable over a hardened SSH reverse tunnel, Caddy terminating TLS, FastAPI for the web layer, `aiosmtpd` for SMTP ingest, and Postgres for persistence. Every piece — from the analyzer internals to the operational runbooks and the layered abuse-protection on the public endpoint — is mine.

---

## Try it

- **URL**: <https://demo.mailtest.justfortesting.xyz>
- **Seeded data** — five pre-loaded emails covering all-pass, DMARC-fail spoof, missing-DKIM, minimal plaintext, and well-formed transactional. Click any row to see the full analysis.
- **Submit a live test** — click "Reveal address" on the top banner to get the demo inbox (`demo@mailtest.justfortesting.xyz`) and send to it from anywhere. Limited to **1 message/minute and 20/day per visitor**.
- **Everything resets daily at 00:00 UTC** so the page stays clean for the next visitor.

The UI is read-only in demo mode. Destructive endpoints (reanalyze, bulk delete, debug raw) live behind an admin API key I hold.

---

## What it actually does

- **SPF / DKIM / DMARC** — live resolver lookups of the sender's policies, DKIM signature verification, and alignment checks. Results surface as individual verdicts with reasoning, not a blunt pass/fail.
- **Sending-platform fingerprinting** — detects platform (SendGrid, Mailgun, Amazon SES, Google Workspace, Microsoft 365, Postmark, Mailchimp, etc.) from headers and routing hops with a confidence score.
- **Content heuristics** — HTML/plaintext ratio, image-to-text balance, link density, tracking-pixel detection, `List-Unsubscribe` / one-click support, spammy-phrase counts, obvious marketing-template tells.
- **Composite deliverability score** — a transparent 0–100 score with per-category weights and the exact checks that contributed.
- **Full MIME tree, parsed headers, raw source** — everything you'd want to copy-paste into a bug report.
- **Operational mailbox simulators** — `check@`, `complaint@` (synthesizes an RFC 5965 ARF report), and `bounce@` (SMTP `550` at RCPT time) mirror [Amazon SES's mailbox simulator](https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html), so you can exercise downstream complaint/bounce handling without real destinations.

---

## Architecture

```
            Public internet
                 │
    ┌────────────┴────────────┐
    │                         │
TCP 443 (HTTPS)           TCP 25 (SMTP)
    │                         │
    ▼                         ▼
┌────────────┐          ┌────────────┐
│   Caddy    │          │  Postfix   │
│   (VPS)    │          │   (VPS)    │
└─────┬──────┘          └─────┬──────┘
      │ reverse-proxy         │ transport_maps
      │ 127.0.0.1:18080       │ [home]:10025
      ▼                       ▼
  ╔══════════════ SSH reverse tunnel (autossh) ═══════════════╗
  ║                                                            ║
  ║        FastAPI :8080  ◀─── /ingest  ◀───  email-bridge :10025
  ║           │                                                ║
  ║           ▼                                                ║
  ║       Postgres                                             ║
  ║                                                            ║
  ║       seeder (sidecar; truncates + re-seeds at 00:00 UTC)  ║
  ╚════════════════════════════════════════════════════════════╝
```

- **VPS** (public, `mailtest.justfortesting.xyz`): Caddy + Postfix only. Two reverse proxies — one for HTTPS, one for SMTP. No application code runs here.
- **Home** (private, behind NAT): the entire application stack. Reachable from the VPS only via an SSH reverse tunnel kept alive by `autossh` under `systemd`.
- **No inbound ports on home.** The home machine initiates the SSH connection; the VPS never dials into home.

---

## Stack

| Concern | Tool |
|--|--|
| Web framework / API | FastAPI (async) |
| SMTP ingest | `aiosmtpd` |
| Persistence | Postgres 16 |
| Container orchestration | Docker Compose |
| Public TLS / HTTPS | Caddy (automatic Let's Encrypt) |
| Public MX | Postfix on Rocky Linux 9 |
| Tunnel | OpenSSH reverse-forward, kept alive by `autossh` |
| DKIM / SPF / DMARC | `dkimpy`, `pyspf`, resolver-side DMARC lookup |
| Rate limiting | `slowapi` + custom UTC-day throttle + bridge-side global cap |

---

## Abuse / threat model

A public portfolio link with a live email address invites a specific set of abuse patterns. Each is caught at the earliest layer that can cheaply see it:

| Threat | Mitigation | Layer |
|--|--|--|
| Search-engine indexing of the demo address | `robots.txt Disallow: /` + `<meta name="robots" content="noindex,nofollow">`. | Template / route |
| Email harvesting off rendered HTML | Address delivered only as base64 in a `data-*` attribute; revealed by user click. | Template / JS |
| Spam flood into the public MX | Postfix per-IP connection / message / recipient rate limits; `smtpd_error_sleep_time` tarpit. | VPS Postfix |
| Flood that sneaks past per-IP limits | Bridge-wide rolling cap (default **30 msg/60s across all peers**); cap-hits return SMTP `451` so legit senders retry. | email-bridge |
| Giant payloads clogging the analyzer | Postfix `message_size_limit` **plus** API `MAX_INGEST_BYTES`. | VPS + API |
| Public hitting destructive endpoints | `DEMO_MODE=true` gates reanalyze / bulk-delete / raw-debug behind `X-Admin-Key`. | API |
| `/ingest` POSTed directly via the web | Per-public-IP rate limit: **1/min and 20/day UTC**. Internal bridge traffic is exempted by the absence of `X-Forwarded-For`. | API |
| Persistent pollution between sessions | `seeder` sidecar truncates + re-seeds the DB daily at **00:00 UTC**. | seeder |
| VPS SSH brute-force | Key-only auth, no root login, `fail2ban` on `sshd`. See [ops/vps-hardening](./ops/vps-hardening/README.md). | VPS sshd |
| Tunnel key misuse | Dedicated `tunnel` user with `nologin` shell; `authorized_keys` options restrict the key to `permitlisten="18080"` only. See [ops/home-tunnel](./ops/home-tunnel/README.md). | VPS sshd |

Each layer is independent — defeating one still leaves the others — and each cost me roughly the time to write a few config lines. There is no CAPTCHA; none of the above needed one.

---

## Repository layout

```
api/                FastAPI app, analyzer, UI templates, seeder, demo-mode guards
bridge/             aiosmtpd → /ingest bridge with global rate cap
smtp/               Local SMTP helper (dev / testing)
relay/              Postfix relay sidecar (multi-address transport example)
ops/
  production-mx/    Public MX + home link (WireGuard variant, kept for reference)
  home-tunnel/      Persistent SSH reverse tunnel: systemd unit + runbook
  vps-hardening/    VPS SSH / fail2ban / Postfix hygiene runbook
scripts/            Postfix pipe → /ingest example and config snippets
for_testing/        Sample `.eml` files for local dev
```

---

## Running this yourself

### Option A — local-only, 60 seconds

```bash
git clone https://github.com/<you>/mailtest.git
cd mailtest
cp .env.example .env             # defaults are fine; nothing in .env is required for local
docker compose up -d --build
```

Open <http://localhost:8080/ui/tests>. The interactive API is at <http://localhost:8080/docs>. Pipe any `.eml` file at the analyzer with:

```bash
curl -F 'raw=@for_testing/sample.eml' http://localhost:8080/ingest
```

### Option B — full public deployment (VPS + home tunnel)

This is what powers the live demo. The setup splits into three independent phases; each has its own runbook under `ops/`. Do them in order.

> **For AI coding agents reading this:** the `ops/` runbooks are the source of truth for VPS-side work. Read `ops/production-mx/README.md`, `ops/home-tunnel/README.md`, and `ops/vps-hardening/README.md` in full before executing any of phase 2 or 3.

**Prereqs**

| Thing | Where | Notes |
|--|--|--|
| Domain you control | — | DNS A + MX records will point at the VPS. |
| VPS | anywhere with a static public IPv4 | Rocky 9 is what I run; any RHEL-family or Debian-family box works. ~1 GB RAM is plenty. |
| Home machine | Linux / WSL2 | Runs the Docker stack. Must be able to reach the VPS on TCP 22 outbound. No inbound ports required. |

**Phase 1 — Bring up the home stack [home]**

```bash
git clone https://github.com/<you>/mailtest.git
cd mailtest
cp .env.example .env
# Generate a strong admin key:
python3 -c "import secrets; print('ADMIN_API_KEY=' + secrets.token_urlsafe(32))" >> .env
# Set DEMO_MODE=true in .env once you're ready to expose it publicly.
docker compose up -d --build
curl -sf http://127.0.0.1:8080/health   # should print {"status":"ok"}
```

**Phase 2 — Set up the VPS [VPS]**

Run, in order:

1. **`ops/vps-hardening/README.md`** — installs SSH key-only auth, `fail2ban`, unattended security upgrades, opens TCP 22/25/80/443 in the firewall.
2. **`ops/production-mx/README.md`** — installs Postfix + Caddy, points Caddy at `127.0.0.1:18080` (the tunnel side), configures Postfix to relay `demo@yourdomain` over the same tunnel to `:10025`. Includes the DNS records (A, MX, SPF/DKIM/DMARC) you need to add at your registrar.
3. **`ops/home-tunnel/README.md`** — creates the `tunnel` user on the VPS with a locked-down `authorized_keys` (`permitlisten="localhost:18080"`), and installs `mailtest-tunnel.service` (autossh under systemd) on the home machine so the reverse tunnel comes back automatically after reboots and network blips.

**Phase 3 — Verify end-to-end**

```bash
# On the VPS:
sudo ss -lntp | grep 18080                       # autossh tunnel listening
curl -sI https://yourdomain/health | head -n 1   # HTTP/2 200 expected
# From any external host:
echo "hello" | mail -s "test" demo@yourdomain    # appears in the UI within seconds
```

If anything fails: each runbook has its own "Troubleshooting" section. Common ones are catalogued in `ops/production-mx/README.md` (`Pipe-ingest captures <> even for real senders`, `502 from Caddy after WSL/Docker hiccup`, etc.).

### Key env vars

See `docker-compose.yml` and `.env.example` for the complete list.

| Var | Default | What |
|--|--|--|
| `DEMO_MODE` | `false` | If `true`, destructive endpoints require `X-Admin-Key`. |
| `ADMIN_API_KEY` | _(empty)_ | The key that unlocks destructive endpoints in demo mode. |
| `DEMO_INBOUND_ADDRESS` | `demo@mailtest.justfortesting.xyz` | Shown on the UI top banner (base64-encoded in the HTML). |
| `OWNER_NAME`, `OWNER_URL` | _(mine)_ | Footer attribution. |
| `INGEST_MIN_INTERVAL_SECONDS` | `60` | Per-IP `/ingest` minimum gap. |
| `INGEST_DAILY_CAP` | `20` | Per-IP `/ingest` UTC-day cap. |
| `BRIDGE_RATE_CAP` | `30` | Global bridge-wide cap. |
| `BRIDGE_RATE_WINDOW_SECONDS` | `60` | Rolling window for the above. |
| `MAX_INGEST_BYTES` | `1048576` | Per-message size cap at `/ingest`. |

---

## Backup & restore

The home stack is the source of truth. Everything except the Postgres volume is in this repo. Worth backing up:

- **Code** — this repo (push to GitHub or any other remote).
- **`.env`** — gitignored; copy it somewhere safe (1Password / encrypted USB / etc.).
- **Postgres volume** (`db-data`) — only if you want to preserve user-submitted tests across host rebuilds. The seeder repopulates the curated demo data on every UTC midnight, so for the public demo this is optional.
- **VPS-side files** — `/etc/caddy/Caddyfile`, `/etc/postfix/main.cf` + `master.cf` + `transport`, and `/usr/local/bin/mailtest-pipe-ingest`. Captured by the runbooks.

**Snapshot the Postgres volume (home machine):**

```bash
docker compose exec -T db pg_dump -U mailtest mailtest | gzip > mailtest-db-$(date +%F).sql.gz
```

**Restore:**

```bash
gunzip -c mailtest-db-YYYY-MM-DD.sql.gz | docker compose exec -T db psql -U mailtest mailtest
```

**Full repo snapshot (for offline / hard-drive backup):**

```bash
# From the project parent directory
tar --exclude='mailtest/.env' \
    --exclude='mailtest/__pycache__' \
    --exclude='mailtest/**/__pycache__' \
    --exclude='mailtest/.git' \
    -czf mailtest-$(date +%F).tar.gz mailtest/
```

---

## Future work

- **Multi-tenant auth.** Per-user inbox address (random local-part), owner-issued master-key signup flow so only approved people can create accounts, private per-user dashboards. The demo was deliberately simplified to single-inbox so the threat model stayed small enough to reason about on a single page; the auth path is the natural next milestone.
- **Webhook delivery.** POST the analysis JSON to a user-supplied URL whenever a new test lands.
- **Trend dashboards.** Per-sending-domain deliverability over time — useful for anyone tuning a transactional email pipeline.
- **ESP integrations.** Hook directly into SendGrid / Mailgun / SES event streams so the same analyzer can score production mail, not just synthetic tests.
- **Distributed rate limiting.** Replace the in-process throttle state with Redis when there's more than one API replica.

---

## License

Personal-portfolio repo. Ask before lifting significant chunks into production code.

---

Built by [Justin Willmore](https://www.linkedin.com/in/justin-willmore-7bb87950/). Questions welcome.
