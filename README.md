# PassM — Enterprise Password Manager

Internal company password manager. Authentication, session and device-trust
foundation for a LastPass-style vault.

> **Internal use only.** Sign-in is Google only, restricted to the company's
> Google Workspace domain (`GOOGLE_ALLOWED_DOMAINS`). Anyone from that domain gets
> a Member account on first sign-in; administrators can also create accounts in
> advance. **The server encrypts and can decrypt every stored password** — see
> [What administrators can and cannot do](#what-administrators-can-and-cannot-do).

---

## What is implemented

**Authentication and accounts**

| Area | Status |
| --- | --- |
| Sign in with Google (`POST /auth/google`) — the only sign-in method | Done |
| Accounts created on first Google sign-in, or in advance by an admin | Done |
| JWT access tokens + refresh-token rotation with replay detection | Done |
| Logout, single session or everywhere | Done |
| Device registration and "remember this device" | Done |
| Session management (list, revoke, idle timeout, per-user cap) | Done |
| RBAC — admin / manager / employee, permission matrix | Done |
| Audit trail, rate limiting, Helmet, CORS, input validation, SQLi/XSS defences | Done |

**Vault**

| Area | Status |
| --- | --- |
| Encrypted storage — every item AES-256-GCM under `ENCRYPTION_KEY`, passwords released one at a time and audited | Done |
| Item types: login, secure note, card, identity, SSH key, API key | Done |
| Password groups and individual passwords, move between them, search | Done |
| Password generator (length, character classes, pronounceable) | Done |
| Chrome MV3 extension — autofill, auto-save, update detection, side panel | Done |
| **Sharing** — grant a person a group or a single password; live immediately | Done |

**Administration**

| Area | Status |
| --- | --- |
| Dashboard — statistics, activity charts, role distribution | Done |
| Security dashboard — spraying and token-replay detection, lockouts, hygiene | Done |
| Users — create, suspend, lock/unlock, force logout, delete | Done |
| Access management — who can use which group or password, with role and restrictions | Done |
| Roles and the permission matrix (read-only — the matrix is code) | Done |
| Audit log with filtering and CSV export | Done |
| Tenant-wide session and device views with kill switches | Done |
| Password health — weak, reused, old, breached; org rollup by department | Done |
| Dark mode, responsive layout, pagination, search, sort, filter throughout | Done |

**Security hardening**

| Area | Status |
| --- | --- |
| Runtime security policy — ~60 settings, admin-editable, no restart | Done |
| CSRF — signed double-submit tokens bound to the session | Done |
| IP allow list — global/user/role scopes, audit mode, address tester | Done |
| Two-step verification — confirm with Google, bound to a server nonce (step-up) | Done |
| Emergency vault lock — whole-tenant break-glass switch | Done |
| Security notifications — new device, failed logins, password change | Done |
| Security posture score with actionable findings | Done |
| Idle auto-lock with warning, clipboard auto-clear, offline encrypted cache | Done |

### Security policy is configured in the app, not the environment

Phases 1–5 put every threshold in an environment variable, which meant changing
"5 failed logins" needed an SSH session and a process restart. Policy now lives
in the database and is edited at **Admin → Security policy**; the environment
supplies defaults for a fresh install.

Two things are worth knowing:

- **`SECURITY_SETTINGS_LOCK`** pins named settings so the admin panel cannot
  change them. That is the floor a compromised administrator account cannot
  lower — pin anything you genuinely rely on.
- **Settings declare where they are enforced.** Ones marked *browser only*
  (clipboard clearing, idle sign-out) are honoured by the
  client and can be ignored by a modified one. They are safety rails, not
  guarantees, and the console says so rather than implying otherwise.

---

## Repository layout

```
/backend            Express + TypeScript API (mysql2, no ORM)
/frontend           React 19 + Vite web console (React Router, Tailwind + Shadcn UI)
/browser-extension  Chrome Manifest V3 extension (React + TypeScript, Vite)
/shared             Cross-package contracts: types, DTO shapes, roles, permissions, error codes
/scripts            Operational scripts (LAN certificate generation)
```

`@passm/shared` is the single source of truth for anything two packages must
agree on. Role names, permission matrix, error codes, route paths, header names
and cookie names all live there, so the API and its clients cannot drift.

---

## Prerequisites

- **Node.js 22.22+** (tested on 24 LTS)
- **MySQL 8.0.19+** — 8.0.19 is the floor because the device upsert uses the
  row-alias form of `ON DUPLICATE KEY UPDATE`
- **Redis** (optional) — see [Redis](#redis-optional)

---

## Quick start

```bash
# 1. Install everything (npm workspaces)
npm install

# 2. Build the shared contracts first — every other package imports it
npm run build:shared

# 3. Create the database and an application user
mysql -u root -p <<'SQL'
CREATE DATABASE passm CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'passm_app'@'%' IDENTIFIED BY 'a-strong-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON passm.* TO 'passm_app'@'%';
-- Migrations need DDL rights; keep them on a separate account.
CREATE USER 'passm_migrator'@'%' IDENTIFIED BY 'another-strong-password';
GRANT ALL PRIVILEGES ON passm.* TO 'passm_migrator'@'%';
FLUSH PRIVILEGES;
SQL

# 4. Configure the API
cd backend
cp .env.example .env
npm run generate:secrets        # paste the output into .env
#   ...then set DB_USER / DB_PASSWORD / DB_NAME,
#   GOOGLE_CLIENT_ID and GOOGLE_ALLOWED_DOMAINS (see "Google sign-in setup")

# 5. Schema and bootstrap admin (no password: sign in with this Google account)
MIGRATION_DB_USER=passm_migrator MIGRATION_DB_PASSWORD=another-strong-password npm run db:migrate
SEED_ADMIN_EMAIL=you@123cfc.com npm run db:seed

# 6. Run the API
npm run dev                     # http://localhost:4000/api/v1
```

Then the console:

```bash
cd frontend
cp .env.example .env.local      # VITE_API_URL=http://localhost:4000/api/v1
npm run dev                     # http://localhost:3000
```

And the extension:

```bash
cd browser-extension
cp .env.example .env
npm run build
# chrome://extensions -> Developer mode -> Load unpacked -> select dist/
# Copy the extension id into backend/.env as:
#   CORS_ALLOW_EXTENSION_ORIGINS=<extension-id>
```

Sign in to the console with the seeded admin's Google account.

### Google sign-in setup

In Google Cloud Console → APIs & Services → Credentials, create an **OAuth
client ID** of type **Web application** (an existing one can be reused), and add:

- **Authorized JavaScript origins** — every address the console is opened at,
  e.g. `http://localhost:3000` and `https://passm.123cfc.com`. Google does not
  accept a bare IP address here; see the LAN section below.
- **Authorized redirect URIs** — the extension's
  `https://fllkfipajdahciclfcimfcenmfallgfm.chromiumapp.org/`.

Put the client id in `backend/.env` as `GOOGLE_CLIENT_ID`. It is not a secret,
and there is no client secret to configure. The console and extension read it
from the API (`GET /auth/google/config`), so neither needs rebuilding when it
changes.

---

## Running on the office network (nip.io)

> **Google sign-in needs a hostname and internet access.** Google will not
> accept a bare IP such as `http://192.168.0.211:1225` as an origin, so the
> server is reached through [nip.io](https://nip.io): public DNS resolves
> `192.168.0.211.nip.io` to `192.168.0.211`, with no setup. Plain HTTP on the
> nip.io name is accepted. Browsers and the API both need to reach Google
> (`accounts.google.com`, `www.googleapis.com`) and nip.io's DNS; a LAN with no
> route out cannot sign anyone in.
>
> The name follows the IP. If the server's address changes: add the new
> `http://<ip>.nip.io:<port>` to the Google OAuth client's origins, and change
> the address in each extension (triple-click the small server address at the
> bottom of the popup or side panel). It is kept until changed again - no
> rebuild. Reserving the IP avoids all of this.

The API serves the console itself, under `/passmadmin/`, so everything is on
one origin and one port - no CORS to configure, and cookies work with plain
`SameSite=Lax`. The production console build calls the API at the relative
`/api/v1` and is built for `/passmadmin/` by default, so a plain git clone
builds correctly with no frontend `.env`.

### Production: the VM

| | |
| --- | --- |
| Server | `192.168.0.211`, port `1225` |
| Console (admins) | `http://192.168.0.211.nip.io:1225/passmadmin/` - the bare host redirects there |
| API (extension) | `http://192.168.0.211.nip.io:1225/api/v1` |
| Database | MySQL on the VM itself (`DB_HOST=localhost`) |

**1. Get the code and build it** (Node 24):

```bash
git clone https://github.com/aayush-9162/Pass-maneger.git passm
cd passm
npm ci
npm run build:lan          # shared + backend (dist/) + console (frontend/out/)
```

**2. Put `backend/.env` in place.** It is git-ignored - copy it to the VM by
hand (scp, or paste it into an editor). It holds the database password and
`ENCRYPTION_KEY`. **Back that key up**: every stored password is encrypted
with it, and losing it loses them all. The VM's values:

```ini
NODE_ENV=production
PORT=1225
HOST=0.0.0.0
LOG_LEVEL=info               # debug is refused in production
DB_HOST=localhost
DB_USER=passm
DB_NAME=passm
WEB_ROOT=../frontend/out
WEB_BASE_PATH=/passmadmin
CORS_ORIGINS=                # same origin - not needed
CORS_ALLOW_EXTENSION_ORIGINS=fllkfipajdahciclfcimfcenmfallgfm
HTTPS_ENABLED=false
COOKIE_SECURE=false          # a Secure cookie is never sent over http://
ALLOW_INSECURE_HTTP=true     # plain HTTP, private addresses only
SEED_ADMIN_EMAIL=aayushdubey@123cfc.com
```

**3. Create the tables and the first admin** (first time only):

```bash
cd backend
npm run db:migrate
npm run db:seed
```

**4. Run it under PM2** so it survives crashes and reboots:

```bash
npm i -g pm2
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup                # prints one more command - run it
```

One process by default; without Redis, more workers would each keep their own
rate limits and session cache.

**5. Network and Google**

- Open TCP 1225 in the VM's firewall for the private network
  (e.g. `sudo ufw allow 1225/tcp`).
- Add `http://192.168.0.211.nip.io:1225` to the Google OAuth client's
  **Authorised JavaScript origins** (an origin has no path - not `/passmadmin`).

**Updating:** `git pull && npm ci && npm run build:lan && pm2 reload passm-api`.

**The extension** is built on a development machine and its `dist/` handed
out. Its default server comes from `browser-extension/.env`:

```bash
echo VITE_API_URL=http://192.168.0.211.nip.io:1225/api/v1 > browser-extension/.env
npm run build --workspace @passm/browser-extension
```

**HTTPS instead** (optional): `./scripts/generate-lan-cert.sh 192.168.0.211`,
then `HTTPS_ENABLED=true`, `TLS_CERT_PATH=certs/server.crt`,
`TLS_KEY_PATH=certs/server.key`, `COOKIE_SECURE=true`, and install
`backend/certs/ca.crt` on every client - the script prints the command per OS.

**On HTTP:** the API runs, and the clipboard falls back to `execCommand`.
`ALLOW_INSECURE_HTTP` only accepts private addresses, and the server warns at
every boot.

What HTTP costs you: tokens and passwords cross the network in cleartext - the
server releases passwords in plaintext to the client that asks - and an attacker
able to modify traffic could alter the served JavaScript. The console shows a banner saying so.

---

## API

Base URL: `/api/v1`

The auth router is mounted twice, so both forms work identically:
`POST /api/v1/auth/google` and the flat `POST /api/v1/google`.

### Authentication

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/google/config` | — | OAuth client id and hosted domain for the sign-in button. |
| `POST` | `/google` | — | Sign in with a Google ID token (`{ "credential": "..." }`). Sets the refresh cookie; returns the access token. |
| `POST` | `/refresh` | refresh cookie | Rotate the refresh token, issue a new access token. |
| `POST` | `/logout` | access token | End this session, or all of them with `{"allDevices":true}`. |
| `GET` | `/profile` | access token | Current user, session and device. |
| `POST` | `/register` | **admin** | Create an account ahead of its first Google sign-in. |

### Self-service

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/auth/sessions` | `session:read:self` |
| `DELETE` | `/auth/sessions/:sessionId` | `session:revoke:self` |
| `GET` | `/auth/devices` | `device:read:self` |
| `PATCH` | `/auth/devices/:deviceId` | `device:manage:self` |
| `DELETE` | `/auth/devices/:deviceId` | `device:manage:self` |

### Passwords

Membership-scoped: the check is a grant on the vault in the path, made in the
service rather than by route middleware. A "group" is a vault of kind `group`;
an individual password is a vault of kind `item` wrapping one entry.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/shared/vaults` | The caller's groups and individual passwords, with their rights on each |
| `POST` | `/shared/vaults` | Create a group; the creator becomes owner |
| `PATCH` / `DELETE` | `/shared/vaults/:vaultId` | Rename or delete (vault `admin`, or `shared_vault:manage`) |
| `GET` | `/shared/vaults/:vaultId/access` | Grants on a vault |
| `POST` / `PATCH` / `DELETE` | `/shared/vaults/:vaultId/grants[/:grantId]` | Give, change, revoke access; live at once |
| `GET` | `/shared/vaults/:vaultId/items` | Names, usernames, sites - never passwords |
| `GET` | `/shared/vaults/:vaultId/items/:itemId/secret?purpose=` | One password; audited as viewed / copied / filled |
| `POST` | `/shared/vaults/:vaultId/items` | Add a password to a group |
| `POST` | `/shared/items` | Add an individual password (the server wraps it) |
| `PATCH` / `DELETE` | `/shared/vaults/:vaultId/items/:itemId` | Edit (revision-checked) or delete |
| `POST` | `/shared/vaults/:vaultId/items/:itemId/move` | Move to a group, or out to stand alone |

### Administration

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/admin/users` | `user:read` |
| `GET` | `/admin/users/:id` | `user:read` |
| `PATCH` | `/admin/users/:id` | `user:update` |
| `PUT` | `/admin/users/:id/role` | `role:assign` |
| `PUT` | `/admin/users/:id/status` | `user:disable` |
| `GET` | `/admin/users/:id/sessions` | self, or `session:read:any` |
| `DELETE` | `/admin/users/:id/sessions` | `session:revoke:any` |
| `GET` | `/admin/users/:id/devices` | self, or `device:read:any` |
| `DELETE` | `/admin/users/:userId/devices/:deviceId` | `device:revoke:any` |
| `GET` | `/admin/roles` | `role:read` |
| `GET` | `/admin/audit-logs` | `audit:read` |

### Health

`GET /health` — liveness, touches no dependency.
`GET /health/ready` — readiness; 503 when MySQL is unreachable.

### Response envelope

Every response, success or failure, has the same shape:

```jsonc
// success
{ "success": true, "data": { }, "requestId": "…", "timestamp": "2025-03-12T14:05:00.000Z" }

// failure
{
  "success": false,
  "error": { "code": "VALIDATION_ERROR", "message": "One or more fields are invalid.",
             "details": [{ "field": "body.credential", "message": "…" }] },
  "requestId": "…", "timestamp": "…"
}
```

Clients branch on `error.code` (see `ERROR_CODES` in `@passm/shared`), never on
the message text.

---

## Roles and permissions

Roles live in the `roles` table for referential integrity; the permission matrix
lives in `shared/src/constants/permissions.ts` so a capability moves between
roles in exactly one place.

| | Employee | Manager | Admin |
| --- | :---: | :---: | :---: |
| Own sessions and devices | ✔ | ✔ | ✔ |
| View users, their sessions and devices | | ✔ | ✔ |
| Read audit log | | ✔ | ✔ |
| Create users, assign roles | | | ✔ |
| Suspend, lock and delete users | | | ✔ |
| Revoke anyone's sessions and devices | | | ✔ |

Routes declare a **permission**, not a role, so authorization is decided by the
matrix rather than by scattered role checks.

---

## Security design

The reasoning behind each decision is documented at its implementation site.
Summary:

**Credentials.** There are none of PassM's own. Sign-in is a Google ID token,
verified against Google's published keys: RS256 only, audience pinned to this
deployment's client id, expiry checked, email verified, and both the `hd` claim
and the email domain on `GOOGLE_ALLOWED_DOMAINS`. Accounts are linked by
Google's stable account id, not the address, so a recycled address cannot
inherit an old account.

**Tokens.** Short-lived access JWT (15 min) in memory; refresh token (7 days) in
an httpOnly cookie, stored server-side only as an HMAC. Three separate signing
keys, algorithm pinned to HS256 on verify, issuer/audience/type all checked.

**Refresh rotation with reuse detection.** Every refresh rotates the token and
demotes the old hash. Presenting a superseded token means it leaked, so all of
that user's sessions are revoked. The rotation is a single conditional `UPDATE`,
so two racing requests cannot both succeed.

**Immediate revocation.** Access tokens are stateless, but every request checks
the session row, so "sign out everywhere", admin revocation and suspension take
effect at once rather than at token expiry.

**Device trust.** "Remember this device" is granted only by a successful sign-in
and is proven by *both* a signed cookie and a matching HMAC on the device
row — so revocation is instant and server-side. Fingerprints are a change
detector only, never an authentication factor.

**Brute force, MFA, recovery.** Google's. With no password there is nothing to
guess here; enforce 2-Step Verification and session length in the Google
Workspace admin console. `/google` keeps an IP rate limiter, and an
administrative lock or suspension still refuses a valid Google sign-in.

**SQL injection.** `multipleStatements` is disabled at the driver level, and every
statement is a prepared statement with bound values. The two places that assemble
SQL text (`ORDER BY`, and the `SET` clause of a profile update) resolve through
explicit allow-lists.

**XSS.** Strict CSP on both the API (`default-src 'none'`) and the console;
allow-listed character sets on stored free text; React escaping on output; the
access token is never placed in web storage.

**Everything else.** Helmet, CORS allow-list (no wildcard with credentials),
JSON-only bodies with a size cap, HTTPS enforcement behind a trusted proxy, HSTS,
audit trail with secret-scrubbed metadata, and logs that redact known sensitive
keys at any depth.

---

## What administrators can and cannot do

The admin panel is built around one boundary, and it is worth stating plainly
because it is unusual and it constrains what the product can offer.

**The server encrypts every password, and can decrypt every one.** This is the
price of Google-only sign-in: with no PassM password there is nothing for a
browser to derive a key from, so items are encrypted by the API under
`ENCRYPTION_KEY` (AES-256-GCM, the item id bound in as additional data) and
decrypted there for whoever a grant allows. Consequences:

**PassM is not end-to-end encrypted.** Credentials are encrypted at rest, and a
database dump *alone* decrypts nothing — but the database together with
`ENCRYPTION_KEY` decrypts everything. Anyone who can read the API host's
environment (server administrators, a backup that includes `.env`, an attacker
with a shell there) is in that position. Keep `ENCRYPTION_KEY` in a secret
manager and out of backups, and treat the API host as holding every password.

**Passwords leave the server one at a time.** Listings carry names, usernames
and sites only. A password is released by `GET .../items/:itemId/secret`, which
refuses a member whose grant hides passwords (or a vault that requires an
approved reveal they lack) and records every release in the audit trail as
viewed, copied or filled. A modified client can mislabel its purpose but cannot
skip the record.

**Access is a grant, and nothing else.** Giving someone a group or a single
password is one row, live at once; revoking it ends access on their next
request. Revoking cannot un-know a password they already read - rotate it.

**An administrator can read any password - by granting themselves access.**
`shared_vault:manage` governs who has access without by itself returning any
password, but an administrator may add their own grant, and that grant is in
the audit trail. This is an application boundary, not a cryptographic one.

**Group names are plaintext.** An administrator has to be able to see that
"Production Infrastructure" exists and who can open it without opening it, so
names are stored in the clear; item contents are not.

**Password health is computed by clients.** The server cannot score a password it
cannot see, so each client assesses its own vault after unlocking and uploads
counts, scores and flags — never a password or a hash of one. A user who has
never run it is reported as *unassessed*, not healthy, so the org-wide number
cannot be improved by people not looking.

---

## Redis (optional)

`REDIS_ENABLED=false` falls back to an in-process cache. That is correct but
**per worker**: in a PM2 cluster each worker keeps its own copy, so rate-limit
counters are effectively multiplied by the worker count and a session revoked on
one worker can survive up to 15 seconds on another. Enable Redis for any
multi-instance deployment. The application logs which backend it chose at boot.

---

## Production deployment

```bash
npm run build                # shared -> backend -> frontend -> extension
cd backend && npm run start:pm2
```

Checklist:

- `NODE_ENV=production` — the config layer then *refuses to start* on placeholder
  secrets, an empty `DB_PASSWORD`, a wildcard or plaintext CORS origin, or
  `LOG_LEVEL=debug`.
- Set `TRUST_PROXY_HOPS` to the real number of proxies. Too high lets clients
  forge `X-Forwarded-For` and evade rate limiting; too low makes every request
  look like it came from the load balancer.
- Terminate TLS at the proxy (leave `HTTPS_ENABLED=false`) or in-process with
  `TLS_KEY_PATH` / `TLS_CERT_PATH`.
- Keep migrations on an account with DDL rights, separate from the application
  account, which has none.
- Put `ENCRYPTION_KEY` and the JWT secrets in a secret manager, not in a file.
  Rotate by moving the old value to `ENCRYPTION_KEY_PREVIOUS` (decrypt-only).

---

## Commands

| Command | Effect |
| --- | --- |
| `npm run build` | Build every package in dependency order |
| `npm run build:lan` | Build for a single-origin deployment (shared, backend, static console) |
| `npm run build:web` | Production build of the console into `frontend/out` |
| `npm run typecheck` | Typecheck every package |
| `npm run dev:backend` | API with hot reload |
| `npm run dev:frontend` | Console with hot reload |
| `npm run dev:extension` | Extension rebuild on change |
| `npm run db:migrate` | Apply pending migrations |
| `npm run db:seed` | Create the bootstrap administrator |
| `./scripts/generate-lan-cert.sh <ip>` | TLS certificate for a LAN IP address |

---

## Architecture

Requests flow strictly one way, and each layer has one job:

```
routes/       middleware chain + permission declaration
controllers/  HTTP in, HTTP out — no business rules
services/     business rules and security policy
repositories/ the only code that writes SQL
models/       row shapes and the mappers to domain records
dto/          zod schemas; the only way untrusted input enters
```

Two consequences worth stating: a service can be tested without HTTP, and
`toPublicUser()` is the single point where a user record becomes a wire
response — which is what guarantees no endpoint can leak a password hash.
