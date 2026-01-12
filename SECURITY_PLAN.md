# Public Deployment Plan (Authenticated Full Features)

## Goals
- Allow full functionality (upload logs, manage decoders, replay, decode) for authenticated users.
- Prevent unauthenticated access and reduce abuse risk on a public server.
- Add resource and access controls without breaking current workflows.

## Phase 1: Authentication + Basic Guardrails
1) Add authentication for all non-public routes.
   - Recommended: Flask-Login + session cookies.
   - Optional: Basic auth for small teams.
2) Require auth for:
   - Uploads, decoder management, log downloads/deletes.
   - Replay, decode, generate, device key management.
3) Add CSRF protection for all POST routes.
   - Flask-WTF or custom CSRF token in forms.
4) Add request size limits.
   - `MAX_CONTENT_LENGTH` for uploads (logs + decoders).

## Phase 2: Replay Target Restrictions
1) Add host/port allowlist for replay targets.
   - Configuration file or env-based list.
2) Optional: restrict to RFC1918 and localhost only.
3) Log all replay target usage.

## Phase 3: Decoder Execution Hardening
1) Disable decoder uploads by default in public mode.
2) If uploads allowed:
   - Run decoder execution in an isolated sandbox (container or firejail).
   - No network access, read-only FS, CPU/memory limits, timeout.
3) Consider a curated decoder registry instead of arbitrary JS.

## Phase 4: Rate Limits + Quotas
1) Rate limit upload, replay, and decode endpoints.
   - Flask-Limiter or reverse-proxy rate limiting.
2) Per-user quotas for storage and job execution.

## Phase 5: Auditing + Monitoring
1) Add audit log for:
   - Login/logout
   - Uploads/deletes
   - Decoder uploads/deletes
   - Replay targets
2) Add basic metrics (requests, errors, latency).

## Phase 6: Production Hardening
1) Disable Flask debug.
2) Run behind HTTPS reverse proxy (nginx/caddy).
3) Store files outside web root with strict permissions.
4) Enable regular backups and log rotation.

## Deliverables by Phase
- Phase 1: Auth + CSRF + size limits
- Phase 2: Replay host restrictions
- Phase 3: Decoder sandboxing
- Phase 4: Rate limits + quotas
- Phase 5: Audit logging
- Phase 6: Production runtime hardening

## Completed So Far
- Authentication added for all app routes using Flask-Login sessions.
- Default `admin` user created with `admin` password and forced change on first login.
- Users management added (create users, change passwords, remove users).
- Admin cannot be removed; only admin can reset the admin password.
- Menu and pages now hide authenticated actions when logged out.
- CSRF protection added for all POST forms.
- Request size limits enforced via `MAX_CONTENT_LENGTH`.
- Uploaded decoders gated by public-mode flags; uploads/execution can be disabled by default.
- Rate limits and per-user storage quotas enforced for scan/replay/decode/generate and uploads.
- Audit logging added for auth events and file/decoder/replay/decode actions (with rotation).
- Production defaults: debug off by default, proxy-aware option, secure cookie flags, configurable data dir.

## Next Up
1) Replay target allowlist and optional RFC1918-only restriction.
