# Roles, permissions, and user provisioning

CyberRange access is **role-based** (spec FR-12, §8). Every user account is
assigned exactly one role at provisioning time; the role determines what that
user can do. The live matrix is served at `GET /api/roles` and rendered under
**Reference → Roles & permissions** in the app.

## What each role can do — step by step

### `admin` — Platform administrator (20 permissions)
Full control plane.
1. Provision and manage user accounts (create, enable, disable).
2. Manage VM/OCI images.
3. Create, read, and **destroy** ranges; **release a quarantined range**
   (admin-only).
4. Drive any lifecycle step.
5. Execute any behavior module, including **S2** high-impact actions.
6. Publish injects and **override scores** (audited).
7. Read the audit ledger and trigger emergency pause/kill controls.

### `instructor` — Exercise delivery (11 permissions)
1. Create ranges and drive the full lifecycle (provision → start → reset → …).
2. Launch exercises.
3. Publish instructor injects during a run.
4. Execute behavior modules, including **S2** (instructor is trusted for
   high-impact lab actions).
5. Override scores with an audited justification.
6. View scoring detail and reports.
7. **Cannot** manage users, manage images, or release a quarantined range —
   those are admin-only.

### `red` — Attacker (8 permissions)
1. Participate in an assigned exercise.
2. Execute **S0/S1** behavior modules — **S2 is blocked** for red.
3. Submit evidence of the attack path.
4. Read the catalog, modules, ranges, and reports.
5. **Cannot** create ranges, publish injects, or score.

### `blue` — Defender (8 permissions)
1. Participate in an assigned exercise.
2. Submit evidence (alerts triaged, containment taken).
3. Read the catalog, ranges, **scoring detail**, and reports.
4. **Cannot** execute attacker modules, create ranges, inject, or override
   scores.

### `purple` — Replay & tuning (8 permissions)
1. Participate in the shared exercise.
2. Execute modules for **deterministic replay** against updated controls.
3. View scoring detail and reports.
4. Coordinates detection improvement measured as baseline → replay (never
   win/lose).

### `solo` — Guided single learner (8 permissions)
1. Runs both attacker and defender phases in one timeline.
2. Participate, execute modules, and submit evidence.
3. Read reports.

### `security_leader` — Read-only oversight (5 permissions)
1. View the catalog, ranges, exercises, scoring, and reports to assess
   readiness.
2. **Cannot change any state** — purely observational.

## Provisioning users (admin panel)

Only `admin` (permission `admin:manage_users`) can provision users. The
**Admin** tab appears in the top navigation for admins only.

1. Sign in. On first run the platform seeds a single admin account —
   `admin` / `admin` (override with the `CR_ADMIN_PASSWORD` env var).
   **Change it immediately.**
2. Go to **Admin → Provision a user**.
3. Enter a username, optional display name, pick a role, and set a password
   (minimum 4 characters).
4. Click **Create user**. The account appears in *Provisioned users*.
5. Share the credentials with the participant; they sign in and receive
   exactly the permissions of their role.
6. Disable an account at any time with **Disable** — this also revokes any
   live session for that user.

### Provisioning via API

```bash
BASE=http://127.0.0.1:8080/api
# 1. Admin logs in, gets a session token
TOKEN=$(curl -s -d '{"username":"admin","password":"admin"}' $BASE/login | jq -r .token)
AUTH="-H Authorization:Bearer\ $TOKEN"

# 2. Provision a blue analyst
curl -s $AUTH -H Content-Type:application/json \
  -d '{"username":"blue-1","password":"changeme","role":"blue","display_name":"Blue Analyst"}' \
  $BASE/users

# 3. That analyst logs in and works within the blue role
BTOKEN=$(curl -s -d '{"username":"blue-1","password":"changeme"}' $BASE/login | jq -r .token)
curl -s -H "Authorization: Bearer $BTOKEN" $BASE/me
```

## How authentication works (MVP)

- Passwords are stored as **PBKDF2-HMAC-SHA256** with a per-user random salt —
  never in plaintext (`auth.py`).
- Login issues an opaque random **session token** (12-hour TTL) stored in the
  `sessions` table. The browser keeps it in `localStorage` and sends it as
  `Authorization: Bearer <token>`.
- Disabling a user deletes their sessions immediately.
- This is the MVP stand-in for the **SSO/OIDC** identity in spec §6. The RBAC
  layer downstream is identical, so swapping in a real IdP later does not
  change any role logic.
- For API/testing convenience, requests without a Bearer token fall back to
  `X-CR-Role` / `X-CR-User` headers. Disable this fallback before any real
  deployment.
