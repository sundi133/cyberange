# Deploying CyberRange to Railway

CyberRange is a single Docker service (stdlib Python + SQLite + static
frontend). It deploys to [Railway](https://railway.app) from the repo's
`Dockerfile` and `railway.json` with no extra build config.

## Steps

### Option A — GitHub (recommended)

1. Push this repo to GitHub.
2. Railway → **New Project → Deploy from GitHub repo** → pick the repo.
   Railway reads `railway.json` and builds the `Dockerfile`.
3. **Variables** tab → add:
   - `CR_ADMIN_PASSWORD` = a strong password (this is the seeded `admin`
     login). **Required** for a public deploy — otherwise the default is
     `admin`/`admin`.
   - Do **not** set `CR_DEV_AUTH` (leaving it unset keeps the API token-only).
4. **Settings → Networking → Generate Domain** to get a public HTTPS URL.
   Railway terminates TLS and forwards to the app over `$PORT` (injected
   automatically; the app binds it).
5. **Add a Volume** (Settings → Volumes) mounted at `/app/backend/data` so the
   SQLite database and provisioned users survive redeploys. Without a volume
   the filesystem is ephemeral and resets on each deploy.
6. Open the domain, sign in as `admin` / `CR_ADMIN_PASSWORD`, then use the
   **Admin** tab to provision red/blue/instructor users.

### Option B — Railway CLI

```bash
npm i -g @railway/cli
railway login
railway init                       # create/link a project
railway variables set CR_ADMIN_PASSWORD='<strong-password>'
railway up                         # build & deploy the Dockerfile
railway domain                     # generate a public URL
```

## Environment variables

| Variable | Purpose | Notes |
|---|---|---|
| `PORT` | Bind port | Injected by Railway; the app reads it. |
| `CR_ADMIN_PASSWORD` | Seeded admin password | **Set this.** Applied only on first run against an empty DB. |
| `DATABASE_URL` | Postgres/Supabase DSN | Set to your Supabase URI (with `?sslmode=require`) to use Postgres; unset = SQLite. |
| `CR_DEV_AUTH` | Enable `X-CR-Role`/`X-CR-User` header identity | Leave **unset** in production; it bypasses login. |
| `HOST` | Bind host | Defaults to `0.0.0.0` via the Dockerfile CMD. |

## Using Supabase (recommended for a hosted deploy)

A single-instance app on Railway with a Volume works for a pilot, but a managed
Postgres survives redeploys and scales better. To use Supabase:

1. Create a Supabase project → **Settings → Database → Connection string → URI**.
2. Set `DATABASE_URL` to that URI with TLS, e.g.
   `postgresql://postgres:<pw>@db.<ref>.supabase.co:5432/postgres?sslmode=require`.
   (For serverless/pooled use, the Supabase **Session pooler** URI also works.)
3. Deploy. The app installs `psycopg` (in the image) and creates its tables on
   first boot; no Volume is needed. Optionally pre-apply
   [supabase/schema.sql](../supabase/schema.sql) in the Supabase SQL editor.

The server connects with the Postgres credentials and enforces access in its own
RBAC layer, so Supabase Row-Level Security is optional.

## What works, and what doesn't, on Railway

**Works:** the full control plane — login/RBAC, user provisioning, range
lifecycle, scenario/module catalog, exercises, evidence timeline, scoring,
reporting, audit, and the dashboard. Module execution runs in **simulated**
mode and the detection engine fires **technique-basis** rules.

**Does not work:** real container execution. The `DockerAdapter` shells out to
a Docker daemon; a Railway app container has no Docker daemon, so
`docker_available()` returns false and modules degrade to simulation
automatically. Consequently **log-basis** detections (rules that match real
container stdout) won't fire on Railway. To exercise real execution + log-basis
detection, run locally on a machine with Docker (`make serve`), or wait for the
Phase-2 VM host adapter.

## Scaling & persistence notes

- **Single instance only.** State (SQLite, sessions) is node-local; do not set
  replicas > 1. Railway runs one instance by default.
- **Back the DB with a Volume** at `/app/backend/data` for durability.
- The server is a threaded stdlib HTTP server — fine for demos and training
  cohorts, not tuned for high concurrency. A production deployment would front
  it with a real WSGI/ASGI server and Postgres (Phase 2).

## Security checklist before exposing a public URL

- [ ] `CR_ADMIN_PASSWORD` set to a strong value.
- [ ] `CR_DEV_AUTH` unset (verify a no-token `GET /api/users` returns 401).
- [ ] Change the admin password again from the Admin panel after first login,
      or provision a new admin and disable the seeded one.
- [ ] A Volume is attached if you need data to persist.
