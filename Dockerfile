FROM python:3.12-slim

# Install the Docker CLI (client only, not the daemon) so the app can drive a
# remote Docker daemon via DOCKER_HOST for real container execution (e.g. a
# docker:dind sidecar on Railway, or an external Docker host). Without
# DOCKER_HOST and no local daemon, the app cleanly falls back to simulation.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend /app/backend
COPY frontend /app/frontend

# Install the Postgres/Supabase driver so DATABASE_URL works in production.
# (Not needed for the default SQLite backend, but harmless.)
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

ENV PYTHONUNBUFFERED=1
WORKDIR /app/backend

# The app binds $PORT (Railway/Heroku inject it); defaults to 8080 locally.
EXPOSE 8080

# 0.0.0.0 so the port is reachable from outside the container. Token auth only
# by default — set CR_DEV_AUTH=1 to re-enable header identity (never in prod).
CMD ["python", "-m", "cyberrange", "serve", "--host", "0.0.0.0"]
