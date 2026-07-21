FROM python:3.12-slim

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
