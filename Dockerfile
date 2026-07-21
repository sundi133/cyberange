FROM python:3.12-slim

WORKDIR /app
COPY backend /app/backend
COPY frontend /app/frontend

ENV PYTHONUNBUFFERED=1
WORKDIR /app/backend

EXPOSE 8080

# 0.0.0.0 so the port is reachable from outside the container.
CMD ["python", "-m", "cyberrange", "serve", "--host", "0.0.0.0", "--port", "8080"]
