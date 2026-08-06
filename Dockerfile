# Railway.app Dockerfile — AEGISX Backend
# Optimized for Railway's free tier (512MB RAM)

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --upgrade pip setuptools wheel && pip install -r requirements.txt

COPY backend/ .

EXPOSE 8000

# Start: wait for DB to be ready, then run with single worker for memory efficiency
CMD ["sh", "-c", "\
  echo '=== AEGISX v1.0.0 ===' && \
  echo 'PORT: '${PORT:-8000} && \
  echo 'Starting uvicorn...' && \
  exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --log-level info --timeout-keep-alive 30 \
"]
