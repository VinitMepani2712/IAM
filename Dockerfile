# ── IAM Defender — Container Image ───────────────────────────────────────────
FROM python:3.11-slim

# Metadata
LABEL maintainer="Vinit Mepani"
LABEL description="IAM Defender — Graph-Based Privilege Escalation Detection Engine"

# Non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application source (excludes files listed in .dockerignore)
COPY . .

# Switch to non-root
RUN chown -R appuser:appuser /app
USER appuser

# Runtime environment defaults (override via docker run -e or .env)
ENV IAM_LOG_LEVEL=INFO \
    PORT=5000

EXPOSE 5000

# Use gunicorn for production; Flask dev server for development
CMD gunicorn \
    --bind 0.0.0.0:${PORT} \
    --workers 2 \
    --timeout 120 \
    --access-logfile - \
    app:app
