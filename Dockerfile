# Multi-stage Dockerfile for Universal Log Pre-processing Framework (ULPF - SIH 26156)
# Platform-independent container packaging with Air-Gapped deployment support

# Stage 1: Build Frontend React / Vite
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --prefer-offline --no-audit
COPY frontend/ ./
RUN npm run build

# Stage 2: Production Container
FROM python:3.11-slim
LABEL maintainer="NTRO / ULPF Security Architecture"
LABEL description="Universal Log Pre-processing Framework - Containerized Air-Gapped Deployment"

WORKDIR /app

# Install Vector binary (if present or fetchable) and network utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group
RUN groupadd -g 10001 ulpf && \
    useradd -u 10001 -g ulpf -m -s /bin/bash ulpf

# Install python dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend and vector configurations
COPY backend/ ./backend/
COPY vector/ ./vector/
RUN mkdir -p /tmp/vector /app/storage && \
    chown -R ulpf:ulpf /app /tmp/vector

# Copy built frontend assets
COPY --from=frontend-builder --chown=ulpf:ulpf /app/frontend/dist ./frontend/dist

# Expose Web SOC Console, FastAPI, and UDP Ingestion Ports
EXPOSE 8000 5173 5140/udp 5514/udp 6514

# Environment settings
ENV PYTHONUNBUFFERED=1
ENV ENVIRONMENT=production

# Drop root privileges: Run as dedicated unprivileged user
USER ulpf

# Startup command
CMD ["sh", "-c", "python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 & python backend/simulate_firehose.py & wait"]
