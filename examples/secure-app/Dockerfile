# Multi-stage build with pinned base image
FROM python:3.11.8-slim-bookworm AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal runtime image
FROM python:3.11.8-slim-bookworm

# Create dedicated non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

WORKDIR /app

# Copy dependencies and application artifacts
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup ./src /app

# Security hardening: drop privileges
USER 10001
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8080
CMD ["python", "app.py"]
