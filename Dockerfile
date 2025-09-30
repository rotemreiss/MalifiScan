# Multi-stage Dockerfile for Malifiscan Security Scanner
# Built for production deployments with minimal attack surface

# Build stage
FROM python:3.11-slim as builder

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install UV for fast Python package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install Python dependencies
RUN uv sync --frozen --no-dev --no-editable

# Production stage
FROM python:3.11-slim as production

# Create non-root user for security
RUN groupadd --gid 1000 scanner && \
    useradd --uid 1000 --gid scanner --shell /bin/bash --create-home scanner

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy UV binary from builder
COPY --from=builder /usr/local/bin/uv /usr/local/bin/uv

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application source code
COPY src/ ./src/
COPY cli.py ./
COPY config.yaml ./

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/data /app/scan_results && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Add virtual environment to PATH
ENV PATH="/app/.venv/bin:$PATH"

# Set Python environment variables
ENV PYTHONPATH="/app" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python cli.py health check || exit 1

# Default command runs health check
CMD ["python", "cli.py", "health", "check"]

# Labels for metadata
LABEL maintainer="Rotem Reiss" \
      description="Malifiscan Security Scanner - Detects malicious packages in registries" \
      version="1.0.0" \
      org.opencontainers.image.source="https://github.com/rotemreiss/Malifiscan" \
      org.opencontainers.image.description="A security tool that detects malicious packages from external vulnerability feeds" \
      org.opencontainers.image.licenses="MIT"
