# Stage 1: Build
FROM python:3.10-slim as builder

# Setup environment
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY pyproject.toml setup.cfg setup.py README.md ./
COPY shadowscan shadowscan/
RUN pip install --user --no-cache-dir "poetry==1.5.1"
RUN poetry config virtualenvs.create false
RUN poetry install --no-dev --no-root

# Stage 2: Production
FROM python:3.10-slim

# Setup environment
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PATH="/root/.local/bin:${PATH}"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libssl1.1 \
    libffi6 \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY --from=builder /root/.local /root/.local
COPY . .

# Set permissions
RUN chown -R 1000:1000 /app
USER 1000

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost/health || exit 1

# Expose ports if needed
EXPOSE 8000

# Run application
CMD ["shadowscan", "run", "--target", "${TARGET}", "--type", "${TARGET_TYPE}"]
