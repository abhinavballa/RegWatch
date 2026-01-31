# Multi-stage build for RegWatch
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY src/ ./src/
COPY web/ ./web/
COPY prompts/ ./prompts/
COPY test_codebases/ ./test_codebases/
COPY test_data/ ./test_data/
COPY docs/ ./docs/
COPY logs/ ./logs/
COPY demo/ ./demo/
COPY .env.example .env

# Create necessary directories
RUN mkdir -p uploads logs/regulation_changes.json

# Set environment variables
ENV FLASK_APP=web.app
ENV PYTHONUNBUFFERED=1

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')"

# Run Flask application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
