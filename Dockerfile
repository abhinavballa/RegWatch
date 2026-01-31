# Multi-stage build for RegWatch
FROM python:3.11-slim as builder

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY src/ ./src/
COPY web/ ./web/
COPY prompts/ ./prompts/
COPY logs/ ./logs/
COPY docs/ ./docs/

# Create directories for uploads and temp files
RUN mkdir -p uploads/ temp/

# Ensure PATH includes local Python packages
ENV PATH=/root/.local/bin:$PATH

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Run Flask application
CMD ["python", "web/app.py"]
