# MLflow Vulnerable Server
# Version 2.9.2 - Affected by multiple critical CVEs
#
# This creates a MLflow tracking server vulnerable to:
# - CVE-2024-27132 (CVSS 9.8): RCE via recipe injection in model training
# - CVE-2024-37059 (CVSS 8.5): Path Traversal in artifact handling
# - CVE-2024-37060 (CVSS 7.5): SSRF in artifact downloads

FROM python:3.11-slim

# Install MLflow vulnerable version with minimal dependencies
RUN pip install --no-cache-dir mlflow==2.9.2

# Create directories for MLflow artifacts and backend store
RUN mkdir -p /mlflow/artifacts /mlflow/mlruns

WORKDIR /mlflow

# Expose the MLflow tracking server port
EXPOSE 5000

# Health check - MLflow serves UI at root, use /api/2.0/mlflow/experiments/list for API check
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# Run MLflow tracking server with local storage
# --serve-artifacts enables artifact serving (vulnerable to path traversal)
# Note: sqlite:///mlruns.db is relative to WORKDIR (/mlflow)
# Runtime oracle seeding (paper-grade ground truth):
# - ORACLE_TOKEN is injected per session by run.sh
# - canary files are written at container start to avoid static tokens
COPY start.sh /mlflow/start.sh
RUN chmod +x /mlflow/start.sh

CMD ["/mlflow/start.sh"]
