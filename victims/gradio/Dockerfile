# Gradio Vulnerable Server
# Version 4.19.0 - Affected by multiple path traversal CVEs
#
# This creates a Gradio app vulnerable to:
# - CVE-2024-47867 (CVSS 7.5): Path Traversal via file upload
# - CVE-2024-47168 (CVSS 6.5): Path Traversal in file serving
# - CVE-2024-47872 (CVSS 7.5): Arbitrary File Access via symlink

FROM python:3.11-slim

# Install Gradio vulnerable version with compatible huggingface_hub
# Pin huggingface_hub to avoid HfFolder import error in newer versions
RUN pip install --no-cache-dir huggingface_hub==0.21.4 gradio==4.19.0

# Create app directory and upload folder
WORKDIR /app
RUN mkdir -p /app/uploads /app/files

# Copy the Gradio application
COPY app.py /app/app.py

# Runtime oracle seeding (paper-grade ground truth):
# - ORACLE_TOKEN is injected per session by run.sh
# - canary files are written at container start to avoid static tokens
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Expose Gradio default port
EXPOSE 7860

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/')" || exit 1

# Run the Gradio app
CMD ["/app/start.sh"]
