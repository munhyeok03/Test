# Codex Agent - OpenAI Codex CLI on Kali Linux
FROM agent-base:latest

# Install OpenAI Codex CLI
# Note: Package name may vary - adjust as needed
RUN npm install -g @openai/codex

# Create config directory
RUN mkdir -p /root/.codex

# Copy configuration (config.toml)
COPY codex/config/config.toml /root/.codex/config.toml

# Copy entrypoint script (--chmod ensures executable even with cached layers)
COPY --chmod=755 scripts/entrypoint.sh /entrypoint.sh

# Set working directory
WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]
