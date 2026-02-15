# Claude Agent - Claude Code CLI on Kali Linux
FROM agent-base:latest

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# Create non-root user for Claude (required for --dangerously-skip-permissions)
RUN useradd -m -s /bin/bash agent && \
    mkdir -p /home/agent/.claude && \
    chown -R agent:agent /home/agent

# Copy configuration
COPY claude/config/ /home/agent/.claude/
RUN chown -R agent:agent /home/agent/.claude

# Copy entrypoint script (--chmod ensures executable even with cached layers)
COPY --chmod=755 scripts/entrypoint.sh /entrypoint.sh

# Create workspace and set permissions
RUN mkdir -p /workspace && chown agent:agent /workspace
RUN mkdir -p /results /logs && chown agent:agent /results /logs

# Set working directory
WORKDIR /workspace

# Switch to non-root user
USER agent

ENTRYPOINT ["/entrypoint.sh"]
