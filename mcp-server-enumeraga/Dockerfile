FROM python:3.11.16-slim-bookworm

WORKDIR /app

# Install system dependencies
# We need Docker CLI to communicate with the host Docker daemon
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    ca-certificates \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY mcp_server_enumeraga/ ./mcp_server_enumeraga/

# Install the package
RUN pip install --no-cache-dir .

# Non-root runtime user. UID 1000 matches the compose default for
# ENUMERAGA_HOST_UID, so directories this process creates on the identity-mounted
# results tree are already owned by the typical host user and do not need chown.
# The host docker socket is reached via a supplementary group (compose group_add
# with DOCKER_GID), not by running as root.
RUN groupadd --gid 1000 enumeraga \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/enumeraga \
        --shell /usr/sbin/nologin enumeraga \
    && mkdir -p /app/enumeraga_output /run/mcp-enumeraga \
    && chown -R enumeraga:enumeraga /app/enumeraga_output /run/mcp-enumeraga

USER enumeraga

# Expose SSE port
EXPOSE 9000

# Run in SSE mode by default
ENV MCP_MODE=sse
ENV PORT=9000

CMD ["mcp-server-enumeraga"]
