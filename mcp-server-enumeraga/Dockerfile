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

# Unprivileged runtime user. UID 1000 matches the compose default for
# ENUMERAGA_HOST_UID, so directories this process creates on the identity-mounted
# results tree are already owned by the typical host user and do not need chown.
RUN groupadd --gid 1000 enumeraga \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/enumeraga \
        --shell /usr/sbin/nologin enumeraga \
    && mkdir -p /app/enumeraga_output /run/mcp-enumeraga \
    && chown -R enumeraga:enumeraga /app/enumeraga_output /run/mcp-enumeraga

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# There is deliberately no USER here. The entrypoint starts as root so it can read
# the bind-mounted Docker socket's group -- a host fact that differs per distro and
# that the image cannot know -- and join it. It then execs the server through setpriv
# as uid 1000, so the server process is unprivileged exactly as before. Requiring the
# operator to discover that GID and pass DOCKER_GID instead left the server unable to
# reach Docker on any host whose socket group was not the guessed default.
#
# One consequence: `docker exec` into this container lands as root, because it does
# not pass through the entrypoint. Use `docker compose exec -u enumeraga` to inspect
# it as the server sees things. This is not a new privilege -- reaching the container
# at all requires the host docker socket, which is root-equivalent already -- but the
# server process itself is uid 1000, which /proc/1/status will confirm.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Expose SSE port
EXPOSE 9000

# Run in SSE mode by default
ENV MCP_MODE=sse
ENV PORT=9000

CMD ["mcp-server-enumeraga"]
