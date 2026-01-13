FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# We need Docker CLI to communicate with the host Docker daemon
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY mcp_server_enumeraga/ ./mcp_server_enumeraga/

# Install the package
RUN pip install --no-cache-dir .

# Create output directory
RUN mkdir -p /app/enumeraga_output && chmod 777 /app/enumeraga_output

# Expose SSE port
EXPOSE 9000

# Run in SSE mode by default
ENV MCP_MODE=sse
ENV PORT=9000

CMD ["mcp-server-enumeraga"]
