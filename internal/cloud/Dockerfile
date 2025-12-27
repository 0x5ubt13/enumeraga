# Enumeraga Cloud Scanner
# Multi-stage build for smaller final image
#
# BUILD INSTRUCTIONS:
# Must be built from the repository root directory:
#   docker build -f internal/cloud/Dockerfile -t gagarter/enumeraga_cloud .
#
FROM debian:stable-slim AS builder
LABEL authors="0x5ubt13"

# Install Go for building
RUN apt-get update && apt-get install -y \
    golang \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source code (build context must be repo root)
COPY . .

# Accept build arguments for version information
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the binary with version info
RUN go build -ldflags="-X github.com/0x5ubt13/enumeraga/internal/utils.Version=${VERSION} \
    -X github.com/0x5ubt13/enumeraga/internal/utils.GitCommit=${GIT_COMMIT} \
    -X github.com/0x5ubt13/enumeraga/internal/utils.BuildDate=${BUILD_DATE}" \
    -o enumeraga main.go

# Final image
FROM ubuntu:latest
LABEL authors="0x5ubt13"
LABEL description="Enumeraga Cloud Scanner - Multi-cloud security enumeration"

# Install necessary dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    gnupg2 \
    curl \
    wget \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    gpg \
    apt-utils \
    sudo \
    procps \
    software-properties-common \
    python3 \
    python3-pip \
    pipx \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Google Cloud CLI
RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update && apt-get install -y google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# Install Azure CLI
RUN sudo mkdir -p /etc/apt/keyrings \
    && curl -sLS https://packages.microsoft.com/keys/microsoft.asc | \
        gpg --dearmor | sudo tee /etc/apt/keyrings/microsoft.gpg > /dev/null \
    && sudo chmod go+r /etc/apt/keyrings/microsoft.gpg

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws

# # Create non-privileged user for homebrew compatibility
# RUN echo 'subtle ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
#     adduser \
#         --disabled-password \
#         --gecos "" \
#         --home "/home/subtle" \
#         --shell "/bin/bash" \
#         --uid 10001 \
#         subtle

# # Switch to non-root user for homebrew installation
# USER subtle
# # ENV PATH=/home/subtle/.local/bin:/home/subtle/.linuxbrew/bin:/home/subtle/.linuxbrew/sbin:$PATH

# # Install Homebrew and cloud tools
# RUN git clone https://github.com/Homebrew/brew ~/.linuxbrew/Homebrew && \
#     mkdir -p ~/.linuxbrew/bin && \
#     ln -s ../Homebrew/bin/brew ~/.linuxbrew/bin && \
#     eval $(~/.linuxbrew/bin/brew shellenv) && \
#     brew install cloudfox awscli azure-cli

# Install cloudfox from pre-built binary to avoid needing Go in final image
RUN CLOUDFOX_VERSION=$(curl -s https://api.github.com/repos/BishopFox/cloudfox/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/') \
    && curl -sL "https://github.com/BishopFox/cloudfox/releases/download/${CLOUDFOX_VERSION}/cloudfox-linux-amd64" -o /usr/local/bin/cloudfox \
    && chmod +x /usr/local/bin/cloudfox

# Install OCI CLI via pip (more reliable than homebrew)
RUN pip3 install --user oci-cli || true

# Install Python-based cloud security tools via pipx
RUN pipx install prowler && pipx install scoutsuite

# Switch back to root for final setup
# USER root
WORKDIR /app

# # Copy pipx installations to root for execution
# RUN cp -r /home/subtle/.local /root/

# Copy the built binary from builder stage
# Note: When building, use: docker build -f internal/cloud/Dockerfile .
COPY --from=builder /build/enumeraga /app/enumeraga

# Copy entrypoint script
COPY internal/cloud/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/enumeraga

# Create output directory and set as volume
RUN mkdir -p /tmp/enumeraga_output
ENV ENUMERAGA_OUTPUT="/tmp/enumeraga_output"
VOLUME ["/tmp/enumeraga_output"]

# Volume mounts for cloud credentials
# AWS: -v ~/.aws:/root/.aws
# Azure: -v ~/.azure:/root/.azure
# GCP: -v ~/.config/gcloud:/root/.config/gcloud

# Set PATH for all tools
ENV PATH="/root/.local/bin:/home/subtle/.linuxbrew/bin:${PATH}"

# ENTRYPOINT handles the 'cloud' subcommand, user provides provider and flags
# Usage: docker run gagarter/enumeraga_cloud aws
#        docker run gagarter/enumeraga_cloud azure -o /tmp/enumeraga_output
ENTRYPOINT ["/app/entrypoint.sh"]

# Default shows help if no provider specified
CMD ["--help"]
