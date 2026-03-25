# Enumeraga Cloud Scanner
# Multi-stage build for smaller final image
#
# BUILD INSTRUCTIONS:
# Must be built from the repository root directory:
#   docker build -f internal/cloud/Dockerfile -t gagarter/enumeraga_cloud .
#
FROM golang:1.23-bookworm AS builder
LABEL authors="0x5ubt13"

WORKDIR /build

# Cache dependency downloads separately from source changes
COPY go.mod go.sum ./
RUN go mod download

# GITHUB_TOKEN is optional but strongly recommended in CI to avoid API rate limits
# Pass via: --build-arg GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}
ARG GITHUB_TOKEN=""

# Copy source and build - -s -w strips debug symbols (30-50% smaller binary)
COPY . .
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
RUN go build -ldflags="-s -w \
    -X github.com/0x5ubt13/enumeraga/internal/utils.Version=${VERSION} \
    -X github.com/0x5ubt13/enumeraga/internal/utils.GitCommit=${GIT_COMMIT} \
    -X github.com/0x5ubt13/enumeraga/internal/utils.BuildDate=${BUILD_DATE}" \
    -o enumeraga main.go

# Final image - debian:bookworm-slim is ~30MB compressed vs ubuntu:latest ~77MB
FROM debian:bookworm-slim
LABEL authors="0x5ubt13"
LABEL description="Enumeraga Cloud Scanner - Multi-cloud security enumeration"

# Install necessary dependencies
# wget removed - curl handles all downloads including the PowerShell deb
# gnupg2 removed - it's a meta-package; gpg (below) is the actual binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    gpg \
    curl \
    ca-certificates \
    apt-transport-https \
    python3 \
    python3-pip \
    pipx \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Google Cloud CLI
RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update && apt-get install -y --no-install-recommends google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws

# Install cloudfox from pre-built binary
# GITHUB_TOKEN (build arg) prevents API rate limit failures on shared CI runners
RUN CLOUDFOX_VERSION=$(curl -s ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
        https://api.github.com/repos/BishopFox/cloudfox/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/') \
    && curl -sL "https://github.com/BishopFox/cloudfox/releases/download/${CLOUDFOX_VERSION}/cloudfox-linux-amd64" -o /usr/local/bin/cloudfox \
    && chmod +x /usr/local/bin/cloudfox

# Install PowerShell Core (required for monkey365)
# Using curl + debian/12 package - no wget or lsb_release needed
RUN curl -sL "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb" -o packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update && apt-get install -y --no-install-recommends powershell \
    && rm -rf /var/lib/apt/lists/*

# Install monkey365 PowerShell module from the Gallery
# https://github.com/silverhack/monkey365
RUN pwsh -NonInteractive -Command "Install-Module -Name monkey365 -Scope AllUsers -Force -AllowClobber"

# Install all Python-based cloud security tools in a single layer
RUN pipx install "prowler>=5.0.0" \
    && pipx install scoutsuite \
    && pipx install gcp-scanner \
    && pipx install oci-cli || true

# Install gcp-iam-brute (GCP IAM permission enumeration via testIamPermissions API)
# https://github.com/hac01/gcp-iam-brute
RUN git clone --depth=1 https://github.com/hac01/gcp-iam-brute /usr/share/gcp-iam-brute \
    && pip3 install -r /usr/share/gcp-iam-brute/requirements.txt --break-system-packages \
    && rm -rf /usr/share/gcp-iam-brute/.git

# Download iam-dataset GCP roles via sparse checkout (gcp/roles/ subtree only, no full history)
# https://github.com/iann0036/iam-dataset
RUN git clone --depth=1 --filter=blob:none --sparse https://github.com/iann0036/iam-dataset /tmp/iam-dataset \
    && cd /tmp/iam-dataset && git sparse-checkout set gcp/roles/ \
    && cp -r /tmp/iam-dataset/gcp/roles/. /usr/share/gcp-iam-brute/roles/ \
    && rm -rf /tmp/iam-dataset

# Wrapper script: gcp-iam-brute hard-codes roles_directory = "roles" as a relative path,
# so invoke the tool from its install directory.
RUN printf '#!/bin/sh\ncd /usr/share/gcp-iam-brute && exec python3 main.py "$@"\n' \
    > /usr/local/bin/gcp-iam-brute && chmod +x /usr/local/bin/gcp-iam-brute

WORKDIR /app

# Copy built binary and entrypoint - --chmod avoids a separate RUN chmod layer
COPY --chmod=755 --from=builder /build/enumeraga /app/enumeraga
COPY --chmod=755 internal/cloud/entrypoint.sh /app/entrypoint.sh

# Volume for output persistence
ENV ENUMERAGA_OUTPUT="/tmp/enumeraga_output"
VOLUME ["/tmp/enumeraga_output"]

# Volume mounts for cloud credentials
# AWS: -v ~/.aws:/root/.aws
# Azure: -v ~/.azure:/root/.azure
# GCP: -v ~/.config/gcloud:/root/.config/gcloud

# Set PATH for pipx-installed tools and pip --user installs
ENV PATH="/root/.local/bin:${PATH}"

# ENTRYPOINT handles the 'cloud' subcommand, user provides provider and flags
# Usage: docker run gagarter/enumeraga_cloud aws
#        docker run gagarter/enumeraga_cloud azure -o /tmp/enumeraga_output
ENTRYPOINT ["/app/entrypoint.sh"]

# Default shows help if no provider specified
CMD ["--help"]
