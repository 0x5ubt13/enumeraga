# Stage 1: Go builder - compiles enumeraga only
# ProjectDiscovery tools are downloaded as pre-built binaries in the final stage
# to avoid CGO/libpcap build dependency issues in CI
FROM golang:1.26-bookworm AS builder
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

# Stage 2: Final image - Kali rolling without Go toolchain
# Removing Go + module cache saves 400-600MB from the final image
FROM kalilinux/kali-rolling
LABEL authors="0x5ubt13"
LABEL description="Enumeraga Infrastructure Scanner - Automated penetration testing enumeration"

WORKDIR /opt/enumeraga

# Update and install required tools in a single layer to reduce image size
# git removed - not needed at runtime (Go module downloads happen in builder)
# unzip kept - needed to extract ProjectDiscovery pre-built binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    curl wget jq ca-certificates unzip \
    # Python (no golang - compiled binaries are copied from builder)
    python3 python3-pip pipx \
    # Network scanning tools
    nmap masscan amass gobuster ffuf dnsenum dnsrecon whois \
    # NFS and filesystem tools
    nfs-common tree \
    # Enumeration tools
    cewl enum4linux-ng dirsearch finger fping hydra \
    nbtscan nikto smbclient smbmap \
    # Security tools
    ssh-audit wafw00f whatweb testssl.sh python3-impacket \
    # Additional infra tools
    ident-user-enum nbtscan-unixwiz responder rusers \
    onesixtyone snmp braa ldap-utils \
    # Metasploit (for enumeration modules)
    metasploit-framework \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Download only the specific SecLists wordlists we need instead of full 1.9GB package
# This reduces image size from ~3GB to ~1GB
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content \
    && mkdir -p /usr/share/seclists/Passwords \
    && mkdir -p /usr/share/seclists/Usernames \
    && mkdir -p /usr/share/seclists/Discovery/SNMP \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
        -o /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top1000.txt \
        -o /usr/share/seclists/Passwords/darkweb2017-top1000.txt \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/web-extensions.txt \
        -o /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt \
        -o /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp-onesixtyone.txt \
        -o /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt

# crackmapexec is being phased out in kali-rolling (renamed to netexec/nxc upstream)
# Install both so the crackmapexec binary path still resolves
RUN apt-get update && apt-get install -y --no-install-recommends crackmapexec netexec || \
    apt-get install -y --no-install-recommends netexec || true \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install ODAT if available (may not be on all architectures)
RUN apt-get update && apt-get install -y odat || true \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rwho client from Debian repos since it's not in Kali
# rwho is used for R-Services enumeration (shows who is logged on network machines)
RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list.d/debian.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends rwho || true \
    && rm -f /etc/apt/sources.list.d/debian.list \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create symlinks for tools that have non-standard names
RUN ln -sf /usr/share/responder/tools/RunFinger.py /usr/local/bin/responder-RunFinger 2>/dev/null || true \
    && ln -sf /usr/bin/testssl.sh /usr/local/bin/testssl 2>/dev/null || true \
    && ln -sf /usr/bin/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true

# Copy compiled enumeraga binary from builder
COPY --chmod=755 --from=builder /build/enumeraga /opt/enumeraga/enumeraga

# Download ProjectDiscovery pre-built binaries - avoids CGO/libpcap build issues
# Release zip naming: tag=v{VER}, filename={tool}_{VER}_linux_amd64.zip
RUN GH_AUTH="${GITHUB_TOKEN:+-H \"Authorization: Bearer $GITHUB_TOKEN\"}" \
    && SF_VER=$(curl -s $GH_AUTH https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v${SF_VER}/subfinder_${SF_VER}_linux_amd64.zip" -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin/ \
    && rm /tmp/subfinder.zip \
    && HTTPX_VER=$(curl -s $GH_AUTH https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && rm /tmp/httpx.zip \
    && NUCLEI_VER=$(curl -s $GH_AUTH https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei

# Copy and setup entrypoint script
COPY --chmod=755 entrypoint-infra.sh /opt/enumeraga/entrypoint.sh

# Volume for output persistence - mount this to get results on host
ENV ENUMERAGA_OUTPUT="/tmp/enumeraga_output"
VOLUME ["/tmp/enumeraga_output"]

# BUILD AND RUN INSTRUCTIONS:
# Build:
#   docker build -t gagarter/enumeraga_infra .
#
# Run (network host required for nmap):
#   docker run --network host -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -t 192.168.1.99
#   docker run --network host -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -t 192.168.1.99 -b
#   docker run --network host -v ./output:/tmp/enumeraga_output -v ./targets.txt:/targets.txt gagarter/enumeraga_infra -t /targets.txt

ENTRYPOINT ["/opt/enumeraga/entrypoint.sh"]

# Default shows help if no arguments provided
CMD []
