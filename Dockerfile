# Base: using Kali Linux for broad tool coverage
FROM kalilinux/kali-rolling
LABEL authors="0x5ubt13"
LABEL description="Enumeraga Infrastructure Scanner - Automated penetration testing enumeration"

WORKDIR /opt/enumeraga

# Update and install required tools in a single layer to reduce image size
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core utilities
    git curl wget unzip jq ca-certificates \
    # Go and Python
    golang python3 python3-pip pipx \
    # Network scanning tools
    nmap masscan amass gobuster ffuf dnsenum dnsrecon whois \
    # NFS and filesystem tools
    nfs-common tree \
    # Enumeration tools
    cewl enum4linux-ng dirsearch finger fping hydra \
    nbtscan nikto smbclient smbmap crackmapexec \
    # Security tools
    ssh-audit wafw00f whatweb testssl.sh python3-impacket \
    # Additional infra tools
    ident-user-enum nbtscan-unixwiz responder rusers rwho \
    onesixtyone snmp braa ldap-utils \
    # Metasploit and Seclists (required for wordlists)
    metasploit-framework seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install ODAT if available (may not be on all architectures)
RUN apt-get update && apt-get install -y odat || true \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create symlinks for tools that have non-standard names
RUN ln -sf /usr/share/responder/tools/RunFinger.py /usr/local/bin/responder-RunFinger 2>/dev/null || true \
    && ln -sf /usr/bin/testssl.sh /usr/local/bin/testssl 2>/dev/null || true \
    && ln -sf /usr/bin/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

ENV PATH="/root/go/bin:${PATH}"

# Copy local source instead of cloning from GitHub
# This ensures local changes are included in the build
COPY . .

# Build Enumeraga binary
RUN go build -o enumeraga main.go

# Copy and setup entrypoint script
COPY entrypoint-infra.sh /opt/enumeraga/entrypoint.sh
RUN chmod +x /opt/enumeraga/entrypoint.sh /opt/enumeraga/enumeraga

# Create output directory
RUN mkdir -p /tmp/enumeraga_output

# Set default output directory as environment variable
ENV ENUMERAGA_OUTPUT="/tmp/enumeraga_output"

# Volume for output persistence - mount this to get results on host
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
