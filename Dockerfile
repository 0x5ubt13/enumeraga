# Base: using Kali Linux for broad tool coverage
FROM kalilinux/kali-rolling
LABEL authors="0x5ubt13"

WORKDIR /opt/enumeraga

# Update and install required tools
RUN apt update && apt install -y \
    git curl wget unzip python3 python3-pip golang jq \
    nmap masscan amass gobuster ffuf dnsenum dnsrecon whois \
    nfs-common tree \
    cewl enum4linux-ng dirsearch finger fping hydra \
    nbtscan nikto smbclient \
    && apt clean

# Install Python-based tools
RUN apt update && apt install -y \
    ssh-audit wafw00f whatweb testssl.sh python3-impacket odat \
    && apt clean

# Add missing infra tools
RUN apt update && apt install -y \
    ident-user-enum \
    nbtscan-unixwiz \
    responder \
    rusers \
    testssl.sh \
    && apt clean

# Symlink RunFinger and Testssl for convenience
RUN ln -s /usr/share/responder/tools/RunFinger.py /usr/local/bin/responder-RunFinger \
    && ln -s /usr/bin/testssl.sh /usr/local/bin/testssl.sh

# Metasploit (msfconsole) and Seclists
RUN apt update && apt install -y metasploit-framework

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

ENV PATH="/root/go/bin:${PATH}"

# Clone Enumeraga repo
RUN git clone https://github.com/0x5ubt13/enumeraga.git .

# Install Python deps if present (future-proofing)
RUN if [ -f requirements.txt ]; then pip3 install -r requirements.txt; fi

# Build Enumeraga binary (infra part)
RUN go build -o enumeraga main.go

ENTRYPOINT ["./enumeraga", "infra"]
