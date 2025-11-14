#!/bin/bash
# Enumeraga Infra Tool Check

TOOLS=(
  # Recon / enumeration tools
  nmap
  masscan
  amass
  subfinder
  httpx
  nuclei
  gobuster
  ffuf
  dnsenum
  dnsrecon
  dig
  whois

  # Networking / HTTP utilities
  curl
  wget
  git
  jq

  # NFS / filesystem utilities
  showmount
  mount
  tree

  # Package management / scripting
  apt
  apt-get
  dpkg
  pip
  python3
)

echo "=== Enumeraga Infra Tool Check ==="
MISSING=0

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[OK] $tool found at $(command -v $tool)"
  else
    echo "[MISSING] $tool not installed"
    MISSING=$((MISSING+1))
  fi
done

echo "=== Summary ==="
if [ "$MISSING" -eq 0 ]; then
  echo "All infra tools are installed ✅"
else
  echo "$MISSING tools are missing ❌"
fi