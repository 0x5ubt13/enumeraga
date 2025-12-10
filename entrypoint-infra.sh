#!/bin/bash
set -e

# Enumeraga Infrastructure Scanner Entrypoint
# Usage: docker run --network host gagarter/enumeraga_infra -t 192.168.1.99
#        docker run --network host gagarter/enumeraga_infra -t targets.txt -b

# Check if any arguments were provided
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Enumeraga Infrastructure Scanner"
    echo ""
    echo "Usage: docker run --network host -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -t <target>"
    echo ""
    echo "Examples:"
    echo "  # Single target scan:"
    echo "  docker run --network host -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -t 192.168.1.99"
    echo ""
    echo "  # Multiple targets with bruteforce:"
    echo "  docker run --network host -v ./output:/tmp/enumeraga_output -v ./targets.txt:/targets.txt gagarter/enumeraga_infra -t /targets.txt -b"
    echo ""
    echo "  # CIDR range scan:"
    echo "  docker run --network host -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -r 192.168.1.0/24 -t 192.168.1.99"
    echo ""
    echo "Note: --network host is required for nmap scans to work properly"
    echo ""
    ./enumeraga infra -h
    exit 0
fi

# Run enumeraga infra with all provided arguments
echo "[*] Starting Enumeraga Infrastructure Scanner..."
echo "[*] Args: $@"
echo ""

./enumeraga infra "$@"

# Report output location
echo ""
echo "[+] Scan complete!"
if [ -d "/tmp/enumeraga_output" ] && [ "$(ls -A /tmp/enumeraga_output 2>/dev/null)" ]; then
    echo "[+] Output saved to /tmp/enumeraga_output"
    echo "[*] If you mounted a volume (-v ./output:/tmp/enumeraga_output), results are on your host."
else
    echo "[!] No output files found. Check the scan logs above."
fi
