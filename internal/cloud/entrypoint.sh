#!/bin/bash
set -e

# Enumeraga Cloud Scanner Entrypoint
# Usage: docker run gagarter/enumeraga_cloud aws [additional flags]
#        docker run gagarter/enumeraga_cloud azure -o /tmp/enumeraga_output

# Check if any arguments were provided
if [ $# -eq 0 ]; then
    echo "Enumeraga Cloud Scanner"
    echo ""
    echo "Usage: docker run -v ~/.aws:/root/.aws gagarter/enumeraga_cloud aws"
    echo "       docker run -v ~/.azure:/root/.azure gagarter/enumeraga_cloud azure"
    echo "       docker run -v ~/.config/gcloud:/root/.config/gcloud gagarter/enumeraga_cloud gcp"
    echo ""
    echo "To persist output, mount the output volume:"
    echo "  docker run -v ~/.aws:/root/.aws -v ./output:/tmp/enumeraga_output gagarter/enumeraga_cloud aws"
    echo ""
    ./enumeraga cloud --help
    exit 0
fi

# Run enumeraga cloud with all provided arguments
# Arguments are passed directly: aws, azure, gcp, etc. plus any flags
echo "[*] Starting Enumeraga Cloud Scanner..."
echo "[*] Provider/Args: $@"
echo ""

./enumeraga cloud "$@"

# Report output location
echo ""
echo "[+] Scan complete!"
if [ -d "/tmp/enumeraga_output" ] && [ "$(ls -A /tmp/enumeraga_output 2>/dev/null)" ]; then
    echo "[+] Output saved to /tmp/enumeraga_output"
    echo "[*] If you mounted a volume (-v ./output:/tmp/enumeraga_output), results are on your host."
    echo ""
    echo "[*] Output contents:"
    ls -la /tmp/enumeraga_output/
else
    echo "[!] No output files generated. Check the scan logs above for errors."
fi
