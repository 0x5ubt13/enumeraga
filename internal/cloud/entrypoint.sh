#!/bin/bash
set -e

# The container runs as root, so output written to the mounted volume lands on the host
# owned by root — which the operator then cannot move without sudo. When the host UID/GID
# are supplied, restore ownership of the mounted output tree on exit (success or failure),
# so results can be moved straight out of the shared results directory.
_restore_output_owner() {
    if [ -n "${ENUMERAGA_HOST_UID:-}" ] && [ -d "/tmp/enumeraga_output" ]; then
        chown -R "${ENUMERAGA_HOST_UID}:${ENUMERAGA_HOST_GID:-$ENUMERAGA_HOST_UID}" /tmp/enumeraga_output 2>/dev/null || true
    fi
}
trap _restore_output_owner EXIT

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

# Echo the arguments with the Azure client secret redacted so it never lands in
# the container logs (service principal auth passes the secret as a CLI argument).
safe_args=""
redact_next=0
for arg in "$@"; do
    if [ "$redact_next" = "1" ]; then
        safe_args="$safe_args ***REDACTED***"
        redact_next=0
        continue
    fi
    case "$arg" in
        --client-secret)   safe_args="$safe_args $arg"; redact_next=1 ;;
        --client-secret=*) safe_args="$safe_args --client-secret=***REDACTED***" ;;
        *)                 safe_args="$safe_args $arg" ;;
    esac
done
echo "[*] Provider/Args:$safe_args"
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
