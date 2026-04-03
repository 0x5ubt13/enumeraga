#!/usr/bin/env bash
# enumeraga-docker.sh — wrapper for running enumeraga docker images
# Usage: ./enumeraga-docker.sh <infra|cloud> [args...]
set -euo pipefail

INFRA_IMAGE="${ENUMERAGA_INFRA_IMAGE:-gagarter/enumeraga_infra}"
CLOUD_IMAGE="${ENUMERAGA_CLOUD_IMAGE:-gagarter/enumeraga_cloud}"
OUTPUT_DIR="${ENUMERAGA_OUTPUT_DIR:-${PWD}/output}"

die()   { echo "Error: $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") <infra|cloud> [args...]

Wraps 'docker run' for enumeraga images, handling volume mounts automatically.

INFRA mode:
  $(basename "$0") infra -t <target|targets_file> [flags...]
  Flags are passed directly to enumeraga infra. Notable ones:
    -t <ip|file>   Single IP or path to targets file (file is mounted automatically)
    -r <cidr>      CIDR range
    -b             Activate bruteforce/fuzzing
    -n             Nmap only
    -q             Quiet
    -V             Verbose

CLOUD mode:
  $(basename "$0") cloud <provider> [flags...]
  Providers: aws, azure, gcp, oci, aliyun, do
  Credential dirs are mounted automatically per provider:
    aws             ~/.aws        → /root/.aws
    azure           ~/.azure      → /root/.azure
    gcp             ~/.config/gcloud → /root/.config/gcloud
  Flags are passed directly to enumeraga cloud. Notable ones:
    -c <file>                SA JSON key file (mounted into container automatically)
    --gcp-token <file>       File containing a GCP OAuth2 access token (ya29.xxx);
                             injected as CLOUDSDK_AUTH_ACCESS_TOKEN and
                             GOOGLE_OAUTH_ACCESS_TOKEN — use this instead of -c
                             when you only have a stolen/captured token
    --tenant <id>            Azure Tenant ID
    --client-id <id>         Azure Client ID
    --client-secret <secret> Azure Client Secret
    --no-iam-brute           Disable gcp-iam-brute (GCP)
    -o <dir>                 Output dir inside container (default: /tmp/enumeraga_output)
    -q                       Quiet
    -V                       Verbose

Environment variables:
  ENUMERAGA_INFRA_IMAGE    Override infra image (default: gagarter/enumeraga_infra)
  ENUMERAGA_CLOUD_IMAGE    Override cloud image (default: gagarter/enumeraga_cloud)
  ENUMERAGA_OUTPUT_DIR     Override host output dir (default: ./output)

Examples:
  $(basename "$0") infra -t 192.168.1.1
  $(basename "$0") infra -t targets.txt -b -q
  $(basename "$0") cloud aws
  $(basename "$0") cloud gcp
  $(basename "$0") cloud gcp -c ~/sa-key.json
  $(basename "$0") cloud gcp --gcp-token ~/stolen_token.txt
  $(basename "$0") cloud azure --tenant abc123 --client-id xyz --client-secret s3cr3t
EOF
    exit 0
}

# Determine whether to allocate a TTY
docker_base_flags() {
    if [[ -t 0 && -t 1 ]]; then
        echo "-it --rm"
    else
        echo "--rm"
    fi
}

run_infra() {
    local volumes=("-v" "${OUTPUT_DIR}:/tmp/enumeraga_output")
    local enumeraga_args=()
    local i=0

    while [[ $i -lt $# ]]; do
        local arg="${!i+_}"; arg="${@:$((i+1)):1}"
        case "$arg" in
            -t|--target)
                i=$((i+1))
                local val="${@:$((i+1)):1}"
                if [[ -f "$val" ]]; then
                    local abs_path container_path
                    abs_path="$(realpath "$val")"
                    container_path="/targets/$(basename "$val")"
                    volumes+=("-v" "${abs_path}:${container_path}:ro")
                    enumeraga_args+=("$arg" "$container_path")
                else
                    enumeraga_args+=("$arg" "$val")
                fi
                ;;
            *)
                enumeraga_args+=("$arg")
                ;;
        esac
        i=$((i+1))
    done

    mkdir -p "$OUTPUT_DIR"
    echo "[*] Output will be saved to: ${OUTPUT_DIR}"
    echo "[*] Running: docker run --network host ${volumes[*]} ${INFRA_IMAGE} ${enumeraga_args[*]:-}"
    echo ""

    # shellcheck disable=SC2046
    docker run $(docker_base_flags) \
        --network host \
        "${volumes[@]}" \
        "$INFRA_IMAGE" \
        "${enumeraga_args[@]+"${enumeraga_args[@]}"}"
}

run_cloud() {
    local volumes=("-v" "${OUTPUT_DIR}:/tmp/enumeraga_output")
    local env_vars=()
    local enumeraga_args=()
    local provider=""
    local creds_file=""
    local creds_container_path=""
    local gcp_token_file=""
    local i=0

    # First pass: identify provider, creds file, and gcp token file
    while [[ $i -lt $# ]]; do
        local arg="${@:$((i+1)):1}"
        case "$arg" in
            -c|--creds)
                i=$((i+1))
                creds_file="${@:$((i+1)):1}"
                ;;
            --gcp-token)
                i=$((i+1))
                gcp_token_file="${@:$((i+1)):1}"
                ;;
            aws|amazon)                          provider="aws" ;;
            az|azure)                            provider="azure" ;;
            gcp|gcloud|g)                        provider="gcp" ;;
            oci|oracle)                          provider="oci" ;;
            ay|ali|aliy|aliyun|alibaba)          provider="aliyun" ;;
            do|digital|digitalocean)             provider="do" ;;
        esac
        i=$((i+1))
    done

    # Mount provider credential directories if they exist
    case "$provider" in
        aws)
            if [[ -d "${HOME}/.aws" ]]; then
                volumes+=("-v" "${HOME}/.aws:/root/.aws:ro")
                echo "[*] Mounting AWS credentials: ~/.aws"
            fi
            ;;
        azure)
            if [[ -d "${HOME}/.azure" ]]; then
                volumes+=("-v" "${HOME}/.azure:/root/.azure:ro")
                echo "[*] Mounting Azure credentials: ~/.azure"
            fi
            ;;
        gcp)
            if [[ -d "${HOME}/.config/gcloud" ]]; then
                volumes+=("-v" "${HOME}/.config/gcloud:/root/.config/gcloud:ro")
                echo "[*] Mounting GCP credentials: ~/.config/gcloud"
            fi
            ;;
    esac

    # Mount explicit SA JSON key file if given
    if [[ -n "$creds_file" ]]; then
        [[ -f "$creds_file" ]] || die "Credentials file not found: ${creds_file}"
        local abs_creds
        abs_creds="$(realpath "$creds_file")"
        creds_container_path="/creds/$(basename "$creds_file")"
        volumes+=("-v" "${abs_creds}:${creds_container_path}:ro")
        echo "[*] Mounting credentials file: ${creds_file} → ${creds_container_path}"
    fi

    # Inject GCP OAuth2 access token via env vars (ya29.xxx — not a JSON key file)
    if [[ -n "$gcp_token_file" ]]; then
        [[ -f "$gcp_token_file" ]] || die "GCP token file not found: ${gcp_token_file}"
        local token
        token="$(tr -d '[:space:]' < "$gcp_token_file")"
        [[ -n "$token" ]] || die "GCP token file is empty: ${gcp_token_file}"
        env_vars+=("-e" "CLOUDSDK_AUTH_ACCESS_TOKEN=${token}")
        env_vars+=("-e" "GOOGLE_OAUTH_ACCESS_TOKEN=${token}")
        echo "[*] Injecting GCP access token from: ${gcp_token_file}"
    fi

    # Second pass: build enumeraga args, rewriting the creds file path to container path,
    # and stripping --gcp-token (it's a wrapper-only flag, not passed to enumeraga)
    i=0
    while [[ $i -lt $# ]]; do
        local arg="${@:$((i+1)):1}"
        case "$arg" in
            -c|--creds)
                i=$((i+1))
                enumeraga_args+=("$arg" "$creds_container_path")
                ;;
            --gcp-token)
                i=$((i+1))  # consume the value, pass nothing to enumeraga
                ;;
            *)
                enumeraga_args+=("$arg")
                ;;
        esac
        i=$((i+1))
    done

    mkdir -p "$OUTPUT_DIR"
    echo "[*] Output will be saved to: ${OUTPUT_DIR}"
    echo "[*] Running: docker run ${volumes[*]} ${CLOUD_IMAGE} ${enumeraga_args[*]:-}"
    echo ""

    # shellcheck disable=SC2046
    docker run $(docker_base_flags) \
        "${volumes[@]}" \
        "${env_vars[@]+"${env_vars[@]}"}" \
        "$CLOUD_IMAGE" \
        "${enumeraga_args[@]+"${enumeraga_args[@]}"}"
}

# ── Main ──────────────────────────────────────────────────────────────────────

MODE="${1:-}"
[[ $# -gt 0 ]] && shift

case "$MODE" in
    infra|i|in|inf|infr)   run_infra "$@" ;;
    cloud|cl|clo|clou)     run_cloud "$@" ;;
    -h|--help|help|"")     usage ;;
    *)  die "Unknown mode '${MODE}'. Use 'infra' or 'cloud'." ;;
esac
