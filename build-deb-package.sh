#!/usr/bin/env bash
set -eu

# Build an Enumeraga .deb on Kali Rolling.
# The script installs only package-build prerequisites; it does not install the
# resulting package or the scanner's optional external tools.

if [[ ! -r /etc/os-release ]]; then
    printf 'error: cannot identify the operating system\n' >&2
    exit 1
fi

# OS Check
. /etc/os-release
if [[ "${ID:-}" != "kali" && "${KALI_BUILD_ALLOW_NONKALI:-0}" != "1" ]]; then
    printf 'error: this script requires Kali Linux (set KALI_BUILD_ALLOW_NONKALI=1 to override)\n' >&2
    exit 1
fi

# Perms: only apt needs root; debian/control declares Rules-Requires-Root: no,
# so module downloads and dpkg-buildpackage run unprivileged.
as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'error: root privileges (or sudo) are required to install build packages\n' >&2
        exit 1
    fi
}

as_build_user() {
    if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        sudo -u "${SUDO_USER}" -- "$@"
    else
        "$@"
    fi
}

export GOTOOLCHAIN=local

BUILD_PACKAGES=(
    build-essential
    ca-certificates
    debhelper-compat
    dpkg-dev
    golang-go
)

printf '[1/6] Updating Kali package indexes...\n'
as_root apt update

printf '[2/6] Installing build packages...\n'
as_root apt install -y --no-install-recommends "${BUILD_PACKAGES[@]}"

[[ -f debian/control ]] || { printf 'error: debian/control is missing\n' >&2; exit 1; }
[[ -f debian/rules ]] || { printf 'error: debian/rules is missing\n' >&2; exit 1; }
[[ -f debian/changelog ]] || { printf 'error: debian/changelog is missing\n' >&2; exit 1; }
[[ -f debian/copyright ]] || { printf 'error: debian/copyright is missing\n' >&2; exit 1; }
[[ -x debian/rules ]] || as_build_user chmod 0755 debian/rules

printf '[3/6] Validating declared build dependencies...\n'
dpkg-checkbuilddeps -B debian/control

printf '[4/6] Downloading Go modules and building the package...\n'
as_build_user env GOTOOLCHAIN=local go mod download
as_build_user dpkg-buildpackage -us -uc -b

printf '[5/6] Verifying the generated package...\n'
DEB_FILE="$(find "../" -maxdepth 1 -type f -name 'enumeraga_*.deb' -printf '%T@ %p\n' | sort -nr | awk 'NR == 1 {sub(/^[^ ]+ /, ""); print}')"
if [[ -z "$DEB_FILE" ]]; then
    printf 'error: no enumeraga .deb was generated\n' >&2
    exit 1
fi

dpkg-deb --info "$DEB_FILE" >/dev/null
dpkg-deb --contents "$DEB_FILE" | grep -qE '\./usr/bin/enumeraga$'
printf '[6/6] DEB package verified: %s\n' "$DEB_FILE"

