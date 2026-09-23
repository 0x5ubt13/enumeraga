#!/bin/sh
# Join the Docker socket's group, then drop to the unprivileged runtime user.
#
# WHY THIS EXISTS. The server talks to the host Docker daemon through a bind-mounted
# socket, which is typically mode 660 root:docker. The group half of that is a host
# fact the image cannot know: it is 999 on Debian and Ubuntu, 998 on Arch, 109 here,
# and 0 under Docker Desktop. Compose can only pass a fixed number through group_add,
# so every operator had to run `stat -c '%g' /var/run/docker.sock` and set DOCKER_GID
# before the server would start. Nobody does, and the failure is silent: the daemon
# reports "permission denied", which the health check renders as "Docker daemon not
# running", so it reads as a broken host rather than a missing environment variable.
#
# Reading the GID at start-up removes the guess. The container starts as root purely
# to adjust group membership and then execs the server as an unprivileged user, so the
# server process itself is never root -- which is the property the hardening was for.
set -eu

SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"
RUN_USER="enumeraga"
RUN_UID=1000
RUN_GID=1000

warn() { printf '[entrypoint] %s\n' "$*" >&2; }

# An explicit DOCKER_GID still wins, so an operator can pin the group when the socket
# is absent at start-up or appears later.
sock_gid="${DOCKER_GID:-}"

if [ -z "$sock_gid" ]; then
    if [ -S "$SOCKET" ]; then
        sock_gid="$(stat -c '%g' "$SOCKET")"
    else
        warn "no Docker socket at $SOCKET."
        warn "Every scan tool needs it. Mount it with:"
        warn "  -v /var/run/docker.sock:/var/run/docker.sock"
        warn "Starting anyway so the server can report the problem rather than vanish."
    fi
fi

if [ "$(id -u)" -ne 0 ]; then
    # Already unprivileged, so group membership cannot be changed from here. This is
    # the supported path for an operator who pins `user:` in compose; it works only if
    # they also granted the socket's group themselves.
    if [ -n "$sock_gid" ] && ! id -G | tr ' ' '\n' | grep -qx "$sock_gid"; then
        warn "running as uid $(id -u) without group $sock_gid, which owns $SOCKET."
        warn "Docker calls will fail with permission denied. Drop the 'user:' override,"
        warn "or add group_add: [\"$sock_gid\"] to the service."
    fi
    exec "$@"
fi

if [ -n "$sock_gid" ]; then
    if [ "$sock_gid" -eq 0 ]; then
        # Docker Desktop commonly ships a root-owned socket. Joining group 0 is broad,
        # so it is done loudly rather than quietly.
        warn "$SOCKET is owned by group 0 (root); granting $RUN_USER that group."
        warn "This is wider than usual. It is how Docker Desktop presents the socket."
    fi

    group_name="$(getent group "$sock_gid" | cut -d: -f1 || true)"
    if [ -z "$group_name" ]; then
        group_name="dockersock"
        # A name collision means some other group already holds the name but not the
        # GID; suffix it rather than fail.
        if getent group "$group_name" >/dev/null 2>&1; then
            group_name="dockersock$sock_gid"
        fi
        groupadd --gid "$sock_gid" "$group_name"
    fi

    if ! id -nG "$RUN_USER" | tr ' ' '\n' | grep -qx "$group_name"; then
        usermod -aG "$group_name" "$RUN_USER"
    fi
fi

# A USER instruction would have set these; setpriv does not, so they are set here.
# Without it the process inherits HOME=/root, which it cannot write, and every docker
# call prints a config-file warning that looks like a failure and is not.
export HOME="/home/$RUN_USER"
export USER="$RUN_USER"
export LOGNAME="$RUN_USER"

# --init-groups rebuilds the supplementary set from /etc/group, which is what picks up
# the group added above. Capabilities are dropped and no-new-privs set because nothing
# beyond this point needs either.
exec setpriv \
    --reuid="$RUN_UID" \
    --regid="$RUN_GID" \
    --init-groups \
    --inh-caps=-all \
    --no-new-privs \
    "$@"
