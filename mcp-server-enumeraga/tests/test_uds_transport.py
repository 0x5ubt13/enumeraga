"""The unix-socket transport.

Why it exists is in the block above ``uds_settings`` in server.py: this server
has no authentication and holds the Docker socket, so a TCP port hands host root
to everything that shares a network with it -- and in the mediator arrangement
``network_mode="container:<id>"`` is for, the caller and the scan container
deliberately share one network namespace and both run as root. A unix socket is
a filesystem object, so a mediator can mount it into the caller and not into the
scan container. These tests hold the properties that make that true.
"""

import asyncio
import os
import socket
import stat

import pytest
from mcp_server_enumeraga.server import (
    DEFAULT_UDS_DIR_MODE,
    DEFAULT_UDS_MODE,
    DEFAULT_UDS_PATH,
    prepare_uds_path,
    uds_settings,
    uvicorn_config,
)


def _noop_app(scope, receive, send):  # pragma: no cover - never called
    raise AssertionError("the app is never invoked by these tests")


def test_uds_settings_default_to_a_private_socket():
    """An operator who sets only MCP_MODE must not get a world-connectable socket."""
    settings = uds_settings({})
    assert settings.path == DEFAULT_UDS_PATH
    assert settings.mode == DEFAULT_UDS_MODE == 0o600
    assert settings.dir_mode == DEFAULT_UDS_DIR_MODE == 0o700


def test_uds_mode_is_read_as_octal_not_decimal():
    """`666` means rw-rw-rw-, and read as decimal it would silently mean 1232.

    The discriminating case is a value with no `0o` prefix whose octal and
    decimal readings are both valid modes -- `600` is 0o600 (384) one way and
    600 (0o1130) the other. A test using only `0o`-prefixed values would pass
    against `int(raw)` as happily as against `int(raw, 8)`.
    """
    assert uds_settings({"MCP_UDS_MODE": "600"}).mode == 0o600
    assert uds_settings({"MCP_UDS_MODE": "660"}).mode == 0o660
    assert uds_settings({"MCP_UDS_MODE": "0o600"}).mode == 0o600
    assert uds_settings({"MCP_UDS_DIR_MODE": "750"}).dir_mode == 0o750


@pytest.mark.parametrize("value", ["rw-------", "0999", "-1", "7777"])
def test_uds_mode_refuses_what_it_cannot_read(value):
    """A mode that cannot be read must stop the server, not fall back to a default.

    Falling back would be the wider of the two outcomes whenever the operator was
    trying to NARROW the socket, which is the only reason to set this at all.
    """
    with pytest.raises(RuntimeError, match="MCP_UDS_MODE"):
        uds_settings({"MCP_UDS_MODE": value})


def test_uds_path_is_overridable(tmp_path):
    assert uds_settings({"MCP_UDS_PATH": str(tmp_path / "s.sock")}).path == str(
        tmp_path / "s.sock"
    )


def test_prepare_leaves_a_placeholder_at_the_requested_mode(tmp_path):
    """Not decoration. uvicorn chmods a unix socket to 0o666 after binding it,
    but only when the path did NOT already exist -- when it did, it restores the
    mode it found. Pre-creating the socket here is therefore the whole mechanism
    by which the requested mode survives startup, and a "tidier" version that
    left the path empty would silently publish a 0o666 socket."""
    path = tmp_path / "enumeraga.sock"
    prepare_uds_path(str(path), mode=0o600)
    assert stat.S_ISSOCK(os.lstat(path).st_mode)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_prepare_creates_the_parent_directory(tmp_path):
    """The socket's directory is a mount point in the compose case and may be empty,
    but in a bare `docker run` nothing has created it."""
    target = tmp_path / "run" / "nested" / "enumeraga.sock"
    prepare_uds_path(str(target))
    assert target.parent.is_dir()


def test_prepare_shuts_the_directory_even_when_it_already_exists(tmp_path):
    """The directory is what actually confines the socket, and it is normally a
    mount point that something else created wide open. makedirs does nothing at
    all to an existing directory and its `mode` is masked by the umask anyway,
    so the chmod has to be unconditional and separate."""
    wide = tmp_path / "mounted"
    wide.mkdir(mode=0o777)
    os.chmod(wide, 0o777)

    prepare_uds_path(str(wide / "enumeraga.sock"))

    assert stat.S_IMODE(os.stat(wide).st_mode) == 0o700


def test_prepare_clears_a_socket_nothing_is_listening_on(tmp_path):
    """bind(2) fails with EADDRINUSE on an existing path whether or not anything
    answers, so an unclean shutdown would otherwise stop every later start."""
    path = tmp_path / "stale.sock"
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(str(path))
    dead.close()  # the file outlives the socket
    assert path.exists()

    prepare_uds_path(str(path))

    # Not "the file is gone": prepare_uds_path leaves a fresh placeholder at the
    # right mode, which is how the permission survives uvicorn's startup. What
    # matters is that the stale inode was replaced, not that the path is empty.
    assert path.exists()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_prepare_refuses_to_displace_a_live_server(tmp_path):
    """Two servers on one socket is one server silently losing its clients."""
    path = tmp_path / "live.sock"
    live = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    live.bind(str(path))
    live.listen(1)
    try:
        with pytest.raises(RuntimeError, match="already listening"):
            prepare_uds_path(str(path))
        assert path.exists(), "the live socket must survive the refusal"
    finally:
        live.close()


def test_prepare_refuses_to_remove_something_that_is_not_a_socket(tmp_path):
    """MCP_UDS_PATH is operator-supplied, and this process holds the Docker socket.

    Unlinking whatever happens to be at the configured path would make a stray
    environment variable into an arbitrary-unlink primitive in a root-equivalent
    process. Only a socket may be cleared.
    """
    path = tmp_path / "not-a-socket"
    path.write_text("important")

    with pytest.raises(RuntimeError, match="not a socket"):
        prepare_uds_path(str(path))

    assert path.read_text() == "important"


def test_prepare_refuses_a_symlink_to_a_socket(tmp_path):
    """lstat, not stat: a symlink at the path would be followed by a naive check,
    and the unlink would then remove the LINK while the check described its target."""
    real = tmp_path / "real.sock"
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(str(real))
    dead.close()
    link = tmp_path / "link.sock"
    link.symlink_to(real)

    with pytest.raises(RuntimeError, match="not a socket"):
        prepare_uds_path(str(link))

    assert link.is_symlink()


def test_uds_config_binds_a_socket(tmp_path):
    path = str(tmp_path / "x.sock")
    assert uvicorn_config(_noop_app, uds=path).uds == path


def test_both_http_transports_share_their_timeouts():
    """A scan runs for minutes with nothing on the wire. The two transports go
    through one builder so the keep-alive cannot be raised for one and forgotten
    for the other."""
    over_tcp = uvicorn_config(_noop_app, host="0.0.0.0", port=9000)
    over_socket = uvicorn_config(_noop_app, uds="/tmp/enumeraga-test.sock")
    assert over_tcp.timeout_keep_alive == over_socket.timeout_keep_alive == 3600
    assert over_tcp.timeout_notify == over_socket.timeout_notify == 300


def test_a_real_server_leaves_the_socket_shut(tmp_path):
    """The assertion the rest of this file exists to support, taken against a
    running uvicorn rather than against our own arithmetic.

    It is here because the obvious implementation does not work. uvicorn chmods
    a unix socket to 0o666 straight after binding it and does so after the umask
    has been applied, so setting a umask -- which was the first thing tried --
    narrows nothing. Measured 06-09-2026: umask 0o177, socket 0o666.

    So the directory carries the guarantee and the socket's own mode is the
    second layer. Both are asserted, because either alone would pass while the
    arrangement was wrong.
    """
    asyncio.run(_assert_socket_is_shut(tmp_path))


async def _assert_socket_is_shut(tmp_path):
    import uvicorn

    path = tmp_path / "dir" / "enumeraga.sock"
    settings = uds_settings({"MCP_UDS_PATH": str(path)})
    prepare_uds_path(settings.path, settings.mode, settings.dir_mode)

    server_instance = uvicorn.Server(uvicorn_config(_noop_app, uds=settings.path))
    serving = asyncio.create_task(server_instance.serve())
    try:
        for _ in range(500):
            if server_instance.started:
                break
            await asyncio.sleep(0.01)
        assert server_instance.started, "uvicorn never came up, so nothing was measured"

        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700, (
            "the socket's directory is traversable by others, which is the layer "
            "that has no race window and therefore the one the guarantee rests on"
        )
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, (
            "the socket is wider than 0600; uvicorn sets 0o666 on a path that did "
            "not already exist, so the placeholder prepare_uds_path leaves is what "
            "has to survive to here"
        )

        # And it must actually serve. A socket nobody can connect to would satisfy
        # every permission assertion above.
        reader, writer = await asyncio.open_unix_connection(settings.path)
        writer.close()
    finally:
        server_instance.should_exit = True
        await serving
