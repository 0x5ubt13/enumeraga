"""Live end-to-end test: boots the server and drives it as a real MCP client over HTTP.

The unit tests in test_server.py call handle_tool_call() and the command builders directly, so
they never boot the server. That blind spot is not hypothetical: mcp 2.0 removed the
@server.list_tools() / @server.call_tool() decorators that run_server() registers handlers with,
which makes the process die on startup — while every unit test still passed. This test exists to
catch that class of breakage, so it must exercise the real startup path and the real wire
protocol rather than importing anything from the server module.

Marked `live` and excluded from the default run (see pytest.ini) because it spawns a subprocess
and binds a port. Run it with:

    pytest -m live
"""

import asyncio
import os
import socket
import subprocess
import sys
import time

import pytest

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

EXPECTED_TOOLS = {
    "enumeraga_infra_scan",
    "enumeraga_cloud_scan",
    "enumeraga_pull_images",
    "enumeraga_check_docker",
}

STARTUP_TIMEOUT = 30.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


@pytest.fixture
def live_server():
    """Boot the server in HTTP mode on a free port; yield its MCP endpoint URL."""
    port = _free_port()
    env = {**os.environ, "MCP_MODE": "sse", "PORT": str(port)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_server_enumeraga.server"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            # Exited before listening — surface its output, that is the whole diagnostic.
            pytest.fail(
                f"server exited during startup (code {proc.returncode}):\n"
                f"{proc.stdout.read() if proc.stdout else '<no output>'}"
            )
        if _port_open(port):
            break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail(f"server did not listen on port {port} within {STARTUP_TIMEOUT}s")

    try:
        yield f"http://127.0.0.1:{port}/mcp/"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.mark.live
def test_live_mcp_session(live_server):
    """Handshake, enumerate tools, and invoke a read-only tool over the wire."""

    async def scenario():
        async with streamable_http_client(live_server) as (read, write, _):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.serverInfo.name == "enumeraga-mcp-server"
                assert init.protocolVersion

                listed = await session.list_tools()
                names = {tool.name for tool in listed.tools}
                assert EXPECTED_TOOLS <= names, f"missing tools: {sorted(EXPECTED_TOOLS - names)}"

                # check_docker is the only read-only tool: it starts no scan, and it reports
                # rather than raising when Docker is absent, so this is safe on a bare CI box.
                result = await session.call_tool("enumeraga_check_docker", {})
                assert result.isError is False
                text = "\n".join(
                    block.text
                    for block in result.content
                    if getattr(block, "type", None) == "text"
                )
                assert "Docker Status Check" in text

                # The session must survive a completed tool call, since a client holds one open
                # across a whole engagement.
                assert (await session.list_tools()).tools

    asyncio.run(scenario())
