import asyncio

import pytest
from mcp_server_enumeraga import server
from mcp_server_enumeraga.server import (
    build_docker_infra_command,
    build_docker_cloud_command,
    scan_key,
    TOOLS,
)


def _call_tool(monkeypatch, name, args, docker_output="done"):
    """Invoke handle_tool_call with docker and duplicate-detection stubbed out."""

    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        return docker_output

    async def no_duplicate(key):
        return None

    monkeypatch.setattr(server, "run_command", fake_run_command)
    monkeypatch.setattr(server, "running_scan_name", no_duplicate)
    result = asyncio.run(server.handle_tool_call(name, args))
    return result[0].text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_infra_scan", {"target": "192.168.1.100", "detach": True}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1", "detach": True}),
    ],
)
def test_scan_results_carry_handling_policy(monkeypatch, name, args):
    """Every scan result must carry the mv-not-cp policy, detached or not.

    The shared results directory must not retain client data, and scan output uses generic
    names that can clobber an operator's hand-written files. Neither is inferable from the
    results path alone, so the policy has to travel with it.
    """
    text = _call_tool(monkeypatch, name, args)

    assert "MOVE" in text and "`mv`" in text
    assert "do not copy" in text
    assert "NEW subdirectory" in text
    assert "never overwrite" in text

def test_build_docker_infra_command_basic():
    """Test infrastructure command building with basic arguments."""
    args = {
        "target": "192.168.1.100"
    }
    cmd = build_docker_infra_command(args)
    
    # Verify essential parts of the command
    assert "docker" in cmd
    assert "run" in cmd
    assert "--rm" in cmd
    assert "--network" in cmd
    assert "host" in cmd
    assert "gagarter/enumeraga_infra:latest" in cmd
    assert "-t" in cmd
    assert "192.168.1.100" in cmd
    
    # Verify volume mount
    assert any(":/tmp/enumeraga_output" in part for part in cmd)

def test_build_docker_infra_command_full():
    """Test infrastructure command building with all arguments."""
    args = {
        "target": "example.com",
        "output_dir": "/custom/path",
        "brute": True,
        "top_ports": "1000",
        "quiet": True,
        "verbose": True
    }
    cmd = build_docker_infra_command(args)
    
    assert "example.com" in cmd
    assert "-b" in cmd
    assert "-p" in cmd
    assert "1000" in cmd
    assert "-q" in cmd
    assert "-V" in cmd
    
    # Check volume mount for custom path
    assert any("/custom/path:/tmp/enumeraga_output" in part for part in cmd)

def test_build_docker_cloud_command_aws():
    """Test cloud command building for AWS context."""
    args = {
        "provider": "aws",
        "output_dir": "/aws/out"
    }
    cmd, extra_env = build_docker_cloud_command(args)

    assert "aws" in cmd
    assert "gagarter/enumeraga_cloud:latest" in cmd
    assert extra_env == {}

    # We can't strictly check for ~/.aws mount as it depends on local file existence
    # but we can check the logic doesn't crash
    assert len(cmd) > 5

def test_build_docker_cloud_command_azure():
    """Test cloud command building for Azure context."""
    args = {
        "provider": "azure",
        "verbose": True
    }
    cmd, extra_env = build_docker_cloud_command(args)

    assert "azure" in cmd
    assert "-V" in cmd
    assert extra_env == {}

def test_build_docker_cloud_command_azure_service_principal():
    """Azure service principal credentials are forwarded via the environment.

    The tenant and client IDs are passed as -e VAR=value, but the client secret is
    passed by name only (-e AZURE_CLIENT_SECRET) with its value carried in extra_env,
    so it never appears in the command-line arguments.
    """
    args = {
        "provider": "azure",
        "tenant": "11111111-1111-1111-1111-111111111111",
        "client_id": "00000000-0000-0000-0000-000000000000",
        "client_secret": "super-secret-value",
        "subscription": "22222222-2222-2222-2222-222222222222",
    }
    cmd, extra_env = build_docker_cloud_command(args)
    joined = " ".join(cmd)

    assert "AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111" in joined
    assert "AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000" in joined
    assert "AZURE_SUBSCRIPTION_ID=22222222-2222-2222-2222-222222222222" in joined
    # The secret is passed by name only and never as a value on the command line.
    assert "AZURE_CLIENT_SECRET" in cmd
    assert "super-secret-value" not in joined
    assert extra_env == {"AZURE_CLIENT_SECRET": "super-secret-value"}


def test_scan_key_distinguishes_different_port_lists():
    """Two bounded scans of one target are not the same work."""
    a = scan_key("infra", {"target": "192.168.1.100", "ports": "80"})
    b = scan_key("infra", {"target": "192.168.1.100", "ports": "443"})
    assert a != b


def test_scan_key_matches_for_identical_scans():
    """The retry-storm guard still has to recognise a genuine repeat."""
    args = {"target": "192.168.1.100", "ports": "80,443", "rate": 5}
    assert scan_key("infra", args) == scan_key("infra", dict(args))


def test_scan_key_treats_falsy_bounds_as_unset():
    """A client passing explicit defaults must not look different from one omitting them."""
    bare = scan_key("infra", {"target": "192.168.1.100"})
    defaulted = scan_key("infra", {"target": "192.168.1.100", "rate": 0, "brute": False})
    assert bare == defaulted


def test_scan_key_distinguishes_rate_and_concurrency():
    """Every bounding argument changes what the scan does, so each must enter the key."""
    base = {"target": "192.168.1.100", "ports": "80"}
    assert scan_key("infra", base) != scan_key("infra", {**base, "rate": 5})
    assert scan_key("infra", base) != scan_key("infra", {**base, "concurrency": 2})
    assert scan_key("infra", base) != scan_key("infra", {**base, "max_runtime": 900})
    assert scan_key("infra", base) != scan_key("infra", {**base, "nmap_only": True})


def test_scan_key_cloud_unchanged():
    """Cloud keys are untouched by this change."""
    assert scan_key("cloud", {"provider": "aws"}) == "cloud:aws:all"


def test_build_docker_infra_command_bounds():
    """Every bounding flag reaches the binary in the form it expects."""
    args = {
        "target": "192.168.1.100",
        "ports": "80,U:53",
        "rate": 5,
        "concurrency": 2,
        "max_runtime": 900,
        "allow_multi_target": True,
        "allow_unthrottled_tools": True,
        "nmap_only": True,
        "gentle": True,
        "timeout": 15,
    }
    cmd = build_docker_infra_command(args)

    def flag_value(flag):
        return cmd[cmd.index(flag) + 1]

    assert flag_value("--ports") == "80,U:53"
    assert flag_value("--rate") == "5"
    assert flag_value("--concurrency") == "2"
    assert flag_value("--max-runtime") == "900"
    assert flag_value("-T") == "15"
    assert "--allow-multi-target" in cmd
    assert "--allow-unthrottled-tools" in cmd
    assert "-n" in cmd
    assert "-g" in cmd


def test_build_docker_infra_command_bounded_alone():
    """--bounded is usable on its own, without any of the four bounding values."""
    cmd = build_docker_infra_command({"target": "192.168.1.100", "bounded": True})
    assert "--bounded" in cmd


def test_build_docker_infra_command_omits_unset_bounds():
    """An unbounded call must produce exactly the command it produced before."""
    cmd = build_docker_infra_command({"target": "192.168.1.100"})
    for flag in (
        "--bounded",
        "--ports",
        "--rate",
        "--concurrency",
        "--max-runtime",
        "--allow-multi-target",
        "--allow-unthrottled-tools",
        "-n",
        "-g",
        "-T",
    ):
        assert flag not in cmd, f"{flag} must not appear when it was not requested"


def test_build_docker_infra_command_numeric_args_are_strings():
    """docker run takes strings; an int in the list raises at subprocess time."""
    cmd = build_docker_infra_command(
        {"target": "192.168.1.100", "rate": 5, "concurrency": 2, "max_runtime": 900, "timeout": 15}
    )
    assert all(isinstance(part, str) for part in cmd)


def test_infra_tool_schema_declares_the_bounding_flags():
    """A flag the builder emits but the schema hides is unreachable from a client."""
    infra = next(t for t in TOOLS if t.name == "enumeraga_infra_scan")
    properties = infra.inputSchema["properties"]
    for name in (
        "bounded",
        "ports",
        "rate",
        "concurrency",
        "max_runtime",
        "allow_multi_target",
        "allow_unthrottled_tools",
        "nmap_only",
        "gentle",
        "timeout",
    ):
        assert name in properties, f"{name} is not declared in the infra tool schema"


def test_infra_command_grants_net_raw_but_not_net_admin():
    """NET_RAW is all the scanners need; NET_ADMIN is not, and granting it is unsafe.

    Verified against a fixture on 2026-08-21: nmap (SYN, UDP, -O, -sV, NSE), masscan,
    fping, nbtscan-unixwiz, onesixtyone, braa and snmpwalk all behave identically with
    NET_RAW alone, and the real binary produces identical results end to end. `ip link
    set` fails without NET_ADMIN and succeeds with it, so the capability's absence is
    detectable and no scanning tool needed it.

    This pairs with the `setcap -r /usr/lib/nmap/nmap` step in the Dockerfile. Kali's
    nmap requests cap_net_admin through file capabilities, and the kernel refuses to
    exec it when that is outside the bounding set, so the two must ship together.
    """
    cmd = build_docker_infra_command({"target": "192.168.1.100"})
    assert "--cap-add=NET_RAW" in cmd
    assert not any("NET_ADMIN" in part for part in cmd)
