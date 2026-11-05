import asyncio

import pytest
from mcp_server_enumeraga import server
from mcp_server_enumeraga.jobs import JobStore
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

    async def image_is_present(image):
        return True

    monkeypatch.setattr(server, "run_command", fake_run_command)
    monkeypatch.setattr(server, "running_scan_name", no_duplicate)
    monkeypatch.setattr(server, "image_present", image_is_present)
    store = JobStore()
    store.save = lambda job: None  # keep job files out of the working tree
    monkeypatch.setattr(server, "JOBS", store)
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


def _network_args(cmd):
    """The --network flag and its value, asserting it appears exactly once."""
    idx = [i for i, part in enumerate(cmd) if part == "--network"]
    assert len(idx) == 1, f"--network must appear exactly once, found {len(idx)}: {cmd}"
    return cmd[idx[0] + 1]


def test_network_mode_defaults_to_host():
    """An existing caller that passes nothing must get exactly what it got before."""
    assert _network_args(build_docker_infra_command({"target": "192.168.1.100"})) == "host"


def test_network_mode_host_is_explicitly_accepted():
    """Passing the default explicitly is the same as omitting it."""
    cmd = build_docker_infra_command({"target": "192.168.1.100", "network_mode": "host"})
    assert _network_args(cmd) == "host"


def test_network_mode_joins_a_container_namespace():
    """The point of the parameter: join a mediator's network namespace.

    `container:` takes a container name or ID, not a compose service name, and under
    compose that name is project-prefixed. The caller passes the resolved identifier.
    """
    cmd = build_docker_infra_command(
        {"target": "192.168.1.100", "network_mode": "container:target-gateway"}
    )
    assert _network_args(cmd) == "container:target-gateway"
    assert "host" not in cmd, "host networking must not survive alongside a namespace join"


def test_network_mode_accepts_a_named_network():
    cmd = build_docker_infra_command({"target": "192.168.1.100", "network_mode": "proxy-net"})
    assert _network_args(cmd) == "proxy-net"


def test_infra_tool_schema_declares_network_mode():
    infra = next(t for t in TOOLS if t.name == "enumeraga_infra_scan")
    assert "network_mode" in infra.inputSchema["properties"]


def test_scan_key_distinguishes_network_modes():
    """A scan through a mediator and a scan on host networking are not the same work."""
    base = {"target": "192.168.1.100", "ports": "8080"}
    assert scan_key("infra", base) != scan_key(
        "infra", {**base, "network_mode": "container:target-gateway"}
    )



def _call_tool_failing(monkeypatch, name, args, error="Command failed with code 1\nscan output here"):
    """Invoke handle_tool_call with the docker run raising, as a non-zero exit does."""

    async def failing_run_command(cmd, timeout=3600, extra_env=None):
        raise RuntimeError(error)

    async def no_duplicate(key):
        return None

    monkeypatch.setattr(server, "run_command", failing_run_command)
    monkeypatch.setattr(server, "running_scan_name", no_duplicate)
    result = asyncio.run(server.handle_tool_call(name, args))
    return result[0].text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
    ],
)
def test_failed_scan_still_reports_where_the_results_are(monkeypatch, name, args):
    """A scan that exits non-zero must still say where its artefacts are.

    The tools that ran before the failure wrote real reports, and a cloud scanner
    routinely exits non-zero simply because it found problems. Returning only the
    error left the caller with container-local paths that vanish with the
    container, which is indistinguishable from losing the scan.
    """
    text = _call_tool_failing(monkeypatch, name, args)

    assert "Results saved to:" in text, (
        "the failure path does not report the host output directory, so the results cannot be collected"
    )
    # The collection policy has to travel with it, exactly as on the success path.
    assert "MOVE" in text and "`mv`" in text
    assert "do not copy" in text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
    ],
)
def test_failed_scan_preserves_the_underlying_error(monkeypatch, name, args):
    """Reporting the path must not swallow what actually went wrong."""
    text = _call_tool_failing(monkeypatch, name, args, error="Command failed with code 3\nprowler found failures")

    assert "code 3" in text
    assert "prowler found failures" in text
    assert "did NOT complete cleanly" in text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
    ],
)
def test_failed_scan_does_not_claim_nothing_was_produced(monkeypatch, name, args):
    """A non-zero exit is not evidence that the scan produced nothing.

    Prowler exits 3 when its checks failed and ScoutSuite 200 when a permission was
    denied; both have already written their reports by then.
    """
    text = _call_tool_failing(monkeypatch, name, args)

    assert "still wrote its reports" in text
    assert "before concluding the scan failed" in text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
    ],
)
def test_results_message_warns_against_reporting_container_paths(monkeypatch, name, args):
    """The tools print container-local paths; those are not the deliverable.

    An operator told only "/tmp/enumeraga_output/azure/..." has been told where the
    files were inside a container that has since been removed.
    """
    for text in (_call_tool(monkeypatch, name, args), _call_tool_failing(monkeypatch, name, args)):
        assert "HOST path" in text
        assert "/tmp/enumeraga_output" in text
        assert "removed when" in text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
    ],
)
def test_results_are_named_as_the_deliverable(monkeypatch, name, args):
    """Collecting the output is the job, not an optional tidy-up afterwards."""
    text = _call_tool(monkeypatch, name, args)

    assert "deliverable" in text
    assert "COLLECT THE RESULTS NOW" in text


@pytest.mark.parametrize(
    "name,args",
    [
        ("enumeraga_infra_scan", {"target": "192.168.1.100"}),
        ("enumeraga_infra_scan", {"target": "192.168.1.100", "detach": True}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1"}),
        ("enumeraga_cloud_scan", {"provider": "azure", "subscription": "sub-1", "detach": True}),
    ],
)
def test_every_response_uses_one_results_path_phrase(monkeypatch, name, args):
    """Clean, detached and failed responses must all say "Results saved to:".

    Whatever collects the output keys off that exact phrase, so a variant wording
    on one path is a path whose results are silently never collected. The detached
    reply said "Results will be saved to:" and so matched nothing.
    """
    clean = _call_tool(monkeypatch, name, args)
    assert "Results saved to:" in clean
    assert "Results will be saved to:" not in clean, (
        "a variant of the results-path phrase will not be matched by whatever collects the output"
    )

    # The failure path has no detached variant, but it must agree on the phrase too.
    if not args.get("detach"):
        failed = _call_tool_failing(monkeypatch, name, args)
        assert "Results saved to:" in failed
        assert "Results will be saved to:" not in failed


# --- detached scans and enumeraga_scan_status --------------------------------

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from mcp_server_enumeraga.jobs import Job, now_iso
from mcp_server_enumeraga.scan_status import ContainerInfo

SCAN_ID_RE = re.compile(r"Scan ID: (enum-[0-9a-f]{12})")


@pytest.fixture
def detached_env(monkeypatch, tmp_path):
    """A fresh job store, an output base under tmp_path and a recording docker stub.

    `state.pull_delay` makes `docker pull` slow; `state.run_error` makes `docker run`
    fail; `state.present` is what image_present answers.
    """

    class State:
        calls: list[list[str]] = []
        pull_delay = 0.0
        run_error = None
        present = True

    state = State()
    state.calls = []

    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        state.calls.append(list(cmd))
        if cmd[:2] == ["docker", "pull"]:
            await asyncio.sleep(state.pull_delay)
            return "pulled"
        if cmd[:2] == ["docker", "run"]:
            if state.run_error:
                raise RuntimeError(state.run_error)
            return "a" * 64 + "\n"
        return ""

    async def no_duplicate(key):
        return None

    async def image_present(image):
        await asyncio.sleep(0)  # yield, as a real docker query would
        return state.present

    monkeypatch.setattr(server, "run_command", fake_run_command)
    monkeypatch.setattr(server, "running_scan_name", no_duplicate)
    monkeypatch.setattr(server, "image_present", image_present)
    monkeypatch.setattr(server, "JOBS", JobStore())
    monkeypatch.setattr(server, "HOST_OUTPUT_DIR", str(tmp_path / "out"))
    return state


def _text(result):
    return result[0].text


def _infra_detached():
    return {"target": "192.168.1.100", "detach": True}


def test_detached_response_has_scan_id_and_poll_line(detached_env):
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_infra_scan", _infra_detached())))

    m = SCAN_ID_RE.search(text)
    assert m, text
    assert "Poll progress with enumeraga_scan_status(scan_id=enum-" in text
    assert "every 60–120 s; do not call docker logs." in text
    assert f"Container: enumeraga-{m.group(1)}" in text
    assert "Results saved to:" in text
    assert text.endswith(server.RESULTS_HANDLING)


def test_detached_cloud_response_has_scan_id(detached_env):
    args = {"provider": "azure", "subscription": "sub-1", "detach": True}
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_cloud_scan", args)))
    assert SCAN_ID_RE.search(text), text
    assert "Poll progress with enumeraga_scan_status(scan_id=enum-" in text


def test_detached_returns_fast_while_pulling(detached_env):
    detached_env.present = False
    detached_env.pull_delay = 30

    start = time.monotonic()
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_infra_scan", _infra_detached())))
    assert time.monotonic() - start < 5
    assert "Stage: pulling_image" in text
    assert SCAN_ID_RE.search(text)


def test_detached_command_carries_scan_id_label_and_name(detached_env):
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_infra_scan", _infra_detached())))
    scan_id = SCAN_ID_RE.search(text).group(1)

    runs = [c for c in detached_env.calls if c[:2] == ["docker", "run"]]
    assert len(runs) == 1
    cmd = runs[0]
    assert cmd[2] == "-d"
    assert cmd[cmd.index("--name") + 1] == f"enumeraga-{scan_id}"
    assert f"enumeraga.scan_id={scan_id}" in cmd
    assert any(part.startswith("enumeraga.key=") for part in cmd)


def test_detached_secret_never_on_argv(detached_env):
    args = {"provider": "azure", "client_secret": "sp-secret-value-xyz", "detach": True}
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_cloud_scan", args)))
    scan_id = SCAN_ID_RE.search(text).group(1)

    assert "sp-secret-value-xyz" not in text
    assert all("sp-secret-value-xyz" not in " ".join(c) for c in detached_env.calls)
    job = server.JOBS.get(scan_id)
    assert job.secrets == frozenset({"sp-secret-value-xyz"})
    assert "sp-secret-value-xyz" not in (Path(job.output_dir) / ".enumeraga-job.json").read_text()


def test_detached_failure_within_wait_reports_outcome(detached_env):
    detached_env.run_error = "Command failed with code 125\ndocker: invalid reference"
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_infra_scan", _infra_detached())))

    assert "did NOT complete cleanly" in text
    assert "invalid reference" in text
    assert "Results saved to:" in text


def test_duplicate_guard_blocks_while_pulling(detached_env):
    detached_env.present = False
    detached_env.pull_delay = 30

    async def both():
        first = await server.handle_tool_call("enumeraga_infra_scan", _infra_detached())
        second = await server.handle_tool_call("enumeraga_infra_scan", _infra_detached())
        return _text(first), _text(second)

    first, second = asyncio.run(both())
    scan_id = SCAN_ID_RE.search(first).group(1)
    assert "Scan ID:" not in second
    assert scan_id in second
    assert f"enumeraga_scan_status(scan_id={scan_id})" in second
    assert len([c for c in detached_env.calls if c[:2] == ["docker", "pull"]]) == 1


def test_attached_scan_unchanged(detached_env):
    text = _text(asyncio.run(server.handle_tool_call(
        "enumeraga_infra_scan", {"target": "192.168.1.100"})))
    assert "Scan ID" not in text
    runs = [c for c in detached_env.calls if c[:2] == ["docker", "run"]]
    assert len(runs) == 1
    assert "-d" not in runs[0]
    assert not any("enumeraga.scan_id" in part for part in runs[0])
    assert "--name" not in runs[0]


def test_scan_status_tool_is_listed():
    tool = next(t for t in TOOLS if t.name == "enumeraga_scan_status")
    assert set(tool.inputSchema["properties"]) == {"scan_id", "output_dir"}
    assert "read-only" in tool.description.lower()
    assert "at least one" in tool.description


def test_status_requires_an_identifier(detached_env):
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_scan_status", {})))
    assert "scan_id" in text and "output_dir" in text
    assert detached_env.calls == []


# Helpers for the status tests -------------------------------------------------

def _make_job(output_dir: Path, *, stage="launched", secrets=frozenset(), target="10.0.0.5"):
    output_dir.mkdir(parents=True, exist_ok=True)
    job = Job(
        scan_id="enum-0123456789ab",
        kind="infra",
        key=f"infra:{target}",
        target=target,
        image=server.INFRA_IMAGE,
        output_dir=str(output_dir),
        stage=stage,
        created_at=now_iso(),
        container_name="enumeraga-enum-0123456789ab",
        secrets=secrets,
    )
    return job


def _write_progress(output_dir: Path, target="10.0.0.5", **over):
    data = {
        "schema": 1, "kind": "infra", "target": target,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "phase": "running", "completed": 2, "total": 4,
        "total_is_provisional": False, "failed": 0, "skipped": 0,
        "running": ["nikto on port 80"],
    }
    data.update(over)
    (output_dir / "progress.json").write_text(json.dumps(data))


def _stub_docker_views(monkeypatch, container=None, logs=()):
    async def container_info(name):
        return container

    async def recent_log_lines(name, n=200):
        return list(logs)

    monkeypatch.setattr(server, "container_info", container_info)
    monkeypatch.setattr(server, "recent_log_lines", recent_log_lines)


def _status(args):
    return json.loads(_text(asyncio.run(server.handle_tool_call("enumeraga_scan_status", args))))


def test_status_by_scan_id_running(detached_env, monkeypatch, tmp_path):
    out = tmp_path / "out" / "acme"
    job = _make_job(out)
    server.JOBS.add(job)
    _write_progress(out)
    _stub_docker_views(monkeypatch, ContainerInfo("c" * 64, job.container_name, "running", None))

    status = _status({"scan_id": job.scan_id})
    assert status["stage"] == "running"
    assert status["progress"]["percent"] == 50
    assert status["scan_id"] == job.scan_id
    assert status["results_path"] == str(out)
    assert status["container"]["state"] == "running"


def test_status_while_pulling_names_the_image(detached_env, monkeypatch, tmp_path):
    job = _make_job(tmp_path / "out", stage="pulling_image")
    server.JOBS.add(job)
    _stub_docker_views(monkeypatch)

    status = _status({"scan_id": job.scan_id})
    assert status["stage"] == "pulling_image"
    assert status["summary"].startswith(f"pulling image {server.INFRA_IMAGE}")


def test_status_failed_job_reports_its_error(detached_env, monkeypatch, tmp_path):
    job = _make_job(tmp_path / "out", stage="failed")
    job.error = "image pull failed: manifest unknown"
    server.JOBS.add(job)
    _stub_docker_views(monkeypatch)

    status = _status({"scan_id": job.scan_id})
    assert status["stage"] == "failed"
    assert "manifest unknown" in status["summary"]
    assert "job error" not in status["summary"]


def test_status_after_container_removed(detached_env, monkeypatch, tmp_path):
    out = tmp_path / "out"
    job = _make_job(out)
    server.JOBS.add(job)
    _write_progress(out, phase="finished", completed=4)
    closing = {"kind": "run", "target": job.target,
               "ended_at": datetime.now(timezone.utc).isoformat(),
               "process_exit_code": 0, "deadline_exceeded": False}
    (out / "run.jsonl").write_text(json.dumps(closing) + "\n")
    _stub_docker_views(monkeypatch, container=None)

    status = _status({"scan_id": job.scan_id})
    assert status["stage"] == "finished"


def test_status_by_output_dir_after_restart(detached_env, monkeypatch, tmp_path):
    out = tmp_path / "out" / "acme"
    job = _make_job(out)
    JobStore().save(job)  # written by an earlier server process
    _write_progress(out)
    _stub_docker_views(monkeypatch, ContainerInfo("c" * 64, job.container_name, "running", None))

    for requested in (str(out), "acme"):
        status = _status({"output_dir": requested})
        assert status["scan_id"] == job.scan_id
        assert status["stage"] == "running"

    # A scan_id that names a different job is not this scan.
    status = _status({"scan_id": "enum-ffffffffffff", "output_dir": str(out)})
    assert status["stage"] == "not_found"


def test_status_unknown_scan_id_without_output_dir(detached_env, monkeypatch):
    _stub_docker_views(monkeypatch)
    status = _status({"scan_id": "enum-ffffffffffff"})
    assert status["stage"] == "not_found"
    assert status["summary"] == (
        "unknown scan_id in this server session; pass output_dir to look up a scan started earlier"
    )
    assert detached_env.calls == []


def test_status_dir_accepts_reported_absolute_path(detached_env, tmp_path):
    reported = server.resolve_output_source({"output_dir": "acme"})
    assert server.resolve_status_dir(reported) == Path(reported)
    assert str(server.resolve_status_dir(reported)) == reported
    base = server.resolve_output_source({})
    assert server.resolve_status_dir(base) == Path(base)
    assert server.resolve_status_dir("acme") == Path(reported)


def test_status_dir_confines_escape_without_mkdir(detached_env, tmp_path):
    base = tmp_path / "out"
    before = sorted(p for p in tmp_path.rglob("*"))
    for requested in ("../../etc", "/etc", str(base) + "/../../etc"):
        resolved = server.resolve_status_dir(requested)
        assert resolved == base or base in resolved.parents, (requested, resolved)
    assert sorted(p for p in tmp_path.rglob("*")) == before
    assert not base.exists()


def test_status_never_includes_secret(detached_env, monkeypatch, tmp_path):
    secret = "Zq9-very-secret-value"
    out = tmp_path / "out"
    job = _make_job(out, secrets=frozenset({secret}))
    server.JOBS.add(job)
    _write_progress(out)
    logs = [
        "\x1b[32m[+]\x1b[0m authenticating with " + secret,
        "using client secret " + secret + " for monkey365",
        "AZURE_CLIENT_SECRET=" + secret,
    ]
    _stub_docker_views(monkeypatch, ContainerInfo("c" * 64, job.container_name, "running", None), logs)

    raw = _text(asyncio.run(server.handle_tool_call("enumeraga_scan_status", {"scan_id": job.scan_id})))
    assert secret not in raw
    status = json.loads(raw)
    assert status["last_log_lines"]
    assert all("\x1b" not in line for line in status["last_log_lines"])


def test_container_info_parses_inspect(monkeypatch):
    seen = {}

    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        seen["cmd"], seen["timeout"] = cmd, timeout
        return "abc123|/enumeraga-enum-0123456789ab|exited|3\n"

    monkeypatch.setattr(server, "run_command", fake_run_command)
    info = asyncio.run(server.container_info("enumeraga-enum-0123456789ab"))
    assert info == ContainerInfo("abc123", "enumeraga-enum-0123456789ab", "exited", 3)
    assert seen["cmd"][:2] == ["docker", "inspect"]
    assert seen["timeout"] == 3


def test_container_info_none_when_missing(monkeypatch):
    """docker says the container does not exist, which is evidence of absence."""
    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        raise RuntimeError("Error: No such object: enumeraga-nope")

    monkeypatch.setattr(server, "run_command", fake_run_command)
    assert asyncio.run(server.container_info("enumeraga-nope")) is None


def test_duplicate_guard_holds_for_concurrent_calls(detached_env):
    """Two identical detached calls in flight together must not both launch."""
    detached_env.present = False
    detached_env.pull_delay = 30

    async def together():
        a, b = await asyncio.gather(
            server.handle_tool_call("enumeraga_infra_scan", _infra_detached()),
            server.handle_tool_call("enumeraga_infra_scan", _infra_detached()),
        )
        return _text(a), _text(b)

    texts = asyncio.run(together())
    assert sum(1 for t in texts if "Scan ID:" in t) == 1
    assert len([c for c in detached_env.calls if c[:2] == ["docker", "pull"]]) == 1


def test_status_tolerates_malformed_job_time(detached_env, monkeypatch, tmp_path):
    out = tmp_path / "out"
    job = _make_job(out)
    job.created_at = "not a time"
    JobStore().save(job)
    _stub_docker_views(monkeypatch, container=None)

    status = _status({"output_dir": str(out)})
    assert status["scan_id"] == job.scan_id
    assert status["stage"] in ("failed", "not_found")



# --- fix round 1: docker failures are not evidence --------------------------

DOCKER_UNKNOWN_REASON = "container state unknown: docker did not answer; poll again"


def _status_with_inspect_error(monkeypatch, tmp_path, error, *, closing_exit=None):
    """Status of a launched job whose `docker inspect` raises `error`."""
    out = tmp_path / "out"
    job = _make_job(out)
    server.JOBS.add(job)
    _write_progress(out)
    if closing_exit is not None:
        closing = {"kind": "run", "target": job.target,
                   "ended_at": datetime.now(timezone.utc).isoformat(),
                   "process_exit_code": closing_exit, "deadline_exceeded": False}
        (out / "run.jsonl").write_text(json.dumps(closing) + "\n")
    docker_calls = []

    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        docker_calls.append(cmd)
        raise RuntimeError(error)

    async def recent_log_lines(name, n=200):
        raise AssertionError("logs must not be fetched when the container is not known")

    monkeypatch.setattr(server, "run_command", fake_run_command)
    monkeypatch.setattr(server, "recent_log_lines", recent_log_lines)
    status = _status({"scan_id": job.scan_id})
    assert docker_calls and docker_calls[0][:2] == ["docker", "inspect"]
    return status


@pytest.mark.parametrize(
    "error",
    [
        "Failed to execute command: Command timed out after 3 seconds",
        "Failed to execute command: Command failed with code 1\n\nStderr output:\n"
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.",
    ],
)
def test_status_docker_unanswered_is_not_terminal(detached_env, monkeypatch, tmp_path, error):
    status = _status_with_inspect_error(monkeypatch, tmp_path, error)
    assert status["stage"] == "running"
    assert DOCKER_UNKNOWN_REASON in status["summary"]


def test_status_no_such_container_is_still_failed(detached_env, monkeypatch, tmp_path):
    status = _status_with_inspect_error(
        monkeypatch, tmp_path,
        "Failed to execute command: Command failed with code 1\n\nStderr output:\n"
        "Error: No such object: enumeraga-enum-0123456789ab",
    )
    assert status["stage"] == "failed"
    assert "the container exited without completing its record" in status["summary"]


def test_status_docker_unanswered_with_closing_line_is_finished(detached_env, monkeypatch, tmp_path):
    status = _status_with_inspect_error(
        monkeypatch, tmp_path, "Failed to execute command: Command timed out after 3 seconds",
        closing_exit=0,
    )
    assert status["stage"] == "finished"


VALID_NAME = "enumeraga-enum-0123456789ab"


def test_container_info_unknown_on_malformed_output(monkeypatch):
    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        return "garbage\n"

    monkeypatch.setattr(server, "run_command", fake_run_command)
    assert asyncio.run(server.container_info(VALID_NAME)) is server.DOCKER_UNKNOWN


def test_container_info_running_has_no_exit_code(monkeypatch):
    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        return f"abc|/{VALID_NAME}|running|0\n"

    monkeypatch.setattr(server, "run_command", fake_run_command)
    info = asyncio.run(server.container_info(VALID_NAME))
    assert info.state == "running" and info.exit_code is None


def test_status_log_progress_is_parsed_after_redaction(detached_env, monkeypatch, tmp_path):
    secret = "Zq9-very-secret-value"
    job = _make_job(tmp_path / "out", secrets=frozenset({secret}))
    server.JOBS.add(job)  # no progress.json, so progress comes from the logs
    logs = [f"[40%] Still running: prowler {secret}, scoutsuite"]
    _stub_docker_views(monkeypatch, ContainerInfo("c" * 64, job.container_name, "running", None), logs)

    raw = _text(asyncio.run(server.handle_tool_call("enumeraga_scan_status", {"scan_id": job.scan_id})))
    assert secret not in raw
    status = json.loads(raw)
    assert status["progress_source"] == "logs"
    assert status["progress"]["percent"] == 40


def test_detached_failure_within_wait_names_the_scan_id(detached_env):
    detached_env.run_error = "Command failed with code 125\ndocker: invalid reference"
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_infra_scan", _infra_detached())))
    assert "did NOT complete cleanly" in text
    assert SCAN_ID_RE.search(text), text


# Duplicate refusals point at enumeraga_scan_status, never at docker logs ---------

def _with_running(monkeypatch, running):
    async def fake_running(key):
        return running

    monkeypatch.setattr(server, "running_scan_name", fake_running)


@pytest.mark.parametrize("tool,args", [
    ("enumeraga_infra_scan", {"target": "10.0.0.5"}),
    ("enumeraga_cloud_scan", {"provider": "aws"}),
])
def test_running_duplicate_refusal_names_scan_id(detached_env, monkeypatch, tool, args):
    _with_running(monkeypatch, server.RunningScan("enumeraga-enum-0123456789ab",
                                                  "enum-0123456789ab"))
    text = _text(asyncio.run(server.handle_tool_call(tool, args)))
    assert "enumeraga_scan_status(scan_id=enum-0123456789ab)" in text
    assert "`docker stop enumeraga-enum-0123456789ab`" in text
    assert "docker logs" not in text
    assert not any(c[:2] == ["docker", "run"] for c in detached_env.calls)


@pytest.mark.parametrize("tool,args", [
    ("enumeraga_infra_scan", {"target": "10.0.0.5", "output_dir": "acme"}),
    ("enumeraga_cloud_scan", {"provider": "aws", "output_dir": "acme"}),
])
def test_running_duplicate_refusal_without_scan_id_names_output_dir(
        detached_env, monkeypatch, tool, args):
    _with_running(monkeypatch, server.RunningScan("quirky_name", None))
    text = _text(asyncio.run(server.handle_tool_call(tool, args)))
    expected = server.resolve_output_source(args)
    assert f"enumeraga_scan_status(output_dir={expected})" in text
    assert "`docker stop quirky_name`" in text
    assert "docker logs" not in text


def test_running_scan_name_reads_scan_id_label_with_short_timeout(monkeypatch):
    seen = {}

    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        seen["cmd"], seen["timeout"] = cmd, timeout
        return "enumeraga-enum-0123456789ab|enum-0123456789ab\n"

    monkeypatch.setattr(server, "run_command", fake_run_command)
    got = asyncio.run(server.running_scan_name("infra:k"))
    assert got == server.RunningScan("enumeraga-enum-0123456789ab", "enum-0123456789ab")
    assert seen["timeout"] == 3
    assert seen["cmd"][-1] == '{{.Names}}|{{.Label "enumeraga.scan_id"}}'


@pytest.mark.parametrize("line", ["happy_turing|\n", "happy_turing|<no value>\n",
                                  "happy_turing|-H tcp://x\n"])
def test_running_scan_name_without_a_valid_scan_id(monkeypatch, line):
    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        return line

    monkeypatch.setattr(server, "run_command", fake_run_command)
    assert asyncio.run(server.running_scan_name("k")) == server.RunningScan("happy_turing", None)


def test_no_tool_description_recommends_docker_logs():
    for tool in TOOLS:
        text = json.dumps({"d": tool.description, "s": tool.inputSchema})
        # The only permitted mention is the instruction not to use it.
        assert text.count("docker logs") == text.count("do not call docker logs"), tool.name
        assert "Container ID" not in text, tool.name


@pytest.mark.parametrize("tool_name", ["enumeraga_infra_scan", "enumeraga_cloud_scan"])
def test_detach_description_points_at_scan_status(tool_name):
    tool = next(t for t in TOOLS if t.name == tool_name)
    desc = tool.inputSchema["properties"]["detach"]["description"]
    assert "Scan ID" in desc and "enumeraga_scan_status" in desc


# The on-disk job file cannot steer docker -------------------------------------

@pytest.mark.parametrize("crafted", ["-H tcp://x", "postgres", "enumeraga-enum-ffffffffffff"])
def test_job_file_container_name_is_derived_not_trusted(detached_env, monkeypatch, tmp_path,
                                                        crafted):
    out = tmp_path / "out" / "acme"
    job = _make_job(out, stage="launched")
    JobStore().save(job)
    data = json.loads((out / ".enumeraga-job.json").read_text())
    data["container_name"] = crafted
    (out / ".enumeraga-job.json").write_text(json.dumps(data))

    exec_calls = []

    async def fake_exec(*argv, **kw):
        exec_calls.append(list(argv))
        raise RuntimeError("no docker in tests")

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", fake_exec)
    _status({"output_dir": str(out)})

    docker_calls = detached_env.calls + exec_calls
    assert docker_calls, "docker should have been asked about the derived name"
    for call in docker_calls:
        assert crafted not in call
        assert call[-1] == "enumeraga-enum-0123456789ab"


@pytest.mark.parametrize("bad_id", ["enum-1", "postgres", "-H tcp://x", "enum-0123456789AB",
                                    "enum-0123456789abc"])
def test_job_file_with_bad_scan_id_is_rejected(detached_env, monkeypatch, tmp_path, bad_id):
    out = tmp_path / "out" / "acme"
    job = _make_job(out, stage="launched")
    JobStore().save(job)
    data = json.loads((out / ".enumeraga-job.json").read_text())
    data["scan_id"] = bad_id
    (out / ".enumeraga-job.json").write_text(json.dumps(data))

    assert JobStore().load_from_dir(out) == (None, False)
    status = _status({"output_dir": str(out)})
    assert status["scan_id"] is None
    assert detached_env.calls == []


@pytest.mark.parametrize("name", ["-H tcp://x", "postgres", "enumeraga-enum-1", ""])
def test_docker_views_refuse_foreign_names(monkeypatch, name):
    calls = []

    async def fake_run_command(cmd, timeout=3600, extra_env=None):
        calls.append(cmd)
        return "abc|/x|running|0\n"

    async def fake_exec(*argv, **kw):
        calls.append(list(argv))
        raise AssertionError("docker logs must not be called")

    monkeypatch.setattr(server, "run_command", fake_run_command)
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", fake_exec)
    assert asyncio.run(server.container_info(name)) is None
    assert asyncio.run(server.recent_log_lines(name)) == []
    assert calls == []


# Cloud provider aliases are refused ---------------------------------------------

@pytest.mark.parametrize("provider", ["amazon", "gcloud", "AWS", "", None])
def test_cloud_scan_rejects_provider_outside_schema(detached_env, monkeypatch, provider):
    def no_job(*a, **kw):
        raise AssertionError("no job should be recorded")

    monkeypatch.setattr(server.JOBS, "add", no_job)
    args = {"provider": provider, "detach": True} if provider is not None else {"detach": True}
    text = _text(asyncio.run(server.handle_tool_call("enumeraga_cloud_scan", args)))
    assert "unsupported cloud provider" in text
    assert "aws, azure, gcp, oci, aliyun, do" in text
    assert detached_env.calls == []


def test_cloud_provider_enum_matches_accepted_set():
    tool = next(t for t in TOOLS if t.name == "enumeraga_cloud_scan")
    assert tuple(tool.inputSchema["properties"]["provider"]["enum"]) == server.CLOUD_PROVIDERS
