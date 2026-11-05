#!/usr/bin/env python3
"""MCP server for Enumeraga - uses Docker containers for isolation and portability."""

import asyncio
import contextlib
import json
import os
import socket
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, NamedTuple

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response

from . import jobs
from .jobs import (
    CONTAINER_NAME_PATTERN, SCAN_ID_PATTERN, Job, JobStore, container_name_for,
    detach_args, launch_detached, new_scan_id, now_iso,
)
from .scan_status import (
    ContainerInfo,
    build_status,
    derive_stage,
    parse_log_progress,
    parse_ts,
    read_closing_run_line,
    read_progress,
    redact,
    strip_ansi,
)

# Docker image names (published on Docker Hub)
INFRA_IMAGE = "gagarter/enumeraga_infra:latest"
CLOUD_IMAGE = "gagarter/enumeraga_cloud:latest"
# The cloud providers the scan tool accepts, by their canonical names only.
CLOUD_PROVIDERS = ("aws", "azure", "gcp", "oci", "aliyun", "do")

# When this server runs inside a container (SSE/compose mode), bind-mount sources
# passed to sibling `docker run` calls are resolved by the host daemon, not by this
# container's filesystem. ENUMERAGA_HOST_OUTPUT_DIR supplies the host path that backs
# the output directory; compose mounts that same host path at the same path inside this
# container (an identity mount) so reads and writes line up on both sides.
HOST_OUTPUT_DIR = os.environ.get("ENUMERAGA_HOST_OUTPUT_DIR")

# Host path to the user's Azure CLI config (~/.azure) for unattended `az login`
# scans. Same identity-mount rationale as HOST_OUTPUT_DIR: in compose mode this
# server runs in a container, so the bind source handed to the sibling scan
# container must be a real host path. Compose identity-mounts the host ~/.azure at
# this same path inside this container so the existence check and the sibling mount
# both resolve. Falls back to ~/.azure directly when running on the host (stdio mode).
HOST_AZURE_DIR = os.environ.get("ENUMERAGA_HOST_AZURE_DIR")

# Detached scans known to this server process. A job file in each scan's output
# directory lets a later process find scans started before a restart.
JOBS = JobStore()

# How long a detached call waits in-process before replying. A missing image is
# pulled in the background, so this only catches a launch that fails at once.
DETACH_WAIT_S = 3

# Bound on each docker query made by enumeraga_scan_status, which must stay quick.
STATUS_DOCKER_TIMEOUT_S = 3


# Define available tools
TOOLS: list[Tool] = [
    Tool(
        name="enumeraga_infra_scan",
        description=(
            "Run infrastructure enumeration scan against a target IP, hostname, or targets file "
            "using Docker container. Performs comprehensive port scanning and service enumeration "
            "using nmap and various specialised tools. No root privileges required - runs in container. "
            "The scan's output files are its deliverable: when this returns, move the directory it names under 'Results saved to:' into your working directory before doing anything else. It reports that path whether or not the scan exited cleanly, and a non-zero exit does not mean nothing was produced."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address, hostname, or comma-separated list of IPs",
                },
                "output_dir": {
                    "type": "string",
                    "description": (
                        "Optional sub-folder name for this scan's results (e.g. an engagement "
                        "name like 'acme-prod'). Results are always written under the server's "
                        "configured host results directory; this value only names a sub-folder "
                        "within it. Do NOT pass an absolute path or a path with '..' — it is "
                        "reduced to a safe sub-folder. Omit to write straight into the results "
                        "directory root."
                    ),
                },
                "brute": {
                    "type": "boolean",
                    "description": "Enable bruteforce/fuzzing tools (dirsearch, wpscan, etc.)",
                    "default": False,
                },
                "top_ports": {
                    "type": "string",
                    "description": "Scan only top N ports (e.g., '100', '1000')",
                },
                "quiet": {
                    "type": "boolean",
                    "description": "Suppress banner and reduce verbosity",
                    "default": False,
                },
                "verbose": {
                    "type": "boolean",
                    "description": "Very verbose output for debugging",
                    "default": False,
                },
                "detach": {
                    "type": "boolean",
                    "description": (
                        "Run in background (detached mode) to avoid timeouts. Returns a Scan ID "
                        "straight away; poll enumeraga_scan_status with it for progress."
                    ),
                    "default": False,
                },
                "nmap_only": {
                    "type": "boolean",
                    "description": (
                        "Run nmap scans only and skip the tool suite. This is the only way to "
                        "guarantee that nothing outside 'ports' is touched: several tools take "
                        "no port argument and connect to whatever their protocol implies."
                    ),
                    "default": False,
                },
                "gentle": {
                    "type": "boolean",
                    "description": (
                        "Throttle scans and tools for a gentler profile. Cannot be combined with "
                        "'rate' or 'concurrency', which the scan rejects at startup, because it is "
                        "itself a rate and concurrency preset."
                    ),
                    "default": False,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Maximum minutes for any single long-running tool (default 10).",
                },
                "bounded": {
                    "type": "boolean",
                    "description": (
                        "Enforce a strict scan contract: a single target, no port widening, no "
                        "re-sweeps. Implied by 'ports', 'rate', 'concurrency' or 'max_runtime', so "
                        "it only needs passing on its own."
                    ),
                    "default": False,
                },
                "ports": {
                    "type": "string",
                    "description": (
                        "Scan exactly these ports and enumerate whichever are open, e.g. '80,443' "
                        "or '80,U:53'. A 'U:' prefix means UDP and 'T:' means TCP; without any 'U:' "
                        "entry no UDP scan runs at all. No discovery sweep, no re-sweep and no extra "
                        "port for OS fingerprinting. Mutually exclusive with 'top_ports'."
                    ),
                },
                "rate": {
                    "type": "integer",
                    "description": (
                        "Cap requests per second for HTTP tools and packets per second for nmap. "
                        "Tools differ in what they can honour: some have a true rate control, some "
                        "expose only a thread count, and some have no throttle at all and are "
                        "skipped unless 'allow_unthrottled_tools' is set. The end-of-run summary "
                        "says which was which."
                    ),
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Maximum simultaneous tool processes, also applied to nmap's parallelism.",
                },
                "max_runtime": {
                    "type": "integer",
                    "description": (
                        "Wall-clock limit in seconds for the whole run. On expiry the scan and its "
                        "child processes are killed and it exits 124, having printed the results "
                        "produced so far. Partial results are valid and are not discarded."
                    ),
                },
                "allow_multi_target": {
                    "type": "boolean",
                    "description": "Permit a targets file under a bounded run, which otherwise refuses more than one target.",
                    "default": False,
                },
                "network_mode": {
                    "type": "string",
                    "description": (
                        "Docker network mode for the scan container. Defaults to 'host', which "
                        "is what a standalone scan on a LAN wants. Pass 'container:<name-or-id>' "
                        "to run inside another container's network namespace, so that container's "
                        "firewall rules and packet capture cover this scan; note that takes a "
                        "container name or ID, not a Compose service name, which is "
                        "project-prefixed. A named Docker network is also accepted. Joining a "
                        "namespace inherits that container's interfaces, DNS and lifetime: if it "
                        "stops, this scan loses its networking."
                    ),
                },
                "allow_unthrottled_tools": {
                    "type": "boolean",
                    "description": (
                        "Run tools that have no rate control instead of skipping them. Without this, "
                        "a rate-capped run skips them and reports each skip with its reason."
                    ),
                    "default": False,
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="enumeraga_cloud_scan",
        description=(
            "Run cloud security assessment against AWS, Azure, GCP, OCI, Alibaba Cloud, or DigitalOcean "
            "using Docker container. Uses tools like ScoutSuite, Prowler, CloudFox, and PMapper to identify "
            "misconfigurations. Requires cloud credentials to be mounted into container. "
            "The scan's output files are its deliverable: when this returns, move the directory it names under 'Results saved to:' into your working directory before doing anything else. It reports that path whether or not the scan exited cleanly, and a non-zero exit does not mean nothing was produced. "
            "AWS/GCP/OCI/Alibaba/DigitalOcean read mounted credentials automatically. "
            "AZURE runs unattended as the user's signed-in Azure CLI session by default: if the "
            "user has run 'az login', scan with just provider='azure' — do NOT ask for 'tenant', "
            "'client_id' or 'client_secret'. Those three are an OPTIONAL service principal; supply "
            "them only if the user explicitly provides them or asks to use one (it additionally "
            "enables monkey365's M365/Entra ID inventory and needs the Reader and Security Reader "
            "roles). Without a service principal only monkey365 is skipped; ScoutSuite and Prowler "
            "still run as the az-login user. The client_secret, when given, is forwarded via an "
            "environment variable and never appears on the command line or in logs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": list(CLOUD_PROVIDERS),
                    "description": "Cloud service provider to scan",
                },
                "profile": {
                    "type": "string",
                    "description": (
                        "AWS named profile from ~/.aws/credentials to scan with (AWS only). "
                        "Passed to the container as AWS_PROFILE so every AWS tool uses it. "
                        "Omit to use the default credential resolution."
                    ),
                },
                "tenant": {
                    "type": "string",
                    "description": (
                        "Azure Tenant (Directory) ID for OPTIONAL service principal auth (Azure only). "
                        "A GUID. Omit to scan as the signed-in 'az login' user — do not ask for it."
                    ),
                },
                "client_id": {
                    "type": "string",
                    "description": (
                        "Azure service principal Client/Application ID for OPTIONAL service principal "
                        "auth (Azure only). A GUID. Omit to scan as the signed-in 'az login' user — "
                        "do not ask for it."
                    ),
                },
                "client_secret": {
                    "type": "string",
                    "description": (
                        "Azure service principal client secret for OPTIONAL service principal auth "
                        "(Azure only). Omit to scan as the signed-in 'az login' user — do not ask the "
                        "user for it unless they choose service principal auth. When given, it is "
                        "forwarded via the AZURE_CLIENT_SECRET environment variable, so it never "
                        "appears on the command line, in the host process list, or in logs."
                    ),
                },
                "subscription": {
                    "type": "string",
                    "description": (
                        "Azure Subscription ID to scope the scan to (Azure only). STRONGLY "
                        "RECOMMENDED: set this to the single subscription that is in scope for "
                        "the engagement. If omitted, Prowler scans EVERY subscription the "
                        "signed-in user can list, which is likely out of scope. If the user has "
                        "not named a subscription, take the active one from 'az account show' "
                        "and confirm it is in scope before scanning, rather than leaving this blank."
                    ),
                },
                "output_dir": {
                    "type": "string",
                    "description": (
                        "Optional sub-folder name for this scan's results (e.g. an engagement "
                        "name like 'acme-prod'). Results are always written under the server's "
                        "configured host results directory; this value only names a sub-folder "
                        "within it. Do NOT pass an absolute path or a path with '..' — it is "
                        "reduced to a safe sub-folder. Omit to write straight into the results "
                        "directory root."
                    ),
                },
                "quiet": {
                    "type": "boolean",
                    "description": "Suppress banner and reduce verbosity",
                    "default": False,
                },
                "verbose": {
                    "type": "boolean",
                    "description": "Very verbose output for debugging",
                    "default": False,
                },
                "detach": {
                    "type": "boolean",
                    "description": (
                        "Run in background (detached mode) to avoid timeouts. Returns a Scan ID "
                        "straight away; poll enumeraga_scan_status with it for progress."
                    ),
                    "default": False,
                },
            },
            "required": ["provider"],
        },
    ),
    Tool(
        name="enumeraga_pull_images",
        description=(
            "Pull the latest Enumeraga Docker images from Docker Hub. "
            "Run this first to ensure you have the latest versions."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "image": {
                    "type": "string",
                    "enum": ["infra", "cloud", "both"],
                    "description": "Which image(s) to pull",
                    "default": "both",
                },
            },
        },
    ),
    Tool(
        name="enumeraga_check_docker",
        description=(
            "Check if Docker is installed and running, and verify Enumeraga images are available."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    Tool(
        name="enumeraga_scan_status",
        description=(
            "Report the stage and progress of a detached infra or cloud scan as a small JSON "
            "object whose 'summary' field is one line ready to relay. Pass at least one of "
            "'scan_id' (preferred, returned by a detached scan) or 'output_dir' (the results "
            "path a scan reported, which also finds a scan started before a server restart). "
            "Read-only and quick: it never starts, stops or retries anything and returns within "
            "a few seconds. Poll every 60–120 s; do not call docker logs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "The Scan ID returned by a detached enumeraga_infra_scan or enumeraga_cloud_scan.",
                },
                "output_dir": {
                    "type": "string",
                    "description": (
                        "The results path a scan reported under 'Results saved to:', or the "
                        "sub-folder name it was started with. Confined to the server's results "
                        "directory exactly as scan output paths are."
                    ),
                },
            },
        },
    ),
]


def _chown_host_tree(path: Path) -> None:
    """Best-effort chown of a created output dir (and the results base) to the host user.

    The server container runs as uid 1000, which matches the compose default for
    ENUMERAGA_HOST_UID, so new directories are already owned by the typical host user.
    This chown still runs when the configured host UID differs; it is silently ignored
    when no host UID is set or when the process lacks permission (non-root cannot
    chown to another user).
    """
    uid = os.environ.get("ENUMERAGA_HOST_UID")
    if not uid:
        return
    try:
        uid_i = int(uid)
        gid_i = int(os.environ.get("ENUMERAGA_HOST_GID", uid))
        for p in {Path(HOST_OUTPUT_DIR), path}:
            os.chown(p, uid_i, gid_i)
    except (OSError, ValueError):
        pass


def _confine_under(base: Path, requested: str) -> Path:
    """Resolve a requested output_dir to a safe sub-path under base.

    The result becomes a docker `-v` bind source, so an unconfined value would let a caller
    mount an arbitrary host path into the scan container (e.g. output_dir="/etc"). Each path
    component is reduced to a safe relative segment: anchors, '.', '..' and a redundant
    leading 'enumeraga_output' are dropped, and ':' and '\\' are stripped (':' is the docker
    -v field separator and could otherwise reshape src:dest:opts). A final check guarantees
    the result never escapes base.
    """
    parts: list[str] = []
    for p in Path(requested).parts:
        if p in ("/", "\\", ".", "..") or p == "enumeraga_output":
            continue
        p = p.replace(":", "").replace("\\", "")
        if p:
            parts.append(p)
    target = base.joinpath(*parts) if parts else base
    # Defence in depth: never let a crafted path escape the base.
    if base != target and base not in target.parents:
        target = base
    return target


def _output_base() -> Path:
    """The directory every scan's output is confined under."""
    return Path(HOST_OUTPUT_DIR) if HOST_OUTPUT_DIR else (Path.cwd() / "enumeraga_output")


def resolve_status_dir(requested: str) -> Path:
    """Resolve an output_dir given to enumeraga_scan_status, without creating anything.

    A caller usually passes back the absolute path a scan reported, which is already
    under the base, so its relative part is confined rather than the whole path (which
    would otherwise be re-rooted as base/<base>). Anything else, absolute or not, is
    confined under the base exactly as a scan's output_dir is, so the result names the
    same directory, in the same string form, as resolve_output_source.
    """
    base = _output_base()
    path = Path(requested)
    if path.is_absolute():
        if path == base:
            return base
        try:
            relative = path.relative_to(base)
        except ValueError:
            return _confine_under(base, requested)
        return _confine_under(base, str(relative))
    return _confine_under(base, requested)


def resolve_output_source(args: dict[str, Any]) -> str:
    """Return the bind-mount source for the output directory, always confined to a base.

    Container mode (ENUMERAGA_HOST_OUTPUT_DIR set): the base is the identity-mounted host
    results dir, so the sibling container's daemon can resolve the bind source. Host/stdio
    mode: the base is <cwd>/enumeraga_output. In both modes a requested output_dir is only
    ever a confined sub-folder of the base — it can never select an arbitrary host path.
    """
    requested = args.get("output_dir")
    base = _output_base()
    target = _confine_under(base, requested) if requested else base
    target.mkdir(parents=True, exist_ok=True)
    if HOST_OUTPUT_DIR:
        _chown_host_tree(target)
    return str(target)


def host_owner_env() -> list[str]:
    """`-e` args that tell the scan container to chown its output back to the host user.

    The scan container runs as root, so without this the output lands on the host owned by
    root and cannot be moved out of the results directory without sudo. ENUMERAGA_HOST_UID
    (and optional ENUMERAGA_HOST_GID) are supplied to this server via compose; we forward
    them so the container's entrypoint restores ownership on exit.
    """
    uid = os.environ.get("ENUMERAGA_HOST_UID")
    if not uid:
        return []
    env_args = ["-e", f"ENUMERAGA_HOST_UID={uid}"]
    gid = os.environ.get("ENUMERAGA_HOST_GID")
    if gid:
        env_args += ["-e", f"ENUMERAGA_HOST_GID={gid}"]
    return env_args


# Tuning knobs forwarded verbatim to the scan container when set on this server, so they
# can be adjusted (e.g. via compose) without rebuilding the scan image. The stall-watchdog
# limits let slow tools such as prowler run longer before being treated as hung.
_PASSTHROUGH_ENV = ("ENUMERAGA_STALL_WARMUP", "ENUMERAGA_STALL_TIMEOUT")


def forwarded_env() -> list[str]:
    """`-e` args forwarding the passthrough tuning vars that are set on this server."""
    env_args: list[str] = []
    for var in _PASSTHROUGH_ENV:
        val = os.environ.get(var)
        if val:
            env_args += ["-e", f"{var}={val}"]
    return env_args


# Every argument that changes which traffic a scan produces. Two scans that differ
# in any of these are different work, however similar their targets look, so each
# has to enter the identity or a bounded retry would be discarded as a duplicate of
# an unrelated scan.
_INFRA_IDENTITY_ARGS = (
    "ports",
    "top_ports",
    "rate",
    "concurrency",
    "max_runtime",
    "allow_multi_target",
    "allow_unthrottled_tools",
    "bounded",
    "nmap_only",
    "gentle",
    "brute",
    "network_mode",
)


def scan_key(kind: str, args: dict[str, Any]) -> str:
    """Identity of a scan, used as a docker label so duplicate runs can be detected.

    A retry storm (the client call times out, the agent re-invokes the tool while the
    first scan is still running) would otherwise spawn racing containers writing the same
    output and re-hammering the target/cloud API. Two scans share a key when they would
    do the same work: same target and same bounds for infra, same provider+subscription
    for cloud.
    """
    if kind == "infra":
        # Falsy is treated as unset, so a client that spells out the defaults produces
        # the same identity as one that omits them.
        bounding = ";".join(
            f"{name}={args[name]}" for name in _INFRA_IDENTITY_ARGS if args.get(name)
        )
        target = args.get("target", "")
        return f"infra:{target}" if not bounding else f"infra:{target};{bounding}"
    return f"cloud:{args.get('provider', '')}:{args.get('subscription') or 'all'}"


def build_docker_infra_command(args: dict[str, Any]) -> list[str]:
    """Build Docker command for infrastructure scan."""
    cmd = [
        "docker", "run", "--rm",
        # NET_RAW replaces --privileged. It is all the scanners need: nmap's SYN and
        # UDP scans, OS fingerprinting and fping's ICMP were all verified against a
        # fixture with this capability alone. NET_ADMIN was granted here too and has
        # been dropped -- it confers netfilter administration, so under host
        # networking it would let a scan flush the host firewall, and inside a
        # mediator's network namespace it would let a scan tear down the rules
        # confining it.
        #
        # This requires the image built by the repository Dockerfile, which strips
        # nmap's file capabilities. Kali's nmap requests cap_net_admin via those, and
        # the kernel refuses the exec if it is outside the bounding set, so an older
        # image run with these arguments fails at exit 126 rather than scanning less.
        "--cap-add=NET_RAW",
        # host is the default, not a requirement. nmap needs to reach the target, and
        # host networking is the simplest way to do that for a standalone scan on a
        # LAN. A caller whose traffic must cross a recording mediator instead passes
        # network_mode="container:<id>" to join that container's network namespace,
        # which is how the confining rules and the packet capture come to cover this
        # scan by construction rather than by configuration.
        "--network", args.get("network_mode") or "host",
        "-v", f"{resolve_output_source(args)}:/tmp/enumeraga_output",
        *host_owner_env(),
        *forwarded_env(),
        "--label", f"enumeraga.key={scan_key('infra', args)}",
        INFRA_IMAGE,
        "-t", args["target"],
    ]

    if args.get("brute"):
        cmd.append("-b")
    if args.get("top_ports"):
        cmd.extend(["-p", args["top_ports"]])
    if args.get("quiet"):
        cmd.append("-q")
    if args.get("verbose"):
        cmd.append("-V")
    if args.get("nmap_only"):
        cmd.append("-n")
    if args.get("gentle"):
        cmd.append("-g")
    if args.get("timeout"):
        cmd.extend(["-T", str(args["timeout"])])

    # Bounding flags. Each of --ports, --rate, --concurrency and --max-runtime
    # implies --bounded in the binary, so --bounded only has to be passed when it
    # is the only thing asked for.
    if args.get("bounded"):
        cmd.append("--bounded")
    if args.get("ports"):
        cmd.extend(["--ports", str(args["ports"])])
    if args.get("rate"):
        cmd.extend(["--rate", str(args["rate"])])
    if args.get("concurrency"):
        cmd.extend(["--concurrency", str(args["concurrency"])])
    if args.get("max_runtime"):
        cmd.extend(["--max-runtime", str(args["max_runtime"])])
    if args.get("allow_multi_target"):
        cmd.append("--allow-multi-target")
    if args.get("allow_unthrottled_tools"):
        cmd.append("--allow-unthrottled-tools")

    return cmd


def build_docker_cloud_command(args: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    """Build the Docker command for a cloud scan.

    Returns the command argument list and a mapping of extra environment variables
    that must be present in the `docker` process environment (used to forward secrets
    by name so their values never appear in the command line itself).
    """
    # Determine credential paths based on provider
    provider = args["provider"]
    volume_mounts = ["-v", f"{resolve_output_source(args)}:/tmp/enumeraga_output"]
    extra_env: dict[str, str] = {}

    if provider == "aws":
        aws_dir = Path.home() / ".aws"
        if aws_dir.exists():
            volume_mounts.extend(["-v", f"{aws_dir}:/root/.aws:ro"])
        # Pass the requested profile through to the container as AWS_PROFILE so the AWS
        # SDK and every AWS tool (ScoutSuite, Prowler, CloudFox, aws-enumerator) use it.
        profile = args.get("profile")
        if profile:
            volume_mounts.extend(["-e", f"AWS_PROFILE={profile}"])

    elif provider == "azure":
        # Prefer the host-path Azure config when running in compose mode (so the
        # sibling container's daemon can resolve the bind source); fall back to the
        # local ~/.azure on the host.
        azure_dir = Path(HOST_AZURE_DIR) if HOST_AZURE_DIR else (Path.home() / ".azure")
        if azure_dir.exists():
            # Mounted read-write (not :ro): by default Azure scans run unattended as the
            # signed-in user from `az login`, and the Azure CLI refreshes its access token
            # mid-session, writing the new one back to this cache. A read-only mount would
            # break that refresh. ScoutSuite (--cli) and Prowler (--az-cli-auth) use it.
            volume_mounts.extend(["-v", f"{azure_dir}:/root/.azure"])
        # A service principal is optional. When supplied, the tenant and client IDs are not
        # secret and are passed as -e VAR=value. The client secret is passed by NAME only
        # (-e AZURE_CLIENT_SECRET) and its value is injected into the `docker` process
        # environment via extra_env, so it never appears in the command line, the host
        # process list, or the command string echoed back to the caller. Without it, only
        # monkey365 is skipped; ScoutSuite and Prowler still run as the az-login user.
        tenant = args.get("tenant")
        client_id = args.get("client_id")
        client_secret = args.get("client_secret")
        subscription = args.get("subscription")
        if tenant:
            volume_mounts.extend(["-e", f"AZURE_TENANT_ID={tenant}"])
        if client_id:
            volume_mounts.extend(["-e", f"AZURE_CLIENT_ID={client_id}"])
        if subscription:
            volume_mounts.extend(["-e", f"AZURE_SUBSCRIPTION_ID={subscription}"])
        if client_secret:
            volume_mounts.extend(["-e", "AZURE_CLIENT_SECRET"])
            extra_env["AZURE_CLIENT_SECRET"] = client_secret

    elif provider == "gcp":
        gcloud_dir = Path.home() / ".config" / "gcloud"
        if gcloud_dir.exists():
            volume_mounts.extend(["-v", f"{gcloud_dir}:/root/.config/gcloud:ro"])

    elif provider == "oci":
        oci_dir = Path.home() / ".oci"
        if oci_dir.exists():
            volume_mounts.extend(["-v", f"{oci_dir}:/root/.oci:ro"])

    elif provider == "aliyun":
        aliyun_dir = Path.home() / ".aliyun"
        if aliyun_dir.exists():
            volume_mounts.extend(["-v", f"{aliyun_dir}:/root/.aliyun:ro"])

    elif provider == "do":
        doctl_dir = Path.home() / ".config" / "doctl"
        if doctl_dir.exists():
            volume_mounts.extend(["-v", f"{doctl_dir}:/root/.config/doctl:ro"])

    label = ["--label", f"enumeraga.key={scan_key('cloud', args)}"]
    cmd = ["docker", "run", "--rm"] + volume_mounts + host_owner_env() + forwarded_env() + label + [CLOUD_IMAGE, provider]

    if args.get("quiet"):
        cmd.append("-q")
    if args.get("verbose"):
        cmd.append("-V")

    return cmd, extra_env


async def run_command(
    cmd: list[str],
    timeout: int = 3600,
    extra_env: dict[str, str] | None = None,
) -> str:
    """Execute command and return output.

    extra_env, when provided, is merged onto the current environment for the child
    process. This forwards secrets (e.g. AZURE_CLIENT_SECRET) by value to the `docker`
    client without placing them in the command-line arguments.
    """
    try:
        child_env = {**os.environ, **extra_env} if extra_env else None
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError(f"Command timed out after {timeout} seconds")

        output = stdout.decode() if stdout else ""
        errors = stderr.decode() if stderr else ""

        # Combine stdout and stderr for full context
        full_output = output
        if errors:
            full_output += f"\n\nStderr output:\n{errors}"

        if process.returncode != 0:
            raise RuntimeError(
                f"Command failed with code {process.returncode}\n{full_output}"
            )

        return full_output

    except Exception as e:
        raise RuntimeError(f"Failed to execute command: {e}")


class RunningScan(NamedTuple):
    """A running enumeraga scan container found by its duplicate-detection key."""

    name: str
    # The enumeraga.scan_id label, set only on a detached scan; None otherwise.
    scan_id: str | None


async def running_scan_name(key: str) -> RunningScan | None:
    """The already-running enumeraga scan container with this key, or None.

    Used to refuse duplicate concurrent scans (see scan_key). Best-effort: if the docker
    query fails for any reason we return None and let the scan proceed rather than block.
    The timeout is short so a detached call stays near its few-second budget.
    """
    try:
        out = await run_command(
            ["docker", "ps", "--filter", f"label=enumeraga.key={key}",
             "--format", '{{.Names}}|{{.Label "enumeraga.scan_id"}}'],
            timeout=3,
        )
    except Exception:
        return None
    for line in out.splitlines():
        name, _, scan_id = line.strip().partition("|")
        if name.strip():
            scan_id = scan_id.strip()
            return RunningScan(name.strip(), scan_id if SCAN_ID_PATTERN.match(scan_id) else None)
    return None


def _running_duplicate_refusal(lead: str, running: RunningScan, arguments: dict[str, Any]) -> str:
    """Refuse a duplicate of a scan whose container is already running.

    Points at enumeraga_scan_status rather than docker logs: by scan_id for a detached
    scan, otherwise by the results path, which finds a scan started without one.
    Stopping stays a manual step.
    """
    if running.scan_id:
        check = f"enumeraga_scan_status(scan_id={running.scan_id})"
    else:
        try:
            results = resolve_output_source(arguments)
        except Exception:
            results = "<the results path it reported>"
        check = f"enumeraga_scan_status(output_dir={results})"
    return (
        f"{lead} (container {running.name}). Not starting a duplicate. Wait for it to "
        f"finish, check progress with {check} every 60–120 s, or stop it with "
        f"`docker stop {running.name}` if it is stuck. Do not retry this tool meanwhile."
    )


async def image_present(image: str) -> bool:
    """Whether the image is available locally (looked up through run_command)."""
    return await jobs.image_present(image, run_command)


class _DockerUnknown:
    """Marker for "docker did not say": a timeout, a daemon error or unreadable output."""

    def __repr__(self) -> str:
        return "DOCKER_UNKNOWN"


DOCKER_UNKNOWN = _DockerUnknown()

_NO_SUCH_CONTAINER = ("no such object", "no such container")


async def container_info(name: str) -> ContainerInfo | None | _DockerUnknown:
    """State of the named container.

    None means docker answered that the container does not exist, which (with --rm)
    is evidence that it has gone. DOCKER_UNKNOWN means docker gave no usable answer;
    that must never be read as the container having gone, or one slow inspect on a
    loaded host would report a healthy scan as failed.

    A name this server would never have given a scan container is treated as not
    found without asking docker, so a crafted job file cannot reach another
    container or smuggle in an option.
    """
    if not CONTAINER_NAME_PATTERN.match(name):
        return None
    try:
        out = await run_command(
            ["docker", "inspect", "--format",
             "{{.Id}}|{{.Name}}|{{.State.Status}}|{{.State.ExitCode}}", name],
            timeout=STATUS_DOCKER_TIMEOUT_S,
        )
    except Exception as exc:
        text = str(exc).lower()
        if any(marker in text for marker in _NO_SUCH_CONTAINER):
            return None
        return DOCKER_UNKNOWN
    line = next((ln.strip() for ln in out.splitlines() if ln.strip()), "")
    parts = line.split("|")
    if len(parts) != 4 or not parts[2]:
        return DOCKER_UNKNOWN
    cid, cname, state, code = parts
    exit_code: int | None = None
    # docker reports ExitCode 0 for a container that has not exited yet.
    if state in ("exited", "dead"):
        try:
            exit_code = int(code)
        except ValueError:
            exit_code = None
    return ContainerInfo(cid, cname.lstrip("/"), state, exit_code)


async def recent_log_lines(name: str, n: int = 200) -> list[str]:
    """The container's last n log lines, stdout and stderr merged, ANSI stripped.

    An empty list means the call failed. Callers must still redact the lines.
    A name this server would never have given a scan container yields no lines and
    no docker call.
    """
    if not CONTAINER_NAME_PATTERN.match(name):
        return []
    try:
        process = await asyncio.create_subprocess_exec(
            "docker", "logs", "--tail", str(n), name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(
                process.communicate(), timeout=STATUS_DOCKER_TIMEOUT_S)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return []
    except Exception:
        return []
    if process.returncode != 0:
        return []
    return [strip_ansi(line) for line in out.decode(errors="replace").splitlines()]


def _status_not_found(scan_id: str | None, reason: str | None, results_path: str | None) -> dict:
    return build_status(
        scan_id=scan_id, stage="not_found", reason=reason, progress=None,
        log_progress=None, closing=None, container=None, results_path=results_path,
        job_created_at=None, last_log_lines=[], now=datetime.now(timezone.utc),
    )


async def scan_status(scan_id: str | None, output_dir: str | None) -> dict:
    """Work out a scan's stage and progress. Read-only; bounded by short docker timeouts."""
    job: Job | None = JOBS.get(scan_id) if scan_id else None
    orphaned = False
    if job is not None:
        directory = Path(job.output_dir)
    elif output_dir:
        directory = resolve_status_dir(output_dir)
        job, orphaned = JOBS.load_from_dir(directory)
        if scan_id and (job is None or job.scan_id != scan_id):
            return _status_not_found(scan_id, None, str(directory))
    else:
        return _status_not_found(
            scan_id,
            "unknown scan_id in this server session; pass output_dir to look up a scan "
            "started earlier",
            None,
        )

    container = None
    container_known = False
    if job is not None:
        found = await container_info(job.container_name)
        if found is not DOCKER_UNKNOWN:
            container, container_known = found, True
        try:
            not_before = parse_ts(job.created_at)
        except ValueError:
            not_before = None
        progress = read_progress(
            directory, kind=job.kind, target=job.target, not_before=not_before)
    else:
        progress = read_progress(directory, kind=None, target=None, not_before=None)
        not_before = None
        if progress is not None:
            try:
                not_before = parse_ts(str(progress.get("started_at")))
            except ValueError:
                not_before = None
    closing = read_closing_run_line(
        directory, target=job.target if job else None, not_before=not_before)

    log_progress = None
    log_lines: list[str] = []
    if job is not None and container is not None:
        secrets = job.secrets
        raw = await recent_log_lines(job.container_name)
        # Redacted before parsing, so no unredacted text can reach progress.running
        # or the summary.
        log_lines = [redact(strip_ansi(line), secrets) for line in raw if line.strip()]
        if log_lines:
            log_progress = parse_log_progress(log_lines)

    stage, reason = derive_stage(
        job.stage if job else None, orphaned, container, container_known, progress, closing)
    if job is not None and job.stage == "failed":
        reason = job.error or reason
    if stage == "pulling_image" and job is not None:
        reason = job.image

    return build_status(
        scan_id=job.scan_id if job else scan_id,
        stage=stage,
        reason=reason,
        progress=progress,
        log_progress=log_progress,
        closing=closing,
        container=container,
        results_path=str(directory),
        job_created_at=job.created_at if job else None,
        last_log_lines=log_lines,
        now=datetime.now(timezone.utc),
    )


async def pull_docker_image(image: str) -> str:
    """Pull Docker image."""
    cmd = ["docker", "pull", image]
    return await run_command(cmd, timeout=600)  # 10 minutes for pull


async def check_docker() -> dict[str, Any]:
    """Check Docker installation and images."""
    result = {
        "docker_installed": False,
        "docker_running": False,
        "infra_image_available": False,
        "cloud_image_available": False,
    }

    try:
        # Check if docker command exists
        version_output = await run_command(["docker", "--version"], timeout=5)
        result["docker_installed"] = True

        # Check if Docker daemon is running
        await run_command(["docker", "ps"], timeout=5)
        result["docker_running"] = True

        # Check if images are available locally
        images_output = await run_command(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=10)
        available_images = images_output.strip().split('\n')

        result["infra_image_available"] = INFRA_IMAGE in available_images
        result["cloud_image_available"] = CLOUD_IMAGE in available_images

        result["version"] = version_output.strip()

    except Exception as e:
        result["error"] = str(e)

    return result


# Engagement policy that cannot be inferred from the results path alone, so it travels with it.
RESULTS_HANDLING = (
    "\n\nCOLLECT THE RESULTS NOW — this is the deliverable. The report files are the entire "
    "point of the scan; a scan whose output is left behind has produced nothing. Do this before "
    "summarising, analysing or answering anything else.\n"
    "Collecting these results: MOVE them (`mv`) into your working directory — do not copy. "
    "This is a shared results directory and must not retain client data once a scan is collected. "
    "Move them into a NEW subdirectory, and never overwrite anything already present: scan output "
    "uses generic names (az_subscriptions.json, findings/) that can silently clobber an operator's "
    "hand-written engagement files.\n"
    "The path above is a HOST path and is the only one that can be collected. Paths printed by the "
    "tools themselves (/tmp/enumeraga_output/...) are inside the container, which is removed when "
    "the scan ends — do not report those as the location of the results."
)


def scan_outcome_message(info_msg: str, scan_kind: str, body: str, output_dir: str,
                         *, clean: bool) -> str:
    """Render a finished scan, whether or not it exited cleanly.

    The host output path is reported on BOTH paths deliberately. A scan that fails
    partway has still written whatever its earlier tools produced, and those files
    are the deliverable: reporting only the error leaves the operator with a
    container-local path that no longer exists, which is the same as losing the
    scan. The wording of the path line is identical in both cases so that whatever
    collects it does not have to special-case a failure.
    """
    if clean:
        headline = f"{scan_kind} completed successfully!"
    else:
        headline = (
            f"{scan_kind} did NOT complete cleanly.\n\n"
            "Any tool that ran before the failure still wrote its reports, and a cloud "
            "scanner commonly exits non-zero simply because it found problems, so treat "
            "the output below as evidence rather than as proof that nothing was produced. "
            "Collect the results and inspect them before concluding the scan failed."
        )
    return f"{info_msg}{headline}\n\n{body}\n\nResults saved to: {output_dir}{RESULTS_HANDLING}"


def _active_job_refusal(job: Job) -> str:
    """Refuse a duplicate while an identical detached scan is still pulling or starting."""
    return (
        f"An identical scan is already in progress (scan {job.scan_id}, stage {job.stage}). "
        f"Not starting a duplicate. Check it with "
        f"enumeraga_scan_status(scan_id={job.scan_id}). Do not retry this tool meanwhile."
    )


async def _start_detached(
    *,
    kind: str,
    key: str,
    target: str,
    image: str,
    cmd: list[str],
    extra_env: dict[str, str] | None,
    scan_id: str,
    output_dir: str,
    info_msg: str,
    scan_kind: str,
) -> str:
    """Record a detached scan, launch it in the background and reply without waiting.

    A missing image is pulled by the background task, so the reply comes back within
    DETACH_WAIT_S whatever the pull costs; the caller then polls enumeraga_scan_status.
    """
    present = await image_present(image)
    job = Job(
        scan_id=scan_id,
        kind=kind,
        key=key,
        target=target,
        image=image,
        output_dir=output_dir,
        stage="starting" if present else "pulling_image",
        created_at=now_iso(),
        container_name=container_name_for(scan_id),
        # Held in memory only, to redact status output; never written to the job file.
        secrets=frozenset((extra_env or {}).values()),
    )
    # Re-checked here because the awaits since the caller's check let an identical
    # concurrent call get this far too; nothing between this check and add() yields.
    active = JOBS.active_for_key(key)
    if active is not None:
        return _active_job_refusal(active)
    JOBS.add(job)
    JOBS.save(job)

    task = asyncio.create_task(
        launch_detached(job, cmd, extra_env, JOBS, run=run_command))
    JOBS.tasks.add(task)
    task.add_done_callback(JOBS.tasks.discard)
    await asyncio.wait({task}, timeout=DETACH_WAIT_S)

    if job.stage == "failed":
        # The id is still useful: enumeraga_scan_status reports the job's error.
        return f"Scan ID: {scan_id}\n" + scan_outcome_message(
            info_msg, scan_kind, job.error or "launch failed", output_dir, clean=False)

    # "launched" is the job's own bookkeeping; to the caller the container is running.
    stage = "running" if job.stage == "launched" else job.stage
    return (
        "Scan started in detached mode.\n"
        f"Scan ID: {scan_id}\n"
        f"Stage: {stage}\n"
        f"Container: {job.container_name}\n\n"
        f"Results saved to: {output_dir}\n"
        f"Poll progress with enumeraga_scan_status(scan_id={scan_id}) every 60–120 s; "
        f"do not call docker logs.{RESULTS_HANDLING}"
    )


async def handle_tool_call(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool execution requests."""
    print(f"Executing tool: {name} with args: {arguments}", file=sys.stderr)
    try:
        if name == "enumeraga_infra_scan":
            key = scan_key("infra", arguments)
            # A detached scan that is still pulling or starting has no container yet,
            # so docker cannot see it; the job store can.
            active = JOBS.active_for_key(key)
            if active is not None:
                return [TextContent(type="text", text=_active_job_refusal(active))]
            # Refuse to start a duplicate while an identical scan is already running.
            existing = await running_scan_name(key)
            if existing:
                return [TextContent(type="text", text=_running_duplicate_refusal(
                    f"An infrastructure scan of {arguments.get('target')} is already running",
                    existing, arguments,
                ))]
            cmd = build_docker_infra_command(arguments)

            # Handle detached mode
            detached = arguments.get("detach", False)
            scan_id = None
            if detached:
                scan_id = new_scan_id()
                cmd = detach_args(cmd, scan_id)

            # Inform user about the scan
            target = arguments["target"]
            output_dir = resolve_output_source(arguments)

            info_msg = f"Starting infrastructure scan of {target}\n"
            info_msg += f"Output directory: {output_dir}\n"
            info_msg += f"Docker command: {' '.join(cmd)}\n\n"
            info_msg += "This may take several minutes depending on the target...\n\n"

            if detached:
                return [TextContent(type="text", text=await _start_detached(
                    kind="infra", key=key, target=target, image=INFRA_IMAGE, cmd=cmd,
                    extra_env=None, scan_id=scan_id, output_dir=output_dir,
                    info_msg=info_msg, scan_kind="Infrastructure scan",
                ))]

            # A failed scan still has to report where its artefacts are: the tools
            # that ran before the failure wrote real output, and the only path that
            # survives the container is this one.
            try:
                output = await run_command(cmd, timeout=7200)  # 2 hour timeout
            except Exception as exc:
                return [
                    TextContent(
                        type="text",
                        text=scan_outcome_message(
                            info_msg, "Infrastructure scan", str(exc), output_dir, clean=False),
                    )
                ]

            return [
                TextContent(
                    type="text",
                    text=scan_outcome_message(
                        info_msg, "Infrastructure scan", output, output_dir, clean=True),
                )
            ]

        elif name == "enumeraga_cloud_scan":
            # Checked before any job or docker call. enumeraga itself accepts aliases
            # (amazon, gcloud, ...), but the schema's names are the contract: an
            # alias would produce a different duplicate key for the same scope.
            provider_arg = arguments.get("provider")
            if provider_arg not in CLOUD_PROVIDERS:
                return [TextContent(type="text", text=(
                    f"Error: unsupported cloud provider {provider_arg!r}. Use one of: "
                    f"{', '.join(CLOUD_PROVIDERS)}. Not starting a scan."
                ))]
            key = scan_key("cloud", arguments)
            active = JOBS.active_for_key(key)
            if active is not None:
                return [TextContent(type="text", text=_active_job_refusal(active))]
            # Refuse to start a duplicate while an identical scan is already running.
            existing = await running_scan_name(key)
            if existing:
                return [TextContent(type="text", text=_running_duplicate_refusal(
                    f"A {arguments.get('provider')} cloud scan for this scope is already "
                    f"running; a duplicate would race on the same output and repeat cloud "
                    f"API calls",
                    existing, arguments,
                ))]
            cmd, extra_env = build_docker_cloud_command(arguments)

            # Handle detached mode
            detached = arguments.get("detach", False)
            scan_id = None
            if detached:
                scan_id = new_scan_id()
                cmd = detach_args(cmd, scan_id)

            provider = arguments["provider"]
            output_dir = resolve_output_source(arguments)

            info_msg = f"Starting {provider.upper()} cloud security assessment\n"
            info_msg += f"Output directory: {output_dir}\n"
            # cmd carries the client secret by name only (-e AZURE_CLIENT_SECRET), so the
            # value is never present in this displayed command string.
            info_msg += f"Docker command: {' '.join(cmd)}\n\n"
            info_msg += "This may take several minutes...\n\n"

            if detached:
                return [TextContent(type="text", text=await _start_detached(
                    kind="cloud", key=key, target=provider, image=CLOUD_IMAGE, cmd=cmd,
                    extra_env=extra_env, scan_id=scan_id, output_dir=output_dir,
                    info_msg=info_msg, scan_kind="Cloud assessment",
                ))]

            # Cloud scanners routinely exit non-zero with their reports already
            # written -- prowler exits 3 when checks fail, ScoutSuite 200 when a
            # permission was denied. Raising here without the output path is what
            # left an operator holding container-local paths for a scan that had in
            # fact produced its reports.
            try:
                output = await run_command(cmd, timeout=7200, extra_env=extra_env)  # 2 hour timeout
            except Exception as exc:
                return [
                    TextContent(
                        type="text",
                        text=scan_outcome_message(
                            info_msg, "Cloud assessment", str(exc), output_dir, clean=False),
                    )
                ]

            return [
                TextContent(
                    type="text",
                    text=scan_outcome_message(
                        info_msg, "Cloud assessment", output, output_dir, clean=True),
                )
            ]

        elif name == "enumeraga_scan_status":
            scan_id = arguments.get("scan_id") or None
            output_dir = arguments.get("output_dir") or None
            if not scan_id and not output_dir:
                return [TextContent(type="text", text=(
                    "enumeraga_scan_status needs scan_id or output_dir: pass the Scan ID a "
                    "detached scan returned, or the path it reported under 'Results saved to:'."
                ))]
            status = await scan_status(scan_id, output_dir)
            return [TextContent(type="text", text=json.dumps(status))]

        elif name == "enumeraga_pull_images":
            image_choice = arguments.get("image", "both")

            results = []
            if image_choice in ["infra", "both"]:
                infra_output = await pull_docker_image(INFRA_IMAGE)
                results.append(f"Infrastructure image:\n{infra_output}")

            if image_choice in ["cloud", "both"]:
                cloud_output = await pull_docker_image(CLOUD_IMAGE)
                results.append(f"Cloud image:\n{cloud_output}")

            return [
                TextContent(
                    type="text",
                    text="Docker images pulled successfully!\n\n" + "\n\n".join(results),
                )
            ]

        elif name == "enumeraga_check_docker":
            status = await check_docker()

            message = "Docker Status Check\n" + "=" * 50 + "\n\n"

            if status.get("docker_installed"):
                message += f"✓ Docker installed: {status.get('version', 'Unknown version')}\n"
            else:
                message += "✗ Docker not installed\n"

            if status.get("docker_running"):
                message += "✓ Docker daemon running\n"
            else:
                message += "✗ Docker daemon not running\n"

            message += "\nImage Status:\n"
            if status.get("infra_image_available"):
                message += f"✓ Infrastructure image available: {INFRA_IMAGE}\n"
            else:
                message += f"✗ Infrastructure image not found: {INFRA_IMAGE}\n"
                message += "  Run 'enumeraga_pull_images' to download\n"

            if status.get("cloud_image_available"):
                message += f"✓ Cloud image available: {CLOUD_IMAGE}\n"
            else:
                message += f"✗ Cloud image not found: {CLOUD_IMAGE}\n"
                message += "  Run 'enumeraga_pull_images' to download\n"

            if status.get("error"):
                message += f"\n⚠ Error: {status['error']}\n"

            return [
                TextContent(
                    type="text",
                    text=message,
                )
            ]

        else:
            return [
                TextContent(
                    type="text",
                    text=f"Unknown tool: {name}",
                )
            ]

    except Exception as e:
        return [
            TextContent(
                type="text",
                text=f"Error executing {name}: {e}",
            )
        ]


# --- unix-socket transport ---------------------------------------------------
#
# WHY A THIRD TRANSPORT EXISTS. This server has no authentication and mounts the
# Docker socket, so reaching it is equivalent to host root -- the compose file
# says so, and the `--network` argument below defaults to `host`, which is what
# makes that concrete. `sse` binds a TCP port, and a TCP port is reachable by
# everything that shares a network with it. That is a problem specifically for
# the mediator arrangement `network_mode="container:<id>"` exists to serve: the
# caller (a runner) and the scan container deliberately share ONE network
# namespace, so any port the caller can reach, the scan container can reach too
# -- and the scan container is third-party tools pointed at a hostile target.
# They both run as root in that namespace, so nothing at the network or uid
# layer tells them apart.
#
# A unix socket does. It is a filesystem object, so it is visible to whoever has
# it mounted and to nobody else, and a mediator can mount it into the caller
# without mounting it into the scan container. That is the whole point of this
# mode: the boundary moves from the network, where the two are indistinguishable,
# to the filesystem, where they are not.
#
# The socket carries the same Starlette app as `sse`, so the same two HTTP
# transports are spoken over it and no client-side protocol change is needed --
# only the address.

DEFAULT_UDS_PATH = "/run/mcp-enumeraga/enumeraga.sock"
DEFAULT_UDS_MODE = 0o600
DEFAULT_UDS_DIR_MODE = 0o700


class UdsSettings(NamedTuple):
    path: str
    mode: int
    dir_mode: int


def _octal(source: Mapping[str, str], name: str, default: int) -> int:
    """Read an environment variable as an octal file mode.

    Octal whether or not it carries an ``0o`` prefix, because every other place
    a mode is written -- chmod, umask, docker-compose -- writes it octal, and a
    mode silently read as decimal would be a quietly different socket. `600`
    read as decimal is 0o1130.
    """
    raw = source.get(name)
    if not raw:
        return default
    try:
        mode = int(raw, 8)
    except ValueError:
        raise RuntimeError(
            f"{name} is {raw!r}, which is not an octal mode such as 0600"
        ) from None
    if not 0 <= mode <= 0o777:
        raise RuntimeError(f"{name} is {raw!r}, which is out of range")
    return mode


def uds_settings(env: Mapping[str, str] | None = None) -> UdsSettings:
    """Resolve where the socket goes and how tightly it is shut."""
    source = os.environ if env is None else env
    return UdsSettings(
        path=source.get("MCP_UDS_PATH") or DEFAULT_UDS_PATH,
        mode=_octal(source, "MCP_UDS_MODE", DEFAULT_UDS_MODE),
        dir_mode=_octal(source, "MCP_UDS_DIR_MODE", DEFAULT_UDS_DIR_MODE),
    )


def prepare_uds_path(
    path: str,
    mode: int = DEFAULT_UDS_MODE,
    dir_mode: int = DEFAULT_UDS_DIR_MODE,
) -> str:
    """Make ``path`` bindable at the right permissions, or refuse and say why.

    TWO LAYERS, AND THAT THERE ARE TWO IS A MEASUREMENT RATHER THAN A PREFERENCE.

    uvicorn does not leave a unix socket where you put it. Its
    ``elif config.uds is not None`` branch sets ``uds_perms = 0o666`` and chmods
    the socket to that after binding, and it does so after any umask has been
    applied -- so a umask, which was the first thing tried here, narrows nothing.
    Measured 06-09-2026: umask 0o177, socket still 0o666.

    But that same branch reads ``os.stat(config.uds).st_mode`` FIRST when the
    path already exists, and asyncio's ``create_unix_server`` unlinks an existing
    socket before binding its own. So a socket file pre-created here at the mode
    we want is the mode uvicorn then restores it to. That is why this function
    binds a throwaway socket and immediately closes it: the placeholder is not a
    leftover, it is how the permission survives startup.

    The DIRECTORY is the layer that carries the guarantee, because it is the only
    one with no window at all. A directory with no search permission cannot be
    traversed whatever the mode on the socket inside it says, and it is set
    before any socket exists. The socket's own mode is briefly wide during
    uvicorn's unlink-and-rebind -- behind that already-closed door.

    bind(2) on an existing path fails with EADDRINUSE whether or not anything is
    listening, so an unclean shutdown would otherwise stop every later start.
    Removing the leftover blindly is the wrong fix twice over: it would silently
    displace a server that IS running, and -- since the path is configurable --
    it would turn a stray environment variable into an arbitrary-unlink
    primitive in a process holding the Docker socket. So the file is removed
    only when it is genuinely a socket AND nothing answers on it.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    # Separately from makedirs, whose `mode` argument is masked by the umask and
    # which does nothing at all when the directory already exists -- and it
    # usually does exist, being a mount point.
    os.chmod(parent, dir_mode)

    if os.path.lexists(path):
        # lstat, not stat: a symlink here would be followed by a naive check, and
        # the unlink below would remove the LINK while the check described its
        # target.
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise RuntimeError(
                f"{path} already exists and is not a socket; refusing to remove it. "
                "Point MCP_UDS_PATH somewhere else, or clear that path by hand"
            )

        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(1)
            probe.connect(path)
        except (ConnectionRefusedError, FileNotFoundError):
            # Nothing is listening: the file outlived its server. Safe to clear.
            os.unlink(path)
        else:
            raise RuntimeError(
                f"another server is already listening on {path}; refusing to displace it"
            )
        finally:
            probe.close()

    placeholder = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        placeholder.bind(path)
    finally:
        placeholder.close()
    # Explicit rather than trusting bind() to have honoured a umask. Nothing can
    # connect to a socket that was bound and never listened on, so the moment
    # between the two is not a window onto anything.
    os.chmod(path, mode)
    return path


def uvicorn_config(app, **address):
    """Build the uvicorn config, with the timeouts shared by every HTTP transport.

    Both network transports go through here so their timeouts cannot drift. A
    scan runs for minutes with nothing on the wire, so the keep-alive is
    deliberately far longer than any default.
    """
    import uvicorn

    return uvicorn.Config(
        app,
        timeout_keep_alive=3600,  # 1 hour keep-alive
        timeout_notify=300,       # 5 minutes notify
        log_level="info",
        **address,
    )


def create_app(server: Server) -> Starlette:
    """Create the Starlette app exposing two HTTP transports.

    - Streamable HTTP at ``/mcp`` is the current MCP transport: the client POSTs
      JSON-RPC messages to a single endpoint and receives responses on the same
      connection. This is what modern clients negotiate by default.
    - The legacy HTTP+SSE transport (``GET /sse`` for the event stream and
      ``POST /messages`` for client messages) is retained so that older clients
      continue to work unchanged.
    """

    # Legacy HTTP+SSE transport.
    sse = SseServerTransport("/messages")

    async def handle_sse(request: Request):
        try:
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await server.run(
                    streams[0], streams[1], server.create_initialization_options()
                )
        except Exception:
            # Handle client disconnects
            pass

    async def handle_post(request: Request):
        try:
            await sse.handle_post_message(
                request.scope, request.receive, request._send
            )
        except Exception:
            pass

    # Current Streamable HTTP transport. The session manager owns its own
    # background task group, which must be running for the lifetime of the app.
    session_manager = StreamableHTTPSessionManager(app=server)

    async def handle_streamable_http(scope, receive, send):
        await session_manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        async with session_manager.run():
            yield

    return Starlette(
        # Never enable debug here: it renders tracebacks (with in-scope locals such as the
        # forwarded client secret) into HTTP responses, which would leak to any caller.
        debug=False,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Route("/messages", endpoint=handle_post, methods=["POST"]),
            Mount("/mcp", app=handle_streamable_http),
        ],
        lifespan=lifespan,
    )


async def run_server():
    """Run the MCP server."""
    server = Server("enumeraga-mcp-server")

    # Register tools
    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return TOOLS

    # Handle tool calls
    @server.call_tool()
    async def call_tool(name: str, arguments: Any) -> list[TextContent]:
        return await handle_tool_call(name, arguments)
    
    # Check execution mode
    mode = os.environ.get("MCP_MODE", "stdio")
    
    if mode == "sse":
        port = int(os.environ.get("PORT", 8000))
        print(f"Starting SSE server on 0.0.0.0:{port}...", file=sys.stderr)
        import uvicorn
        config = uvicorn_config(create_app(server), host="0.0.0.0", port=port)
        server_instance = uvicorn.Server(config)
        await server_instance.serve()
    elif mode == "uds":
        import uvicorn

        settings = uds_settings()
        prepare_uds_path(settings.path, settings.mode, settings.dir_mode)
        print(
            f"Starting server on unix socket {settings.path} "
            f"(socket {settings.mode:04o} in a {settings.dir_mode:04o} directory)...",
            file=sys.stderr,
        )
        server_instance = uvicorn.Server(uvicorn_config(create_app(server), uds=settings.path))
        await server_instance.serve()
    else:
        # Run stdio server
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )


def main():
    """Entry point for the MCP server."""
    # Check Python version
    if sys.version_info < (3, 10):
        print("Error: Python 3.10+ required", file=sys.stderr)
        sys.exit(1)

    # Run server
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
