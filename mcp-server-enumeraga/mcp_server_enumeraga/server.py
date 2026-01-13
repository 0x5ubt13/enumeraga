#!/usr/bin/env python3
"""MCP server for Enumeraga - uses Docker containers for isolation and portability."""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import Response

# Docker image names (published on Docker Hub)
INFRA_IMAGE = "gagarter/enumeraga_infra:latest"
CLOUD_IMAGE = "gagarter/enumeraga_cloud:latest"


# Define available tools
TOOLS: list[Tool] = [
    Tool(
        name="enumeraga_infra_scan",
        description=(
            "Run infrastructure enumeration scan against a target IP, hostname, or targets file "
            "using Docker container. Performs comprehensive port scanning and service enumeration "
            "using nmap and various specialised tools. No root privileges required - runs in container."
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
                    "description": "Custom output directory on host (default: ./enumeraga_output)",
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
                    "description": "Run in background (detached mode) to avoid timeouts. Returns Container ID.",
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
            "misconfigurations. Requires cloud credentials to be mounted into container."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["aws", "azure", "gcp", "oci", "aliyun", "do"],
                    "description": "Cloud service provider to scan",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Custom output directory on host (default: ./enumeraga_output)",
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
                    "description": "Run in background (detached mode) to avoid timeouts. Returns Container ID.",
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
]


def build_docker_infra_command(args: dict[str, Any]) -> list[str]:
    """Build Docker command for infrastructure scan."""
    output_dir = Path(args.get("output_dir", "./enumeraga_output")).absolute()
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker", "run", "--rm", "--privileged",
        "--network", "host",  # Required for nmap to work properly
        "-v", f"{output_dir}:/tmp/enumeraga_output",
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

    return cmd


def build_docker_cloud_command(args: dict[str, Any]) -> list[str]:
    """Build Docker command for cloud scan."""
    output_dir = Path(args.get("output_dir", "./enumeraga_output")).absolute()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine credential paths based on provider
    provider = args["provider"]
    volume_mounts = ["-v", f"{output_dir}:/tmp/enumeraga_output"]

    if provider == "aws":
        aws_dir = Path.home() / ".aws"
        if aws_dir.exists():
            volume_mounts.extend(["-v", f"{aws_dir}:/root/.aws:ro"])

    elif provider == "azure":
        azure_dir = Path.home() / ".azure"
        if azure_dir.exists():
            volume_mounts.extend(["-v", f"{azure_dir}:/root/.azure:ro"])

    elif provider == "gcp":
        gcloud_dir = Path.home() / ".config" / "gcloud"
        if gcloud_dir.exists():
            volume_mounts.extend(["-v", f"{gcloud_dir}:/root/.config/gcloud:ro"])

    cmd = ["docker", "run", "--rm"] + volume_mounts + [CLOUD_IMAGE, provider]

    if args.get("quiet"):
        cmd.append("-q")
    if args.get("verbose"):
        cmd.append("-V")

    return cmd


async def run_command(cmd: list[str], timeout: int = 3600) -> str:
    """Execute command and return output."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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


async def handle_tool_call(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool execution requests."""
    print(f"Executing tool: {name} with args: {arguments}", file=sys.stderr)
    try:
        if name == "enumeraga_infra_scan":
            cmd = build_docker_infra_command(arguments)
            
            # Handle detached mode
            detached = arguments.get("detach", False)
            if detached:
                # Insert -d after "run"
                cmd.insert(2, "-d")

            # Inform user about the scan
            # Inform user about the scan
            target = arguments["target"]
            output_dir = Path(arguments.get("output_dir", "./enumeraga_output")).absolute()

            info_msg = f"Starting infrastructure scan of {target}\n"
            info_msg += f"Output directory: {output_dir}\n"
            info_msg += f"Docker command: {' '.join(cmd)}\n\n"
            info_msg += "This may take several minutes depending on the target...\n\n"

            output = await run_command(cmd, timeout=7200)  # 2 hour timeout

            if detached:
                 return [
                    TextContent(
                        type="text",
                        text=f"Scan started in detached mode.\nContainer ID: {output.strip()}\n\nResults will be saved to: {output_dir}\nCheck container logs: docker logs {output.strip()}",
                    )
                ]

            return [
                TextContent(
                    type="text",
                    text=f"{info_msg}Scan completed successfully!\n\n{output}\n\nResults saved to: {output_dir}",
                )
            ]

        elif name == "enumeraga_cloud_scan":
            cmd = build_docker_cloud_command(arguments)
            
            # Handle detached mode
            detached = arguments.get("detach", False)
            if detached:
                # Insert -d after "run"
                cmd.insert(2, "-d")

            provider = arguments["provider"]
            output_dir = Path(arguments.get("output_dir", "./enumeraga_output")).absolute()

            info_msg = f"Starting {provider.upper()} cloud security assessment\n"
            info_msg += f"Output directory: {output_dir}\n"
            info_msg += f"Docker command: {' '.join(cmd)}\n\n"
            info_msg += "This may take several minutes...\n\n"

            output = await run_command(cmd, timeout=7200)  # 2 hour timeout

            if detached:
                 return [
                    TextContent(
                        type="text",
                        text=f"Scan started in detached mode.\nContainer ID: {output.strip()}\n\nResults will be saved to: {output_dir}\nCheck container logs: docker logs {output.strip()}",
                    )
                ]

            return [
                TextContent(
                    type="text",
                    text=f"{info_msg}Assessment completed!\n\n{output}\n\nResults saved to: {output_dir}",
                )
            ]

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


def create_app(server: Server) -> Starlette:
    """Create Starlette app for SSE."""
    
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

    return Starlette(
        debug=True,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Route("/messages", endpoint=handle_post, methods=["POST"]),
        ],
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
        # When running in Docker, we need to adjust default output path
        if not arguments.get("output_dir"):
            arguments["output_dir"] = "/tmp/enumeraga_output"
        return await handle_tool_call(name, arguments)
    
    # Check execution mode
    mode = os.environ.get("MCP_MODE", "stdio")
    
    if mode == "sse":
        port = int(os.environ.get("PORT", 8000))
        print(f"Starting SSE server on 0.0.0.0:{port}...", file=sys.stderr)
        import uvicorn
        app = create_app(server)
        
        # Configure generous timeouts for long-running scans
        config = uvicorn.Config(
            app, 
            host="0.0.0.0", 
            port=port,
            timeout_keep_alive=3600, # 1 hour keep-alive
            timeout_notify=300,      # 5 minutes notify
            log_level="info"
        )
        server_instance = uvicorn.Server(config)
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
