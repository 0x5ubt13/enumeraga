# Enumeraga MCP Server (Docker-Based)

Model Context Protocol (MCP) server for Enumeraga. Every scan runs inside a **Docker container**, so none of Enumeraga's ~20 scan tools are installed on the host — only Docker, plus a small Python process for the server itself when run in stdio mode. See [Deployment](#deployment) for the two ways to run it.

## Architecture

```
User → LLM → MCP Server → Docker Containers → Results
                                ↓
                      gagarter/enumeraga_infra
                      gagarter/enumeraga_cloud
```

The MCP server orchestrates Docker containers that have all tools pre-installed, providing:
- ✅ **Zero local dependencies** (except Docker)
- ✅ **Automatic updates** via Docker Hub
- ✅ **Complete isolation** - scans run in containers
- ✅ **No root required** on host system
- ✅ **Consistent environment** across all platforms

## Prerequisites

- **Docker** installed and running — used for every scan, in both deployment modes
- **The scan images** built or pulled: `gagarter/enumeraga_infra` and `gagarter/enumeraga_cloud`
- **Python 3.10+** — only for **stdio** mode (the server process runs on the host)
- Internet connection (to pull Docker images)

## Two Dockerfiles — don't confuse them

| File | Builds | Required? |
|------|--------|-----------|
| `Dockerfile` (repo root) | `gagarter/enumeraga_infra` scan image | **Yes** — the server runs scans by launching this |
| `internal/cloud/Dockerfile` | `gagarter/enumeraga_cloud` scan image | **Yes** — same, for cloud scans |
| `mcp-server-enumeraga/Dockerfile` + `docker-compose.yml` | The MCP **server** as a container, over HTTP/SSE or a unix socket | **Optional** — only for containerised deployment (modes B and C below) |

The MCP server *orchestrates* scan containers; it never scans on the host. So the scan images are always needed. The server's own image is needed only if you deploy the server itself as a container.

## Deployment

Pick one of three modes.

### Mode A — stdio (recommended for a local CLI/desktop agent)

The MCP client (Claude Desktop, omp, Gemini CLI, …) launches the server as a stdio subprocess on the host. Because the process **inherits the client's working directory**, scan results land under the directory you summoned the agent in (`<cwd>/enumeraga_output/`, or `<cwd>/<output_dir>` if you pass one).

**Recommended: install with pipx.** No clone is needed. Pin a release tag so every machine runs the same server:

```bash
pipx install "git+https://github.com/0x5ubt13/enumeraga@v0.7.0-beta#subdirectory=mcp-server-enumeraga"

# Pull the scan images once (or call `enumeraga_pull_images` later):
docker pull gagarter/enumeraga_infra:latest
docker pull gagarter/enumeraga_cloud:latest
```

`pipx list` then reports the installed release (`mcp-server-enumeraga 0.7.0b0`, the PEP 440 spelling of `v0.7.0-beta`). To move to another release, run the same command with the new tag and `--force`.

Point your client at the `mcp-server-enumeraga` launcher that pipx puts on your `PATH`. **Do not set a `cwd`** in the config — that is what lets the server inherit the client's directory:

```json
{
  "mcpServers": {
    "enumeraga": {
      "command": "mcp-server-enumeraga"
    }
  }
}
```

For Claude Code: `claude mcp add enumeraga -- mcp-server-enumeraga`. Config file locations for other clients are listed under [Configuration](#configuration) below.

Some desktop clients start their servers from a fixed directory rather than a project folder (Claude Desktop, for instance). Under such a client, `<cwd>/enumeraga_output/` may not be where you expect, or may not be writable, and `output_dir` cannot help because it is always a sub-folder of that directory. Use mode B there instead.

**From a clone (for development).** `./setup.sh` creates `./venv` and installs the server in editable mode. Point the client at `venv/bin/mcp-server-enumeraga`, again with no `cwd`. To test local changes to the scan images, build them from the repository root with `docker build -t gagarter/enumeraga_infra:latest .` and `docker build -f internal/cloud/Dockerfile -t gagarter/enumeraga_cloud:latest .`.

### Mode B — HTTP / SSE (for a shared or remote server, e.g. n8n)

The server runs as a long-lived container exposing `http://<host>:9000/mcp/`. It has no concept of any client's working directory, so output goes to a fixed, **identity-mounted** host directory instead.

```bash
cd mcp-server-enumeraga
# Optional overrides (defaults shown):
export ENUMERAGA_HOST_OUTPUT_DIR=/tmp/enumeraga_scan_results   # where results are written
export ENUMERAGA_HOST_AZURE_DIR="$HOME/.azure"                 # az-login reuse for Azure
docker compose up -d --build
```

Clients then use an HTTP entry instead of a command:

```json
{ "mcpServers": { "enumeraga": { "type": "http", "url": "http://localhost:9000/mcp/" } } }
```

Notes for mode B:
- The server runs as uid 1000, not root. The entrypoint reads the group of the mounted Docker socket at start-up and joins it, so nothing has to be set for the host's docker group. Set `DOCKER_GID` only if the socket is not present when the container starts, or if you pin `user:` on the service.
- `docker-compose.yml` identity-mounts `ENUMERAGA_HOST_OUTPUT_DIR` and `ENUMERAGA_HOST_AZURE_DIR` into the server container at the same paths, so the sibling scan containers (spawned via the mounted Docker socket) can resolve them on the host daemon.
- A request's `output_dir` becomes a **sub-folder of** `ENUMERAGA_HOST_OUTPUT_DIR` (absolute paths and `..` are stripped), so output never escapes the mounted tree.
- An `enumeraga-image-refresher` sidecar periodically `docker pull`s the `:latest` scan images. Stop it (`docker compose stop enumeraga-image-refresher`) while testing a locally built image, or it will overwrite your build.

### Mode C — unix socket (for a mediator that shares a network namespace with the scan)

Same server and the same two HTTP transports as mode B, over a unix domain socket instead of a TCP port.

```bash
export MCP_MODE=uds
export MCP_UDS_PATH=/run/mcp-enumeraga/enumeraga.sock   # default
```

**Use this when the caller and the scan container share a network namespace.** That is the arrangement `network_mode="container:<id>"` exists to serve: a mediator confines the scan by putting it in a namespace whose egress is filtered and captured, and the mediator's own client sits in that same namespace. A TCP port cannot separate the two — they share one loopback, and both run as root, so nothing at the network or uid layer tells them apart.

That matters here more than it would for most servers, because **reaching this server is equivalent to host root**: it has no authentication, it mounts the Docker socket, and `network_mode` is a caller-supplied argument that defaults to `host`. A scan container that could reach it could ask for a sibling with host networking, outside every rule confining it.

A unix socket is a filesystem object, so the mediator mounts it into its client and not into the scan container. The boundary moves from the network, where the two are identical, to the filesystem, where they are not.

| Variable | Default | Notes |
|---|---|---|
| `MCP_UDS_PATH` | `/run/mcp-enumeraga/enumeraga.sock` | Mount the **directory**, not the file: the socket is recreated at each start, and a bind mount of the file itself would pin the old inode. |
| `MCP_UDS_MODE` | `0600` | Read as octal with or without an `0o` prefix. |
| `MCP_UDS_DIR_MODE` | `0700` | The socket's directory. |

Notes for mode C:
- **The directory carries the guarantee, not the socket's mode.** uvicorn chmods a unix socket to `0666` right after binding it, after any umask has been applied — so a umask narrows nothing (measured: umask `0177`, socket still `0666`). The server works around it by pre-creating the socket file at `MCP_UDS_MODE`, which uvicorn then preserves; but a directory with no search permission is the layer with no window at all, and that is where the confinement actually lives. Do not "tidy away" either one.
- A leftover socket from an unclean shutdown is cleared automatically. A path that exists and is **not** a socket, or one something is still listening on, refuses to start rather than being removed — `MCP_UDS_PATH` is operator-supplied and this process holds the Docker socket, so an unconditional unlink would be an arbitrary-delete primitive.
- The server still needs no network of its own in this mode. `network_mode: none` is a reasonable thing for a mediator's compose file to give it.

## Configuration

### For Claude Desktop

Add to your configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "enumeraga": {
      "command": "python3",
      "args": [
        "/path/to/enumeraga/mcp-server-enumeraga/mcp_server_enumeraga/server.py"
      ]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "enumeraga": {
      "command": "mcp-server-enumeraga"
    }
  }
}
```

### For Gemini CLI

Add to your configuration file:

**macOS**: `~/.gemini/config.json`
**Windows**: `%USERPROFILE%\.gemini\config.json`
**Linux**: `~/.gemini/config.json`

```json
{
  "mcpServers": {
    "enumeraga": {
      "command": "python3",
      "args": [
        "/path/to/enumeraga/mcp-server-enumeraga/mcp_server_enumeraga/server.py"
      ]
    }
  }
}
```

### For Local Ollama (via compatible clients)

If you are using an MCP client that works with a local Ollama server (e.g., via a bridge or compatible UI), use the standard MCP configuration:

```json
{
  "mcpServers": {
    "enumeraga": {
      "command": "python3",
      "args": [
        "/path/to/enumeraga/mcp-server-enumeraga/mcp_server_enumeraga/server.py"
      ]
    }
  }
}
```

## Available Tools

### 1. enumeraga_infra_scan

Run infrastructure enumeration using Docker container.

**Parameters:**
- `target` (required, string): IP address, hostname, or comma-separated IPs
- `output_dir` (optional, string): Sub-folder name for this scan's results, under the server's configured results directory
- `brute` (optional, boolean): Enable bruteforce/fuzzing tools
- `top_ports` (optional, string): Scan only top N ports (e.g., "100"). Mutually exclusive with `ports`
- `quiet` (optional, boolean): Suppress verbose output
- `verbose` (optional, boolean): Very verbose debugging output
- `detach` (optional, boolean): Run in the background to avoid client timeouts; returns a container ID
- `nmap_only` (optional, boolean): Run nmap scans only and skip the tool suite
- `gentle` (optional, boolean): Throttle scans and tools. Cannot be combined with `rate` or `concurrency`
- `timeout` (optional, integer): Maximum minutes for any single long-running tool (default 10)
- `network_mode` (optional, string): Docker network mode. Defaults to `host`. Pass `container:<name-or-id>` to run inside another container's network namespace, or a named Docker network

**Running inside another container's network namespace.** `network_mode: "container:<name-or-id>"` puts the scan in that container's namespace, so its firewall rules and any packet capture cover the scan by construction rather than by configuration. Three things to know: it takes a container name or ID, not a Compose service name, which is project-prefixed; the scan inherits that container's interfaces, DNS and lifetime, so if it stops the scan loses its networking; and this is mutually exclusive with host networking, which is why it is a parameter rather than an addition.

The container is granted `CAP_NET_RAW` and nothing else, which is what makes joining a mediator's namespace safe: without `CAP_NET_ADMIN` in its bounding set, the scan cannot alter the rules confining it. This requires an image built from the current Dockerfile, which strips nmap's file capabilities; an older image run against these arguments fails loudly with exit 126 rather than scanning less.

**Bounding parameters.** Any one of `ports`, `rate`, `concurrency` or `max_runtime` implies `bounded`, so bounds never need pairing with a mode flag:

- `bounded` (optional, boolean): Enforce a strict scan contract — a single target, no port widening, no re-sweeps
- `ports` (optional, string): Scan exactly these ports and enumerate whichever are open, e.g. `"80,443"` or `"80,U:53"`. `U:` means UDP, `T:` means TCP; with no `U:` entry no UDP scan runs at all
- `rate` (optional, integer): Requests per second for HTTP tools, packets per second for nmap
- `concurrency` (optional, integer): Maximum simultaneous tool processes, also applied to nmap's parallelism
- `max_runtime` (optional, integer): Wall-clock limit in seconds. On expiry the scan and its children are killed and it exits 124, having printed the results produced so far
- `allow_multi_target` (optional, boolean): Permit a targets file under a bounded run, which otherwise refuses more than one target
- `allow_unthrottled_tools` (optional, boolean): Run tools that have no rate control instead of skipping them

Tools differ in what a `rate` cap can mean for them, and a tool with no throttle at all is skipped and reported rather than run uncapped. The repository README's "Bounded scans" section carries the per-tool capability table and an account of what `ports` cannot constrain; `docs/bounded-scanning-rationale.md` records why the bounds exist and which alternatives were rejected.

Validation lives in the scanner, not here. Passing `ports` with `top_ports`, or `gentle` with `rate`, is rejected at startup with a message naming both flags.

**The run record.** Every scan writes `run.jsonl` into the mounted results directory: one JSON object per line naming each tool launched, its argument vector, its timings and its real exit status, bracketed by a pair of `run` lines carrying the bounds and the final disposition. It is appended as the scan proceeds, so it can be read while a scan is still running — which is the point when `detach` is set. Its absence means recording was disabled, not that nothing ran. The repository README documents the entry shapes.

**Example:**
```python
{
    "target": "192.168.1.100",
    "brute": True,
    "output_dir": "./scan_results"
}
```

**Example — bounded scan:**
```python
{
    "target": "192.168.1.100",
    "ports": "80,443",
    "rate": 5,
    "concurrency": 2,
    "max_runtime": 900
}
```

**Docker Command Generated:**
```bash
docker run --rm --network host \
  -v ./scan_results:/tmp/enumeraga_output \
  gagarter/enumeraga_infra:latest \
  -t 192.168.1.100 -b
```

For the bounded example above:
```bash
docker run --rm --network host \
  -v ./enumeraga_output:/tmp/enumeraga_output \
  gagarter/enumeraga_infra:latest \
  -t 192.168.1.100 --ports 80,443 --rate 5 --concurrency 2 --max-runtime 900
```

### 2. enumeraga_cloud_scan

Run cloud security assessment using Docker container.

**Parameters:**
- `provider` (required, enum): `aws`, `azure`, `gcp`, `oci`, `aliyun`, `do`
- `output_dir` (optional, string): sub-folder name for this scan's results
- `subscription` (optional, string): **Azure** — scope the scan to one subscription ID
- `tenant`, `client_id`, `client_secret` (optional, strings): **Azure** — service principal auth
- `quiet` (optional, boolean): Suppress verbose output
- `verbose` (optional, boolean): Very verbose debugging output

**Azure authentication:**
- **Default — your own user:** run `az login` on the host first, then call with just `provider: "azure"`. ScoutSuite and Prowler reuse that session (`--cli` / `--az-cli-auth`) and run unattended. monkey365 is skipped (it has no Azure-CLI mode).
- **Service principal (optional):** pass `tenant` + `client_id` + `client_secret` to use an SP instead — this additionally enables monkey365's M365 / Entra ID inventory.
- **Scope:** always set `subscription` to the in-scope subscription. Without it, Prowler scans **every** subscription the identity can list.

**Example:**
```python
{
    "provider": "aws",
    "output_dir": "./aws_assessment"
}
```

**Docker Command Generated:**
```bash
docker run --rm \
  -v ./aws_assessment:/tmp/enumeraga_output \
  -v ~/.aws:/root/.aws:ro \
  gagarter/enumeraga_cloud:latest \
  aws
```

**Cloud Credentials:**
The server automatically mounts credential directories into the scan container:
- AWS: `~/.aws` → `/root/.aws` (read-only)
- Azure: `~/.azure` → `/root/.azure` (**read-write** — the Azure CLI refreshes its token mid-scan)
- GCP: `~/.config/gcloud` → `/root/.config/gcloud` (read-only)

### 3. enumeraga_pull_images

Pull latest Docker images from Docker Hub.

**Parameters:**
- `image` (optional, enum): `infra`, `cloud`, or `both` (default: `both`)

**Example:**
```python
{
    "image": "both"
}
```

**What it does:**
```bash
docker pull gagarter/enumeraga_infra:latest
docker pull gagarter/enumeraga_cloud:latest
```

### 4. enumeraga_check_docker

Verify Docker installation and image availability.

**Parameters:** None

**Example output:**
```
Docker Status Check
==================================================

✓ Docker installed: Docker version 24.0.7
✓ Docker daemon running

Image Status:
✓ Infrastructure image available: gagarter/enumeraga_infra:latest
✓ Cloud image available: gagarter/enumeraga_cloud:latest
```

## Usage Examples

For ready-to-use, copy-paste prompts that drive these tools from an LLM agent (Azure/AWS/GCP cloud scans, infrastructure scans, readiness check), see [PROMPTS.md](PROMPTS.md).

### First Time Setup

**User:** "Check if Enumeraga is ready"

**LLM uses:** `enumeraga_check_docker`

If images not found:

**LLM uses:** `enumeraga_pull_images` with `{"image": "both"}`

### Infrastructure Scan

**User:** "Scan 192.168.1.100 for open ports"

**LLM uses:** `enumeraga_infra_scan`
```python
{
    "target": "192.168.1.100"
}
```

**User:** "Do a comprehensive bruteforce scan of 10.0.0.50"

**LLM uses:** `enumeraga_infra_scan`
```python
{
    "target": "10.0.0.50",
    "brute": True,
    "verbose": True,
    "output_dir": "./comprehensive_scan"
}
```

### Cloud Security Assessment

**User:** "Assess my AWS security posture"

**LLM uses:** `enumeraga_cloud_scan`
```python
{
    "provider": "aws",
    "output_dir": "./aws_security_review"
}
```

## How It Works

1. **LLM Decision**: Claude/Gemini/Other LLM analyses user request and decides to use Enumeraga
2. **Tool Selection**: Chooses appropriate tool (infra_scan, cloud_scan, etc.)
3. **Docker Command**: MCP server builds Docker command with proper volumes
4. **Container Execution**: Docker pulls image (if needed) and runs container
5. **Results Capture**: Output is saved to mounted volume and returned to LLM
6. **Cleanup**: Container is removed (`--rm` flag), no traces left

## CI/CD Pipeline

The Docker images are automatically built and published via GitHub Actions:

- **Trigger**: Push to `main` or `develop`, or version tags (`v*.*.*`)
- **Builds**: Both `gagarter/enumeraga_infra` and `gagarter/enumeraga_cloud`
- **Tags Created**:
  - `latest` (from main branch)
  - `develop` (from develop branch)
  - Semantic versions (`1.0.0`, `1.0`, `1`)
  - Git SHA (`main-abc123`)

**Workflow:** `.github/workflows/docker-build.yml`

## Security Considerations

### Container Isolation

✅ **Benefits:**
- Scans run in isolated containers
- Host system not affected by scan tools
- Easy cleanup - just remove containers
- Reproducible environment

⚠️ **Important:**
- Infrastructure scans default to `--network host`; pass `network_mode` to join another container's network namespace instead
- Cloud credentials mounted read-only
- Output directory writable by container
- No sensitive data in container after removal

### Authorisation

**You are responsible for:**
- Having permission to scan targets
- Securing cloud credentials
- Reviewing scan outputs
- Following penetration testing rules of engagement

### Best Practices

1. **Dedicated Scan Machine**: Run from isolated VM or workstation
2. **Credential Management**: Use least-privilege cloud credentials
3. **Output Security**: Secure output directories with proper permissions
4. **Network Isolation**: Use separate network segment for scanning
5. **Audit Logs**: Keep records of what was scanned and when

## Troubleshooting

### "Docker not found"

Install Docker:
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# macOS (install Docker Desktop)
brew install --cask docker

# Windows (install Docker Desktop)
# Download from docker.com
```

### "Cannot connect to Docker daemon"

Start Docker:
```bash
sudo systemctl start docker  # Linux
# Or start Docker Desktop on macOS/Windows
```

### "Permission denied" accessing Docker

Add user to docker group:
```bash
sudo usermod -aG docker $USER
# Log out and back in
```

### "Image pull failed"

Check internet connection and Docker Hub status:
```bash
docker pull hello-world
```

### Cloud credentials not working

Verify credentials are configured:
```bash
# AWS
aws sts get-caller-identity

# Azure
az account show

# GCP
gcloud auth list
```

## Development

### Testing Locally

```bash
# Pull latest images
docker pull gagarter/enumeraga_infra:latest
docker pull gagarter/enumeraga_cloud:latest

# Test infrastructure scan
docker run --rm --network host \
  -v ./test_output:/tmp/enumeraga_output \
  gagarter/enumeraga_infra:latest \
  -t scanme.nmap.org

# Test cloud scan (requires credentials)
docker run --rm \
  -v ./test_output:/tmp/enumeraga_output \
  -v ~/.aws:/root/.aws:ro \
  gagarter/enumeraga_cloud:latest \
  aws
```

### Building Images Locally

```bash
# Infrastructure image
docker build -t enumeraga_infra:dev .

# Cloud image
docker build -f internal/cloud/Dockerfile -t enumeraga_cloud:dev .
```

### MCP Server Development

```bash
# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy mcp_server_enumeraga/

# Format code
black mcp_server_enumeraga/

# Test server manually
python3 mcp_server_enumeraga/server.py
```

## Project Structure

```
mcp-server-enumeraga/
├── mcp_server_enumeraga/
│   ├── __init__.py          # Package info
│   └── server.py            # Docker-based MCP server
├── pyproject.toml           # Python package config
├── README.md                # This file
└── setup.sh                 # Quick setup script

../.github/workflows/
└── docker-build.yml         # CI/CD for Docker images
```

## Performance

- **Image Size**: ~2-3GB each (with all tools installed)
- **Pull Time**: 5-10 minutes on first run (cached after)
- **Scan Speed**: Same as native Enumeraga (runs in container)
- **Startup Overhead**: ~2-5 seconds per scan

## Advantages Over Local Installation

| Aspect | Docker-Based | Local Install |
|--------|-------------|---------------|
| Dependencies | Zero (except Docker) | 20+ tools |
| Setup Time | ~10 min (image pull) | 30+ min (apt-get) |
| Updates | `docker pull` (2 min) | Reinstall all tools |
| Isolation | Complete | Shared system |
| Consistency | Guaranteed | Varies by OS |
| Cleanup | Container removal | Manual uninstall |
| Root Required | No | Yes (for nmap) |

## Links

- [Enumeraga GitHub](https://github.com/0x5ubt13/enumeraga)
- [Docker Hub - Infra Image](https://hub.docker.com/r/gagarter/enumeraga_infra)
- [Docker Hub - Cloud Image](https://hub.docker.com/r/gagarter/enumeraga_cloud)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

## License

MIT License - See main Enumeraga repository for details.
