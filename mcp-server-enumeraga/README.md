# Enumeraga MCP Server (Docker-Based)

Model Context Protocol (MCP) server for Enumeraga that uses **Docker containers** for complete isolation and portability. No need to install Enumeraga or its dependencies locally - just Docker!

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

- **Python 3.10+**
- **Docker** installed and running
- Internet connection (to pull Docker images)

## Installation

```bash
cd mcp-server-enumeraga

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install the MCP server
pip install -e .
```

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
- `output_dir` (optional, string): Output directory (default: ./enumeraga_output)
- `brute` (optional, boolean): Enable bruteforce/fuzzing tools
- `top_ports` (optional, string): Scan only top N ports (e.g., "100")
- `quiet` (optional, boolean): Suppress verbose output
- `verbose` (optional, boolean): Very verbose debugging output

**Example:**
```python
{
    "target": "192.168.1.100",
    "brute": True,
    "output_dir": "./scan_results"
}
```

**Docker Command Generated:**
```bash
docker run --rm --network host \
  -v ./scan_results:/tmp/enumeraga_output \
  gagarter/enumeraga_infra:latest \
  -t 192.168.1.100 -b
```

### 2. enumeraga_cloud_scan

Run cloud security assessment using Docker container.

**Parameters:**
- `provider` (required, enum): `aws`, `azure`, `gcp`, `oci`, `aliyun`, `do`
- `output_dir` (optional, string): Output directory (default: ./enumeraga_output)
- `quiet` (optional, boolean): Suppress verbose output
- `verbose` (optional, boolean): Very verbose debugging output

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
The server automatically mounts credential directories:
- AWS: `~/.aws` → `/root/.aws` (read-only)
- Azure: `~/.azure` → `/root/.azure` (read-only)
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
- Infrastructure scans use `--network host` (required for nmap)
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
