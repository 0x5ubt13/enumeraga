<img src="img/Enumeraga-logo_transparent.png" align="left" width="130" height="130"/>

# Enumeraga - Hack your initial scans

[![Go Report Card](https://goreportcard.com/badge/github.com/0x5ubt13/enumeraga)](https://goreportcard.com/report/github.com/0x5ubt13/enumeraga)
[![Maintainability](https://api.codeclimate.com/v1/badges/a26c3b3db97f4a3fdeef/maintainability)](https://codeclimate.com/github/0x5ubt13/enumeraga/maintainability)
[![GoDoc](https://godoc.org/github.com/0x5ubt13/enumeraga?status.svg)](https://godoc.org/github.com/0x5ubt13/enumeraga)
![License](https://img.shields.io/github/license/0x5ubt13/enumeraga?color=blue)
[![Go Version](https://img.shields.io/badge/Go-1.23+-blue.svg)](https://golang.org)

Automatic multiprocess Linux CLI tool that aims for a quick enumeration wrapping pentesting tools. Scan your target in 20 seconds! This is an attempt to develop a rich tool that leverages the nice features Go has to offer. Now available in containerised versions for both infrastructure and cloud scanning!

![Enumeraga demo gif](./img/enumeraga_demo_gif_v0.1.4-beta.gif)

## Features

- **Fast parallel infrastructure scanning** - Runs multiple tools concurrently with configurable worker pool (default: 20 concurrent tools)
- **Smart protocol detection** - Groups ports by protocol and runs appropriate enumeration tools
- **Graceful shutdown** - Ctrl+C cleanly terminates all running tools
- **Configurable timeouts** - Prevent long-running tools from blocking scans (default: 10 minutes)
- **Progress tracking** - Real-time progress counter showing completed/total tools
- **Docker support** - Containerised versions for both infrastructure and cloud scanning
- **Cloud scanning** - Supports the major Cloud Service Providers

## Wrapped Tools

### Infrastructure Scanning

| Category | Tools |
|----------|-------|
| **Port Scanning** | Nmap |
| **Web Enumeration** | Nikto, Dirsearch, Ffuf, Gobuster, WPScan, WhatWeb, WafW00f, CeWL |
| **SMB/NetBIOS** | CrackMapExec, SMBMap, Enum4linux-ng, Nmblookup, Nbtscan-unixwiz |
| **LDAP** | Ldapsearch |
| **SNMP** | SNMPWalk, Onesixtyone, Braa |
| **Database** | ODAT (Oracle), Hydra (MySQL brute) |
| **SSH** | SSH-Audit, Hydra |
| **SSL/TLS** | Testssl |
| **Other** | Metasploit, Ident-user-enum, Responder-RunFinger, RPCDump, Rusers, Rwho, Nuclei |
| **Brute Force** | Hydra (FTP, SSH, MySQL, RDP) |

### Cloud Scanning

| Provider | Tools | Scan order |
|----------|-------|------------|
| **AWS** | ScoutSuite, Prowler, CloudFox, Nuclei | sequential |
| **Azure** | monkey365, ScoutSuite, Prowler, CloudFox, Nuclei | sequential |
| **GCP** | gcp_scanner, gcp-iam-brute, ScoutSuite, Prowler, CloudFox, Nuclei | sequential |
| **OCI** | ScoutSuite | sequential |
| **AliCloud** | ScoutSuite | sequential |
| **DigitalOcean** | ScoutSuite | sequential |
| **Kubernetes** | kubenumerate | — |

Tools run sequentially per provider to avoid cloud API rate limiting. Inventory tools run first (`gcp_scanner`, `monkey365`), then IAM permission testing (`gcp-iam-brute`), then compliance/misconfiguration scanners, and finally external template checks (Nuclei).

## Usage

### Enumeraga Infra

Give `enumeraga infra` either a single IP address or a file containing a list of IPs. Sit back, relax, and laugh maniacally while it handles all enumeration for you, going through every open port on your target on your behalf:

    enumeraga infra -h

                                                            dev
    __________                                    ______________________ 
    ___  ____/__________  ________ __________________    |_  ____/__    |
    __  __/  __  __ \  / / /_  __ `__ \  _ \_  ___/_  /| |  / __ __  /| |
    _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ / /_/ / _  ___ |
    /_____/  /_/ /_/\__,_/ /_/ /_/ /_/\___//_/    /_/  |_\____/  /_/  |_|
                                by 0x5ubt13

    Usage: enumeraga infra [OPTIONS]

    Options:
    -b, --brute          Activate all fuzzing and bruteforce in the tool
    -g, --gentle         Throttle scans and tools for a gentler scan profile
    -h, --help           Display this help and exit
    -i, --install        Only try to install pre-requisite tools and exit
    -n, --nmap-only      Activate nmap scans only and ignore all other tools
    -o, --output DIR     Select a different base folder for output (default: /tmp/enumeraga_output)
    -p, --top-ports N    Run port sweep with nmap --top-ports=N
    -q, --quiet          Don't print the banner and decrease overall verbosity
    -r, --range CIDR     Specify a CIDR range to use tools for whole subnets
    -t, --target TARGET  Specify target single IP / List of IPs file (required)
    -T, --timeout MINS   Maximum time in minutes for long-running tools (default: 10)
    -V, --vv             Flood your terminal with plenty of verbosity!


    Examples:
    enumeraga -i
    enumeraga -bq -t 10.10.11.230
    enumeraga -V -r 10.129.121.0/24 -t 10.129.121.60
    enumeraga -t targets_file.txt -r 10.10.8.0/24
    exit status 1


#### Examples

```bash
# Basic scan of a single target
sudo enumeraga infra -t 192.168.1.100

# Scan with brute force tools enabled
sudo enumeraga infra -t 192.168.1.100 -b

# Scan with verbose output
sudo enumeraga infra -t 192.168.1.100 -V

# Scan with 5-minute timeout for long-running tools
sudo enumeraga infra -t 192.168.1.100 -T 5

# Scan top 1000 ports only
sudo enumeraga infra -t 192.168.1.100 -p 1000

# Scan a CIDR range
sudo enumeraga infra -t 192.168.1.100 -r 192.168.1.0/24

# Scan multiple targets from a file
sudo enumeraga infra -t targets.txt

# Quiet mode (minimal output)
sudo enumeraga infra -t 192.168.1.100 -q
```

### Enumeraga Cloud

Give `enumeraga cloud` a CSP, and depending on which, a couple more parameters for it to go through your fave cloud enumeration tools. Just like enumeraga infra, sit back, relax, and laugh maniacally while it handles all enumeration for you, going through every relevant cloud tool on your behalf:

    enumeraga cloud -h

                                                            dev
    __________                                    ______________________ 
    ___  ____/__________  ________ __________________    |_  ____/__    |
    __  __/  __  __ \  / / /_  __ `__ \  _ \_  ___/_  /| |  / __ __  /| |
    _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ / /_/ / _  ___ |
    /_____/  /_/ /_/\__,_/ /_/ /_/ /_/\___//_/    /_/  |_\____/  /_/  |_|
                                by 0x5ubt13

    Usage: enumeraga cloud [OPTIONS] <provider>
    
    Cloud Providers:
      aws, amazon          Amazon Web Services
      azure, az            Microsoft Azure
      gcp, gcloud, g       Google Cloud Platform
      oci, oracle          Oracle Cloud Infrastructure
      aliyun, alibaba      Alibaba Cloud
      do, digitalocean     DigitalOcean
    
    Options:
      -c, --creds FILE         Path to credentials file (e.g. GCP service     account JSON)
          --tenant ID          Azure Tenant ID (service principal auth, used     by monkey365)
          --client-id ID       Azure Client/App ID (service principal auth,     used by monkey365)
          --client-secret SEC  Azure Client Secret (service principal auth,     used by monkey365)
          --iam-brute-email EMAIL  Override service account email for     gcp-iam-brute (GCP only)
          --no-iam-brute           Disable gcp-iam-brute permission     enumeration (GCP only)
      -h, --help               Display this help and exit
      -o, --output DIR         Select a different base folder for output     (default: /tmp/enumeraga_output)
      -q, --quiet              Don't print the banner and decrease overall     verbosity
      -V, --vv                 Flood your terminal with plenty of verbosity!
    
    Examples:
     enumeraga cloud aws
     enumeraga cloud gcp --creds sa-key.json --project <project-id>
     enumeraga cloud azure --tenant <tenant-id> --client-id <app-id>     --client-secret <secret>

#### Examples

```bash
# AWS — uses ~/.aws credentials
enumeraga cloud aws

# Azure — Application Default Credentials
enumeraga cloud azure

# Azure — service principal (required for monkey365 full M365 + Entra ID coverage)
enumeraga cloud azure --tenant <tenant-id> --client-id <app-id> --client-secret <secret>

# GCP — Application Default Credentials (gcp-iam-brute runs automatically)
enumeraga cloud gcp

# GCP — service account key file with explicit project
enumeraga cloud gcp --creds /path/to/sa-key.json --project <project-id>

# GCP — override the service account email used by gcp-iam-brute
enumeraga cloud gcp --creds /path/to/sa-key.json --project <project-id> --iam-brute-email sa@project.iam.gserviceaccount.com

# GCP — skip gcp-iam-brute (e.g. if testIamPermissions is restricted by policy)
enumeraga cloud gcp --creds /path/to/sa-key.json --project <project-id> --no-iam-brute

# Kubernetes
enumeraga cloud k8s
```

## Installation

### Requirements

- Go 1.23 or later
- Linux (Kali recommended for tool availability)
- Root/sudo privileges (for nmap privileged scans)

### Build from source

```bash
git clone https://github.com/0x5ubt13/enumeraga.git
cd enumeraga
go build -o enumeraga main.go
sudo ./enumeraga infra -h
```

### Quick install (download latest release)

```bash
sudo mkdir -p /opt/enumeraga
sudo curl -L https://github.com/0x5ubt13/enumeraga/releases/latest/download/enumeraga -o /opt/enumeraga/enumeraga
sudo chmod +x /opt/enumeraga/enumeraga
sudo ln -s /opt/enumeraga/enumeraga /usr/bin/enumeraga
enumeraga -h
```

### Containerised version - Infrastructure Scanning

Build and run the infrastructure scanner in a container:

```bash
# Build the image
docker build -t gagarter/enumeraga_infra .

# ...Or use the latest built image on Dockerhub:
docker pull gagarter/enumeraga_infra

# Run against a single target
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -t 192.168.1.99

# Run with bruteforce enabled
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v ./output:/tmp/enumeraga_output gagarter/enumeraga_infra -t 192.168.1.99 -b

# Run against targets from a file
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v ./output:/tmp/enumeraga_output -v ./targets.txt:/targets.txt gagarter/enumeraga_infra -t /targets.txt
```
**Note:** Use `--network host --cap-add NET_RAW --cap-add NET_ADMIN` for nmap privileged scans to work correctly in Docker.

#### M-series MacOS (ARM64)!

If you want all the goodies of Enumeraga without having to emulate an entire x86_64 virtual machine, I gotchu! Use this:

```bash
docker run --privileged --platform linux/amd64 --network host -v ./enumeraga_output:/tmp/enumeraga_output gagarter/enumeraga_infra -t 192.168.1.99
```

### Containerised version - Cloud Scanning

Build and run the cloud scanner in a container:

```bash
# Build the image (MUST run from repo root)
docker build -f internal/cloud/Dockerfile -t gagarter/enumeraga_cloud .

# ... Or use the latest built image on Dockerhub:
docker pull gagarter/enumeraga_cloud

# Run against AWS (mount AWS credentials)
docker run -v ~/.aws:/root/.aws -v ./output:/tmp/enumeraga_output gagarter/enumeraga_cloud aws

# Run against Azure with ADC (mount Azure CLI session)
docker run -v ~/.azure:/root/.azure -v ./output:/tmp/enumeraga_output gagarter/enumeraga_cloud azure

# Run against Azure with a service principal (required for monkey365 full coverage)
docker run -v ./output:/tmp/enumeraga_output gagarter/enumeraga_cloud azure \
  --tenant <tenant-id> --client-id <app-id> --client-secret <secret>

# Run against GCP using Application Default Credentials
docker run -v ~/.config/gcloud:/root/.config/gcloud -v ./output:/tmp/enumeraga_output gagarter/enumeraga_cloud gcp

# Run against GCP with a service account key file
docker run -v ./sa-key.json:/creds/sa-key.json -v ./output:/tmp/enumeraga_output \
  gagarter/enumeraga_cloud gcp --creds /creds/sa-key.json

# Run against GCP with a service account key and explicit project ID
docker run -v ./sa-key.json:/creds/sa-key.json -v ./output:/tmp/enumeraga_output \
  gagarter/enumeraga_cloud gcp --creds /creds/sa-key.json --project <project-id>

# Run against GCP, skipping gcp-iam-brute
docker run -v ./sa-key.json:/creds/sa-key.json -v ./output:/tmp/enumeraga_output \
  gagarter/enumeraga_cloud gcp --creds /creds/sa-key.json --project <project-id> --no-iam-brute
```

**Key points for cloud scanning:**
- Mount the appropriate credentials directory for your target cloud provider
- Mount an output directory to persist scan results: `-v ./output:/tmp/enumeraga_output`
- Supports AWS, Azure, GCP, OCI, AliCloud, and DigitalOcean
- **Azure:** pass `--tenant`, `--client-id`, and `--client-secret` for service principal auth — required for [monkey365](https://github.com/silverhack/monkey365) to enumerate M365, Entra ID, Exchange Online, and SharePoint alongside Azure resources
- **GCP:** pass `--creds /path/to/sa-key.json` to authenticate with a service account key file; without it, [gcp_scanner](https://github.com/google/gcp_scanner) and other tools fall back to Application Default Credentials
- **GCP:** [gcp-iam-brute](https://github.com/hac01/gcp-iam-brute) runs automatically after `gcp_scanner` to actively test IAM permissions via the `testIamPermissions` API; use `--no-iam-brute` to disable it or `--iam-brute-email` to override the detected service account email

## Flow chart

```mermaid
flowchart TD
    START([START]) --> INFRA_MODE & CLOUD_MODE

    %% ─────────────────────────────────────
    %% INFRA COLUMN
    %% ─────────────────────────────────────
    subgraph INFRA["infra"]
        direction TB
        INFRA_MODE(["enumeraga infra"])

        subgraph INFRA_CHECKS["Checks phase"]
            direction TB
            TOOL_CHECK{Missing tool?}
            INSTALL_TOOL([Install tool])
            MULTI{Multiple targets?}
            FOR_TARGET([For each target])
            SINGLE_IP{Single IP}

            TOOL_CHECK -- yes --> INSTALL_TOOL --> TOOL_CHECK
            TOOL_CHECK -- all ok --> MULTI
            MULTI -- yes --> FOR_TARGET --> SINGLE_IP
            MULTI -- no --> SINGLE_IP
        end

        subgraph INFRA_ENUM["Enumeration phase"]
            direction TB
            SWEEP([Sweep open ports])
            ALL_PORTS([All open ports\nNmap scan])
            PARSE([Parse open protocols])
            FOR_PROTO{For each protocol}
            PROTO_NMAP([Dedicated protocol\nNmap scan])
            PROTO_TOOLS([Run specific\nenumeration tools])
            INFRA_DONE([Finish in parallel])

            SWEEP --> ALL_PORTS & PARSE
            PARSE --> FOR_PROTO
            FOR_PROTO --> PROTO_NMAP & PROTO_TOOLS
            PROTO_NMAP & PROTO_TOOLS --> INFRA_DONE
        end

        INFRA_MODE --> INFRA_CHECKS
        SINGLE_IP --> INFRA_ENUM
    end

    %% ─────────────────────────────────────
    %% CLOUD COLUMN
    %% ─────────────────────────────────────
    subgraph CLOUD["cloud"]
        direction TB
        CLOUD_MODE(["enumeraga cloud"])

        subgraph CLOUD_CHECKS["Checks phase"]
            direction TB
            PROVIDER{Provider?}
            VALIDATE([Validate credentials])
            AUTH([Auth preflight\ngcloud / ADC / SP])

            PROVIDER --> VALIDATE --> AUTH
        end

        subgraph CLOUD_ENUM["Enumeration phase — sequential"]
            direction TB
            PSWITCH{Provider switch}

            subgraph GCP_PIPE["GCP"]
                direction TB
                GCP1([gcp_scanner\ninventory])
                GCP2([gcp-iam-brute\nIAM permissions])
                GCP3([ScoutSuite\ncompliance])
                GCP4([Prowler\nCIS checks])
                GCP5([CloudFox\ndeep enum])
                GCP6([Nuclei\nexternal checks])
                GCP1 --> GCP2 --> GCP3 --> GCP4 --> GCP5 --> GCP6
            end

            subgraph AZ_PIPE["Azure"]
                direction TB
                AZ1([monkey365\nM365 + Entra ID])
                AZ2([ScoutSuite\ncompliance])
                AZ3([Prowler\nCIS checks])
                AZ4([CloudFox\ndeep enum])
                AZ5([Nuclei\nexternal checks])
                AZ1 --> AZ2 --> AZ3 --> AZ4 --> AZ5
            end

            subgraph AWS_PIPE["AWS / other"]
                direction TB
                AWS1([ScoutSuite\ncompliance])
                AWS2([Prowler\nCIS checks])
                AWS3([CloudFox\ndeep enum])
                AWS4([Nuclei\nexternal checks])
                AWS1 --> AWS2 --> AWS3 --> AWS4
            end

            subgraph K8S_PIPE["k8s"]
                direction TB
                K8S1([kubenumerate])
            end

            PSWITCH -- GCP --> GCP_PIPE
            PSWITCH -- Azure --> AZ_PIPE
            PSWITCH -- AWS/other --> AWS_PIPE
            PSWITCH -- k8s --> K8S_PIPE

            OUTPUT([Write output reports])
            GCP_PIPE & AZ_PIPE & AWS_PIPE & K8S_PIPE --> OUTPUT
        end

        CLOUD_MODE --> CLOUD_CHECKS
        AUTH --> PSWITCH
    end
```

## Protocols Enumerated

- FTP (20-21)
- SSH (22)
- SMTP (25, 465, 587)
- DNS (53)
- Finger (79)
- HTTP/HTTPS (80, 443, 8080, 8443)
- Kerberos (88)
- POP3/IMAP (110, 143, 993, 995)
- MSRPC (135, 593)
- NetBIOS/SMB (137-139, 445)
- SNMP (161)
- LDAP (389, 636)
- R-Services (512-514)
- Rsync (873)
- NFS (2049)
- MySQL (3306)
- RDP (3389)
- WinRM (5985-5986)
- Webmin/NDMP (10000)

## Development

### Running Tests

```bash
# Quick tests
make test-short

# Full test suite
make test-verbose

# With coverage
make test-coverage

# Linting
golangci-lint run
```

### Project Structure

```
enumeraga/
├── main.go                    # Entry point
├── internal/
│   ├── checks/               # CLI argument parsing
│   ├── commands/             # Tool execution wrappers
│   ├── cloud/                # Cloud scanning logic
│   ├── cloudScanner/         # Cloud provider handlers
│   ├── config/               # Configuration management
│   ├── infra/                # Infrastructure scanning logic
│   ├── portsIterator/        # Protocol-specific handlers
│   ├── scans/                # Nmap wrapper functions
│   ├── types/                # Type definitions
│   └── utils/                # Shared utilities
├── Dockerfile                # Infrastructure container
└── internal/cloud/Dockerfile # Cloud scanning container
```

## The motivation

Working as pentesters, or playing CTFs, or fiddling around with practice labs, we come across the same initial phases of recon and enumeration over and over again. Or how many times we have to spawn a new clean testing machine and reinstall everything? I thought it would be an amazing opportunity to practice my coding skills if I automated the installation process and the initial tools that I always run in new engagements. Then, after seeing the first results in Bash (if you're curious: [autoEnum](https://github.com/0x5ubt13/autoenum)), I liked what I had done, and I kept adding on more features, until the Bash script grew up so much that I started thinking: "what if I actually use Go and compile this to a binary? Would I be able to pull it off...?" And, well, I'm a sucker for a good challenge if learning is a joyful side effect.

## The name

Doing a casual search looking for my tool, I found out that the name "autoEnum" was already taken by a tool also written in Bash doing similar things developed years ago, so I decided to give my tool a different name. I thought of this version as the third iteration of the program, being the first one [autoNmap](https://github.com/0x5ubt13/myToolkit/tree/main/autoNmap), and the second one [autoEnum](https://github.com/0x5ubt13/autoenum).

The next name had to be some sort of third iteration. It was quite fun and creative trying to come up with a new name, and after brainstorming several possibilities, I tried Pokemon, but I could not think of cool name for a second "evolution" using "auto" as a prefix. It made sense borrowing from the spell naming convention of the Final Fantasy universe, which also includes a G in the third version of their spells, and so to honour the decision to use Go, and develop the third stage of a script that does automatic enumeration for you, `Enumeraga` was born.

## Disclaimer

This tool has to run as `root`, and despite my nickname, it's not precisely a subtle tool! Contrarily, it will create a ton of noise. Given its aggressive nature, please ensure you know what you're doing before launching it, and of course double-check you have absolute permission to enumerate your target(s).

## Similar tools out there

I am aware other enumeration tools exist, but this one aims to be very fast and concise. So far by the current testing times, Enumeraga is able to run its core logic in about 20 to 60 seconds per host, depending on the number of ports open.

Enumeraga's bottleneck is clearly identified at the port sweeping phase. Once that's out the way the rest of logic gets triggered almost instantly, grouping up several ports in their respective protocols and targeting protocols for enumeration instead.

If you have new ideas to implement in this tool or have any feedback please reach out!

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## To Do

- [x] Update flow chart to include the new Cloud enum flow
- [ ] Test thoroughly on various targets
- [ ] Release v1.0
- [ ] Add a flag to pass `vhosts` and functionality to use them
- [ ] Link each wrapped tool on README to their official repos
- [ ] Add more enumeration tools

Happy enumeration!
