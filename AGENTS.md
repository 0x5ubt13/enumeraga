# AGENTS.md

## The word "enumeraga"

**"enumeraga" is the proper name of this project** — a Go-based security reconnaissance CLI. Whenever the user writes or says "enumeraga" they mean this tool. It is never the verb "enumerate" or "enumerating", and it must never be auto-corrected, paraphrased, or treated as a typo. Reproduce it verbatim.

## The enumeraga MCP server

An MCP server named **`enumeraga`** is configured for this workspace over HTTP at `http://localhost:9000/mcp/`, running as a Docker container (`enumeraga-mcp`) that spawns sibling scan containers. It has **no access to the current working directory** — scan output is written to a fixed host results directory and the tool reports the exact path back (`Results saved to: <path>`). When the user asks to run a scan, pull images, or check the tool, prefer these MCP tools over shelling out.

**After a scan completes: `mv` the results into the current working directory.** Take the path from the tool's `Results saved to: <path>` line and move its contents into the folder you were summoned in (e.g. `mv <path> ./`), then report the new local location. Use `mv`, not `cp` — the shared results directory must not retain client data after the move.

The tools:

- **`enumeraga_infra_scan`** — infrastructure enumeration against a target IP, hostname, or targets file (nmap plus specialised tools, run in a container).
- **`enumeraga_cloud_scan`** — cloud-provider enumeration (aws, azure, gcp, etc). For **Azure**, scan unattended as the user's signed-in `az login` session: call it with just `provider: "azure"`. Do **not** ask for `tenant`, `client_id` or `client_secret` — those are an optional service principal, used only if the user explicitly supplies one (it additionally enables monkey365). If ScoutSuite/Prowler fail inside the scan container with "Please run 'az login'", that is a **setup** problem, not a choice for the user: the host has no live `az login`, or the cloud scan image lacks the Azure CLI. Do **not** offer to create a service principal or to mount credentials yourself — the MCP tool cannot accept mount/env overrides from here. Report plainly that the operator must `az login` on the host (and, if needed, rebuild the cloud image `gagarter/enumeraga_cloud:latest`), then re-run with `provider: "azure"`.
- **`enumeraga_pull_images`** — warm-pull the cached scan container images.
- **`enumeraga_check_docker`** — check Docker availability.

**Scans are long — never retry.** A cloud or infra scan can run for many minutes, longer than the MCP client's response timeout. A timeout does **not** mean the scan failed — the container keeps running. Do **not** re-invoke the scan tool: a second call would be a duplicate. Either pass `detach: true` to start it in the background and poll with `docker logs <id>`, or wait. The server refuses a duplicate while an identical scan is running and tells you the container name; if you see that, wait or check its logs — do not keep calling.

**A running container is alive, not stalled.** While a scan container is still listed by `docker ps`, treat it as running even if its logs are quiet for several minutes — prowler runs ~187 checks largely silently before writing its report. Do not `docker stop`/`kill` it, do not declare the scan dead or failed, and do not re-run the tool. Conclude it has finished only when the container is gone from `docker ps` (it is `--rm`). The scan image's own watchdog already kills genuinely hung tools, so leave that judgement to it.

**Azure scope safety:** always pass `subscription` to `enumeraga_cloud_scan` for Azure, set to the single in-scope subscription. If omitted, Prowler scans *every* subscription the signed-in user can list — which is almost certainly out of scope and a breach of the engagement boundary. If the user has not named one, take the active subscription from `az account show`, confirm it is in scope, then pass it.

If a tool call cannot connect, the `enumeraga-mcp` container is probably not running. Start it from `mcp-server-enumeraga/` with `docker compose up -d` (it binds port 9000), then retry.
