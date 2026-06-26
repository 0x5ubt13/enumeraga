# Enumeraga MCP — prompt collection

Ready-to-use prompts for driving the enumeraga MCP tools from an LLM agent (omp, Claude Desktop, etc.). Copy a block, replace the `<PLACEHOLDERS>`, and paste it in.

These assume the `enumeraga` MCP server is **connected** (HTTP at `http://localhost:9000/mcp/` in container mode, or the stdio command in local mode). If the agent says it cannot find the server, the issue is the connection, not the prompt: restart the agent session so it reloads its MCP config, confirm the `enumeraga-mcp` container is up, then retry. No prompt can reach a server the session never connected to.

Every template shares the same invariants:
- Call the named tool **directly** — never tell the agent to look for a binary, a local install, raw `docker` commands, or a different server.
- After a scan the tool prints `Results saved to: <path>`. **Move** (`mv`, not `cp`) the contents into the working directory so the shared results directory keeps no client data.
- Never overwrite, edit, or delete existing files in the working directory.
- Stop and report on any auth/setup error — do not work around it or create credentials.
- Scans run for many minutes. A client-side timeout does **not** mean failure — never re-invoke the tool (that spawns a duplicate). Use `detach: true` and poll `docker logs <id>`, or wait. The server also refuses duplicate concurrent scans and names the running container.
- While a scan container is **still listed by `docker ps`, it is alive — treat it as running, not stalled or dead**, even if its logs are quiet for several minutes. Prowler in particular runs ~187 checks largely silently before writing its report, so long gaps with no new log lines are normal. Do **not** `docker stop`/`kill` it, do **not** declare the scan failed, and do **not** re-run the tool. Only conclude it finished when the container disappears from `docker ps` (it is `--rm`).

---

## Readiness check

```text
Using the enumeraga MCP server you are connected to, call enumeraga_check_docker and tell me whether Docker is running and the enumeraga_infra and enumeraga_cloud images are present. If an image is missing, call enumeraga_pull_images to fetch it. Do not run any scan yet.
```

---

## Azure cloud scan (scoped, as the signed-in user)

```text
You have an MCP server named enumeraga connected over HTTP, exposing the tool enumeraga_cloud_scan. Call that tool directly — do not search for a binary, a local install, docker commands, or another server. ./AGENTS.md in this directory has supporting hints; read it first.

Task: run an Azure cloud security assessment of subscription <SUBSCRIPTION_ID> only.

1. Before anything, read ./AGENTS.md and every existing az_*.json / scope file already in this directory for context. I have already run the az commands. Do not re-run them or send new az commands unless something needed is genuinely missing, and never overwrite, edit, or delete any existing file in this directory.
2. Call enumeraga_cloud_scan with exactly: provider="azure", subscription="<SUBSCRIPTION_ID>", detach=true. Do not pass — or ask me for — tenant, client_id, or client_secret. Authentication uses the host's existing az login. Do not create a service principal.
3. The tool returns immediately with a Container ID and the results path. The scan then runs in the background for several minutes — do NOT call the tool again (a second call is a duplicate). Poll progress with `docker logs --tail 30 <ID>`; the scan is finished once `docker ps` no longer lists that container.
4. Once finished, move (mv, not cp) the contents of the results path into the current directory, then tell me the local location and summarise the findings.

Hard constraints: stay strictly inside subscription <SUBSCRIPTION_ID>; never scan another subscription or tenant. A timeout or slow response is not a failure — never re-invoke the scan tool. If the tool reports an az login / setup error, stop and tell me — do not work around it, mount credentials, or create a service principal.
```

### Azure with a service principal (only when explicitly required)

```text
As above, but authenticate with the service principal I provide: call enumeraga_cloud_scan with provider="azure", subscription="<SUBSCRIPTION_ID>", detach=true, tenant="<TENANT_ID>", client_id="<CLIENT_ID>", client_secret="<CLIENT_SECRET>". This also enables monkey365's M365 / Entra ID inventory. Forward the secret only to the tool; never print it. Same detached poll-then-move flow, scope, and stop-on-error rules apply.
```

---

## AWS cloud scan

```text
You are connected to the enumeraga MCP server; call enumeraga_cloud_scan directly. Read ./AGENTS.md first.

Task: run an AWS cloud security assessment using my mounted credentials.

1. Read any existing context files in this directory; do not overwrite, edit, or delete them.
2. Call enumeraga_cloud_scan with provider="aws", detach=true (add profile="<AWS_PROFILE>" only if I name a specific profile). Credentials come from the mounted ~/.aws — do not ask me to paste keys.
3. The tool returns immediately with a Container ID and results path; the scan runs in the background. Do NOT call the tool again. Poll `docker logs --tail 30 <ID>`; done when `docker ps` no longer lists it. Then mv the contents of the results path into the current directory and summarise the findings.

If the tool reports a credentials error, stop and tell me. A timeout is not a failure — never re-invoke the tool.
```

---

## GCP cloud scan

```text
You are connected to the enumeraga MCP server; call enumeraga_cloud_scan directly. Read ./AGENTS.md first.

Task: run a GCP cloud security assessment.

1. Read any existing context files in this directory; do not overwrite, edit, or delete them.
2. Call enumeraga_cloud_scan with provider="gcp", detach=true. Credentials come from the mounted gcloud config / application default credentials — do not ask me to paste a key.
3. The tool returns immediately with a Container ID and results path; the scan runs in the background. Do NOT call the tool again. Poll `docker logs --tail 30 <ID>`; done when `docker ps` no longer lists it. Then mv the contents of the results path into the current directory and summarise the findings.

If the tool reports an auth error, stop and tell me. A timeout is not a failure — never re-invoke the tool.
```

---

## Infrastructure scan

```text
You are connected to the enumeraga MCP server; call enumeraga_infra_scan directly — do not search for a binary or another server. Read ./AGENTS.md first.

Task: enumerate <TARGET> (a single IP, hostname, or comma-separated list). I have authorisation to scan this target.

1. Read any existing context files in this directory; do not overwrite, edit, or delete them.
2. Call enumeraga_infra_scan with target="<TARGET>", detach=true. Add brute=true only if I ask for bruteforce/fuzzing, and top_ports="<N>" only if I ask to limit the port range.
3. The tool returns immediately with a Container ID and results path; the scan runs in the background. Do NOT call the tool again. Poll `docker logs --tail 30 <ID>`; done when `docker ps` no longer lists it. Then mv the contents of the results path into the current directory and summarise the findings.

Stay strictly to <TARGET>; do not scan anything else. A timeout is not a failure — never re-invoke the tool. Stop and tell me on any error.
```
