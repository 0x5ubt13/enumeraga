# Security Policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch. Older tagged versions are not maintained, so please upgrade to the latest version before reporting.

| Version | Supported |
| ------- | --------- |
| latest (`main`) | yes |
| older releases | no |

## Reporting a vulnerability

Please report security issues privately rather than through public issues or pull requests.

The preferred channel is GitHub's private vulnerability reporting: open the repository's Security tab and choose "Report a vulnerability". This keeps the report confidential until a fix is ready.

Please include:
- the affected version or commit,
- a description of the issue and its impact,
- clear steps to reproduce, with a minimal proof of concept where possible.

You can expect an acknowledgement within a few working days. We will work with you on a fix and agree a disclosure timeline before any details are made public. Reporters who wish to be credited will be named in the release notes.

## Scope and responsible use

enumeraga is an authorised-testing tool: it launches active scans and runs other security binaries on your behalf. Only run it against infrastructure and cloud accounts that you have explicit permission to assess.

In scope for reports are issues in enumeraga itself, for example:
- command construction and argument handling where input reaches an executed tool,
- output path handling and file permissions,
- the MCP server's network exposure, Docker socket usage, and credential handling.

Out of scope:
- misuse of the tool against systems you are not authorised to test, which is a matter for you and the asset owner rather than a flaw in enumeraga,
- vulnerabilities in the third-party tools that enumeraga orchestrates, which should be reported to their respective projects,
- findings that require an already-compromised host or a privileged local account.

## Hardening notes for operators

- The MCP server has no authentication and can spawn containers through the host Docker socket, so reaching it is equivalent to root on the host. Bind it to localhost only (the default compose configuration uses `127.0.0.1`) and do not expose it to untrusted networks. Place an authenticating reverse proxy in front if remote access is required.
- Provide cloud credentials with the least privilege needed. For Azure, the Reader and Security Reader roles are sufficient for the default scans.
- Review scan output before sharing it, as it can contain sensitive details about the assessed environment.
