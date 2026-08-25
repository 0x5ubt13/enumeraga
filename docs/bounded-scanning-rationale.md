# Why bounded scanning exists

This document records the reasoning behind `--bounded` and its companion flags. The flags themselves, and the per-tool rate table, are documented in the README; this is the design rationale, kept separately so that the decisions and their trade-offs survive after the diff stops being fresh.

## The requirement

The request came from an automated caller: a retest runner that validates every outbound action against a signed scope manifest before it fires. Its rules of engagement require that every action be bounded by an explicit port list, a request rate, a concurrency limit and a wall-clock timeout, and that all of it be logged. Its position was that it would rather not call enumeraga at all than call it unlogged.

Two consequences followed from how that caller works. Approval is bound to a hash of the exact request, so the scan it validates must be the scan enumeraga runs — adaptive behaviour is legitimate, but it must not be invisible. And an argument that cannot be honoured must fail loudly, because a silently ignored rate cap is worse than an error: it produces a run that has to be treated as unbounded after the fact, which is the one outcome the manifest exists to prevent.

## The tension, and how it was resolved

Enumeraga's value is that it is one lazy command away from full enumeration. Point it at a host and it finds everything it can. A strict scan contract is the opposite instinct: name your ports, cap your rate, refuse anything not asked for.

Rather than pick a side, the bounds are opt-in. `--bounded` gates the whole contract, and it is implied by any of `--ports`, `--rate`, `--concurrency` or `--max-runtime` so that bounds never have to be paired with a mode flag.

**The default run is unchanged.** `sudo enumeraga infra -t <ip>` performs the same scan it did before this work. That is not an aspiration, it is checkable: every scope gate returns "in scope" when no port list is present, the rate helper falls through to the previous `--min-rate` behaviour when no rate is set, and the bounded sweep is only reached behind an explicit port-list test. Anyone auditing this should verify it rather than take the claim on trust.

## Decisions worth recording

**`--ports` means those ports and no others.** No discovery sweep, no re-sweep, no UDP scan unless a `U:` entry asks for one, and no extra port appended for OS fingerprinting. Enumeraga scans exactly what was named and then enumerates whichever of those turn out to be open. The alternative — sweep first, then filter — would have been easier to build and would have quietly touched ports nobody authorised.

**Handler port clusters are filtered, not trusted.** Several protocol handlers scanned a whole cluster regardless of which port dispatched them: SMB reached for 137, 138, 139 and 445; MSRPC for 135 and 593; R-services for 512 to 514; SNMP for 161, 162, 10161 and 10162. Each is now narrowed to whichever of those ports the caller actually authorised. This was the largest single source of unauthorised traffic and none of it was visible from the command line.

**Protocol is part of the scope, not just the port number.** The open-port list that the dispatcher iterates merges the TCP and UDP results with no protocol tag, so a port found open over UDP was routed by its number alone and could pull in TCP work. Nmap scans now honour the `T:`/`U:` prefix, so `--ports U:53` produces no TCP probe of port 53, and the aggressive scan — which is TCP — omits any port authorised only for UDP.

**Tools are classified by what they can actually honour.** A rate cap means different things to different tools, and pretending otherwise would have been the silent-failure mode the caller specifically objected to. Four classes: tools with genuine rate or delay control; tools that expose only a thread count, which is a concurrency limit and not a rate; tools that issue roughly one request, where a cap is meaningless; and tools with no throttle at all, which are skipped under `--rate` unless `--allow-unthrottled-tools` is passed. A tool with no table entry falls into the last class, so adding a tool without classifying it causes a visible skip rather than an invisible uncapped run.

**A rate cap must never loosen an existing throttle.** An early version of the flag-rewriting logic raised `dirsearch -t 10` to `-t 50` when given `--rate 50`, and did the same to hydra and wpscan. A bounded run was more aggressive than an unbounded one. Caps are now only ever tightened.

**`--gentle` with `--rate` is rejected, not merged.** Gentle mode is itself a rate and concurrency preset, and its per-tool values can be looser than an explicit rate. Composing the two would have meant deciding silently which won. The combination is refused at startup with a message naming both flags.

**A wall-clock stop produces results, not a discard.** `--max-runtime` kills the run and its child processes and exits 124, following the convention of GNU `timeout`, after printing whatever completed. Partial results from a bounded run are valid; throwing them away would punish the caller for setting a limit.

## Limits worth being honest about

Some tools take no port argument at all. They connect to whatever port their protocol implies, and `--ports` cannot constrain them — `nmblookup`, `enum4linux-ng`, `netexec`, `smbmap`, `snmpwalk`, `showmount` and `ssh-audit` all behave this way, and that list should not be assumed complete. With `--ports 445`, the SMB suite may still reach 139.

Non-nmap tools are held to the authorised port numbers but not to the protocol, because most speak one protocol by construction and expose no argument to constrain it.

A caller who needs an absolute guarantee that nothing outside `--ports` is touched should pass `--nmap-only`, where every scan is an nmap invocation and every invocation is confined by both port and protocol.

## Deliberate non-goals

Enumeraga does not check scope or approval itself. Deciding whether a scan is authorised belongs to the caller that holds the manifest; duplicating that logic here would create a second, weaker copy of a security control and invite disagreement between them. Enumeraga's job is to honour the bounds it is given and to report faithfully on what it did.

Nothing in the tool descriptions or output addresses an automated caller as though it needed persuading to behave. The bounds are mechanical, and they hold whether the caller reads the prose or not.

## Still outstanding

This work covers bounds only. Two further pieces were scoped and deliberately deferred:

- **A structured run record.** Which tools ran, their exact argument vectors, timestamps, exit statuses and artefact paths, emitted as machine-readable output. The tool tracker now distinguishes skipped from failed and records a reason for each skip, which is the groundwork, but there is no run record file yet.
- **Proxy support.** An upstream proxy passed through to the spawned tools, plus a CA bundle, plus an honest statement of which tools cannot proxy at all. Two probes inside enumeraga make direct connections in Go and would need routing. This is the requesting caller's stated blocker, so bounds alone do not unblock them.
