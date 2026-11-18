# Trust and verification

A security tool asks for more trust than almost any other program. This page states what Activity Observer asks you to trust, what it does to deserve that, and how to check it yourself.

## What can go wrong, and what stands in the way

| Risk | What stands in the way |
| --- | --- |
| The project is compromised and ships something malicious | No binaries are distributed. You build from source that you or your agent can read. Releases are signed tags. There is no updater, so a later compromise of this repository does not reach an installed copy. |
| A dependency is compromised | The collector uses only Apple system frameworks and SQLite. The MCP server and widgets use seven npm packages at run time and esbuild at build time, 46 packages in all with their dependencies, each pinned with an integrity hash in `UI/package-lock.json`, installed with scripts disabled and bundled at build time. Nothing is fetched at run time. |
| The installed files are replaced | The installer records the SHA-256 of the collector, the verifier and every sandbox profile. Each reader checks those pins and file ownership before it talks to the collector, and the detector raises an incident when they differ. |
| A program rewrites the log | Only the root-owned writer can append. Every record is chained to the previous one by hash, and the head is signed with a key that only root can read. A review starts from an anchor kept in your chat history, outside the Mac. |
| Activity Observer is used to send data out | The collector, the sensor, the detector's scanner and the MCP server run under sandbox profiles that deny all internet sockets. The MCP server listens on loopback only and requires a per-installation token. |
| Text in a record steers the agent | Observed strings are cleaned of hidden characters, kept under a marked `observed` field and flagged when they read like instructions. The tools are read-only, so a successful injection has nothing to act with through this server. The skills tell the agent to treat such text as evidence. |

## Components and privileges

| Component | Runs as | Sandbox | Can write |
| --- | --- | --- | --- |
| Writer (`guard`) | root, LaunchDaemon | `Policies/guard.sb`: no network, no process creation | The log directory |
| Log reader for screen and permission events | root starts `/usr/bin/log stream` as the user | none of ours (an Apple tool) | A root-owned pipe to the writer |
| Sensor | user, LaunchAgent | `Policies/sensor.sb`: no network, no file writes, no process creation | Nothing. It sends records to the writer over a Unix socket |
| Detector scanner | user, LaunchAgent every 30 s | `Policies/incident.sb`: no network | Its own state directory |
| Detector delivery | user | none: it has to start your agent's command-line tool | Passes an incident ID and a fixed prompt to that tool |
| MCP server | user, LaunchAgent | `Policies/mcp-http.sb`: loopback only, no file writes | Nothing |
| Relay for Claude | user, started by Claude | `Policies/relay.sb`: loopback only | Nothing |
| `observer` command-line tool | user | `incident.sb` for reviews and `doctor`. Only `alerts here` and `connect` run outside it, because they start an agent's tool | Published reports, alert target |

The sandbox profiles are short. Read them in [`Policies/`](../Policies).

## Verify an installation

```sh
OBSERVER="$HOME/Library/Application Support/ActivityObserver UI/UI/observer"

# Services, collector reachability, alert target, last review
"$OBSERVER" doctor

# The installed files and the hashes the installer pinned
shasum -a 256 /Library/PrivilegedHelperTools/local.activity-observer
cat "/Library/Application Support/ActivityObserver/install-manifest.json"
ls -l /Library/PrivilegedHelperTools/local.activity-observer "/Library/Application Support/ActivityObserver/policies"

# The collector's own check that internet sockets are denied under its profile
/usr/bin/sandbox-exec -D AO_NODE=/Library/PrivilegedHelperTools/local.activity-observer \
  -f "/Library/Application Support/ActivityObserver/policies/mcp.sb" \
  /Library/PrivilegedHelperTools/local.activity-observer check-network-isolation

# The whole retained log: every hash link and the signed head
/usr/bin/sandbox-exec -D AO_NODE=/Library/PrivilegedHelperTools/local.activity-observer \
  -f "/Library/Application Support/ActivityObserver/policies/mcp.sb" \
  /Library/PrivilegedHelperTools/local.activity-observer verify
```

The hash of your build will differ from anyone else's, because the collector is compiled and ad-hoc signed on your Mac. What matters is that the installed file matches the one `./prepare-protected-install.sh` printed.

To watch for yourself that nothing leaves the Mac, look up the Activity Observer programs in its own dashboard, or run `nettop` and filter for `local.activity-observer` and the `node` processes started from `ActivityObserver UI`. They should show loopback traffic only.

## Verify the source

```sh
# signature of the release you are about to build
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v v0.4.1
# fails if a package does not match its pinned hash
cd UI && npm ci --ignore-scripts
```

The tag is signed with the maintainer's SSH key, which is listed in `allowed_signers`. The same key is published at <https://github.com/jin-su-choi.keys>, so you can compare the two instead of trusting the file in your checkout.

Then let an agent read it. A prompt that works:

> Review this repository before I install it. Look for anything that opens a network connection, writes outside its own directories, runs with root privileges without need, or does something the README does not describe. List what you checked.

## Repository policy

- `main` is protected. Only the owner can merge, and the owner reviews every change.
- No collaborators with write access.
- Releases are signed tags. No release assets are published.
- Changes are kept to a minimum. See [CONTRIBUTING.md](../CONTRIBUTING.md).

This is a single-maintainer project. That removes several ways for a malicious change to arrive, and it also means one person's account and one person's attention are the whole review process. Building from a tag you verified, after a read by your own agent, is the defense that does not depend on the maintainer.

## What trust is still required

- **Your agent and its provider.** The agent reads activity data during a review, and that data is sent to the model provider like any other chat content. The agent is itself a program that updates automatically. Activity Observer records what the agent's own processes do, so its behavior is visible in the log, but the judgment about that log comes from the same agent.
- **macOS.** Network attribution uses the system's NetworkStatistics framework, which is private API. Screen, camera, microphone and permission events are parsed from the system log. An OS update can change either.
- **Root.** Whoever has root on the Mac can read the signing key and write the log.
