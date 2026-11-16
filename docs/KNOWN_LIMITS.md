# Known limits

A quiet log is not proof of a clean Mac. This page lists what Activity Observer cannot do, and what has and has not been verified.

## By design

- **No prevention.** Nothing is blocked, quarantined or killed. An information stealer can collect and upload in minutes, before a person or an agent reacts. Activity Observer shortens the time until you know and preserves what happened.
- **The agent judges, and agents err.** A review can miss something or raise a false concern. A verdict of no threat found covers what was recorded and what the agent checked. Treat a report as a colleague's reading of the evidence, and open the records when it matters.
- **Rules gate real time.** Only incidents that match a rule in [DETECTION.md](DETECTION.md) reach the agent quickly. Everything else waits for the daily review. The rules are few and need continual improvement.
- **Reviews depend on the host being open.** A scheduled review runs only while the agent's app is open and the Mac is awake. An alert waits in a queue until the agent session can take it.

## Not observed

- Keystrokes, screen contents, audio, packet contents, URLs and domain names. Destinations are IP addresses and ports.
- **Connections made through Apple's own networking stack.** URLSession and Network.framework run these connections in user space, and macOS reports them only to tools that carry a private Apple entitlement, such as `nettop`. The sensor has no such entitlement and sees socket connections only. Native apps, Safari, system services, many updaters and `nscurl` are therefore missing from the network record. Programs built on Chromium or Electron and tools such as curl, node, python and git are recorded. Found on macOS 27.0.1: a 118 MB `nscurl` download that `nettop` displayed left no record, and neither did a 264 MB download by a browser's updater. Whether the root-owned writer could observe these connections has not been tested.
- File reads and writes in general. Only program files, autostart items and a short list of sensitive files are watched, and those by change, not by who changed them.
- Process starts. A command run in a terminal is recorded only when it uses the network or a watched location, or when it is an app launch. For network connections the chain of parent programs is recorded at the time of the connection.
- Activity inside a process. An interpreter or an app that reads your files and uploads them looks like that interpreter or app.
- Which program changed a file, an autostart item or a setting.
- Login items registered through `SMAppService`. They leave no LaunchAgent file, so they do not appear as autostart changes.
- Connections of processes owned by other users are attributed less precisely, and the responsible parent is unknown for them.
- There is no Endpoint Security client and no kernel-level audit.

## Collection can lapse

- File events can be dropped under heavy file activity. The collector then rechecks the files it knows, which confirms their current state and does not recover the missed events. A file created and deleted inside a gap is never seen.
- Screen, camera, microphone and permission events are parsed from the system log. A macOS update can change the format, and those sensors then report themselves as degraded or see nothing.
- Network attribution uses a private macOS framework.
- Storage is limited to 1 GB. Old records are pruned first, and the retention period depends on how active the Mac is. On the author's Mac the detailed records covered about three days before 0.4.0 doubled the pruning threshold. How long they last under 0.4.0 has not been measured.

## Trust boundaries

- **Root.** The signing key is stored on the Mac, readable only by root. An attacker with root can forge the log from that moment on. Records and anchors that were already copied into chat history can still expose a rewrite of the past.
- **Your user account.** The detector, the MCP server, the command-line tool and the plugins run as you. Malware running as you can stop the detector, change the settings file or remove the plugin. It cannot alter the log or stop the root-owned writer. The daily review and `observer doctor` show when the detector is not running, and the settings file is watched by the detector itself.
- **The starting point of a review.** A review should start from the signed anchor in your chat history. A scheduled run that starts in a fresh session falls back to the last published review stored on the Mac, which malware running as you could have moved forward to hide a range.
- **The learning day.** What was already happening when the detector learned its baseline looks normal to it.
- **Prompt injection.** Program names and paths are attacker-controlled text that an agent reads. They are cleaned, kept in a marked field and flagged when they read like instructions, and the tools are read-only. This lowers the risk. It does not remove it: an agent could still be talked into misjudging what it reads.
- **The model provider.** What the agent reads is sent to OpenAI or Anthropic. See [PRIVACY.md](PRIVACY.md).

## Platform and hosts

- macOS 14.2 or later only. Windows support is planned.
- The side-panel dashboard is a Codex feature. Claude Code and Claude Desktop get the tools, the skills and the inline widgets.
- The interface is in English and Korean and follows the system language.

## What has been verified

Version 0.4.0 was exercised on one machine: macOS 27.0.1, Apple M4, 16 GB of memory, Node.js 22.18.

Verified there:

- An update install from 0.3.3 to 0.4.0, the pinned hashes of every installed file, and a signed status that reports each sensor as active.
- Verification of the whole retained log: 408,289 records in 26 seconds.
- The record kinds added in 0.4.0 appearing in the production log: permission decisions, merged connection records, parent program chains.
- `observer doctor`, `observer review begin` over 173,363 records (18.5 seconds, 145 MB at peak) and `observer review publish` in a temporary home directory, including its refusal to store a review without a verdict, with findings for unknown programs, or with a verdict that its findings contradict.
- Codex: plugin registration and the five skills installed in the plugin cache. The widgets, including the verdict and the threat state, were rendered from the build in a local MCP Apps host.
- One investigation done by hand with the method of the security-analyst skill: a 2.25 GB upload that a review had left open was traced to the user's own model proxy through the package, its signer, the listening process and the owner of the address.
- Claude Code: plugin validation, then marketplace add, install and a connected MCP server in a clean configuration directory.
- One real-time alert from the new rules in production: a `sensitive_file_changed` incident was queued about 40 seconds after the change.
- A replay of the rules over three days of real records (396,687 records), which raised 6 incidents.
- Resource use: see the table in the [README](../README.md#light-enough-to-forget). It comes from a three-minute sample of process CPU time and resident memory.

Not verified:

- A scheduled daily review, an alert review and a deep inspection run by an agent with the analyst skills in their current form. The skills were rewritten after the first reviews summarized the log and left the judgment to the user.
- A reviewer on a small model starting a sub-agent on a stronger one for a deep inspection, in Codex or in Claude Code.
- A first install on a Mac that never had Activity Observer, the complete `setup.sh` flow, and `uninstall.sh`.
- Delivery of an alert into a Claude Code session, and the 0.4.0 widgets inside Claude.
- Other macOS versions and Intel Macs.
- GPU use.
- The time from an event to its alert for the new rules, beyond the single case above.
- The token cost of the digest-based daily review. The earlier review, which read every record, used about 4.8 million tokens a day.
- How many days of records 1 GB holds under 0.4.0.
