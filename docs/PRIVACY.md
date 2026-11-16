# What is collected and where it goes

## Collected

| Kind | Fields |
| --- | --- |
| Network connections | Program (bundle identifier or executable name, path, process ID), remote IP address and port, protocol, local address, bytes sent and received per minute, the paths of parent programs, start and end of a connection. Repeated connections to one destination within five minutes are merged into a count. |
| Input access | Programs that hold a keyboard event tap or open a HID device, and the device name. |
| Screen, camera, microphone | Which program started and stopped using them, from the system's own privacy indicators. |
| Privacy permission decisions | Program, permission (for example Accessibility, Screen Recording, Full Disk Access), allowed or denied. One record per combination every six hours. |
| Programs | Path, bundle identifier, version, code-signing team and identifier, a SHA-256 for small executables, and whether a program was installed, updated, changed, removed or first seen. |
| Autostart items | Changes under LaunchAgents, LaunchDaemons and PrivilegedHelperTools. |
| Sensitive files | For SSH access files, shell startup files, git, npm and netrc configuration, and agent settings: path, size, permissions, owner and a SHA-256. For agent state files only the MCP server and hook definitions are hashed. |
| App lifecycle | Launch and exit of applications. |
| The observer itself | Sensor health, dropped-record counters, gaps, restarts, storage use. |

## Not collected

Keystrokes, clipboard contents, screen images, audio, video, packet contents, URLs, domain names, browser history, file contents, passwords, tokens and message contents. The contents of the sensitive files are hashed and never stored.

## Where it is stored

- The log: `/Library/Application Support/ActivityObserver/data`, readable and writable only by root. It is limited to 1 GB. When the limit is reached the oldest records are pruned and the pruning boundary is signed, so a reviewer can see that a range is gone.
- Published reviews, incidents and settings: `~/Library/Application Support/ActivityObserver UI`, readable only by your user.

Nothing is uploaded by Activity Observer. Its processes cannot open internet connections.

## What reaches your model provider

The agent does the reviewing, and the agent runs on a model hosted by OpenAI or Anthropic. Whatever the agent reads from the log becomes part of the conversation and is sent to that provider under your account's terms:

- the daily digest: program names and paths, version changes, which programs used which access, remote addresses with byte counts, changed sensitive file paths
- the records behind an alert
- anything you select in the dashboard and attach to a message

Paths can contain your user name and project names. Remote addresses reveal which services you use. If that is not acceptable for your account or your employer, do not connect an agent. The collector, the log and the dashboard preview still work without one.

## Deleting it

`./uninstall.sh --purge` removes the programs, the log, the signing key, published reviews, incidents and settings. Without `--purge` the log and key are kept so that a later installation continues the same chain.
