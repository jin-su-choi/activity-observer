# Detection

Two things look at the log.

- **The daily review** is done by the agent. It reads a digest of every record since the last review, investigates what stood out with the [analyst skills](../plugin/skills/security-analyst/SKILL.md) and ends with a verdict. Nothing is filtered out beforehand.
- **Real-time detection** is done by fixed rules. A detector reads new records every 30 seconds, and only what matches a rule is sent to the agent as an incident. The agent then investigates and judges.

The rules exist to decide what is worth interrupting the agent for within a minute or two. They are deliberately broad about unusual behavior and leave the verdict to the agent. They are also few, and they will miss things. Improving them is ongoing work, and this page explains how to measure a change.

## Rules

| Reason code | Raised when | Notes |
| --- | --- | --- |
| `new_destination_send` | A program sends 256 KiB or more within five minutes to an external address it first contacted less than an hour earlier. | From the third such send within a week the program counts as a habitual sender, like a browser or a sync client, and this rule stops alerting for it. |
| `new_program_network` | An executable is seen for the first time and connects to an external address within ten minutes. | Higher severity when the executable is unsigned or runs from a temporary or download folder. System locations sealed by macOS are excluded. |
| `changed_program_access` | A program changed (installed, updated, files changed) and within a day uses the keyboard, HID devices, the screen, microphone or camera in a way it had not before the change. | Programs listed under `expectedAccess` in the settings are exempt for the kinds of access listed there. |
| `signer_changed`, `signer_changed_access` | A program's code-signing team changed. The second code is added when it then uses sensitive access. | Always high severity. |
| `sensitive_external_send` | The same executable uses the keyboard, screen or audio and makes an unusual send within five minutes. | Unusual means a new destination as above, or at least 8 MiB and four times the previous five-minute peak to a known one. |
| `autostart_changed` | A LaunchAgent, LaunchDaemon or privileged helper is added or changed. | |
| `sensitive_file_changed` | SSH access files, shell startup files, git, npm or netrc configuration, or the MCP server and hook definitions of coding agents change. | Compared every 30 seconds by hash. |
| `settings_changed` | The detector's own settings file changes. | So that an allowance cannot be added quietly. |
| `collection_gap`, `collection_loss`, `sensor_unhealthy`, `collection_unavailable`, `retention_gap` | The observer could not see: dropped records, a stopped sensor, an unreachable collector, records pruned before the detector read them. | A file-watch gap that the collector repairs by rechecking known paths within ten minutes is left to the daily review. |
| `protected_installation`, `log_integrity` | An installed file does not match its pin, or the signed status or hash chain fails. | Always high severity. |

Incidents about one program within an hour are merged. The agent is alerted again only when the severity rises.

### The learning day

Rules that compare against a baseline, `new_destination_send` and `new_program_network`, stay silent for the first 24 hours after installation and after a pruned range. A baseline learned on a machine that is already compromised includes the compromise. The first daily review looks at everything for that reason.

## What the rules would have seen

**A launcher that starts stealing data** (the NIKKE pattern). No installed file changes, so nothing fires at first. When the launcher uploads what it collected to a server it never talked to, `new_destination_send` fires, within a minute or two of the upload passing 256 KiB. The collection itself, reading browser databases and wallet files, is invisible. If the stolen data is small or goes to an address the launcher already used, the rule does not fire and the daily review is the only chance.

**A fake coding task** (the Binance pattern). The task's script runs under an interpreter such as node or python. Its first connection carries the chain of parent programs, so the agent can see it was started from a terminal in a freshly cloned folder. A helper binary it downloads and runs raises `new_program_network`. A LaunchAgent it writes raises `autostart_changed`, and an SSH key or an edited agent configuration raises `sensitive_file_changed`. If it only reads tokens and posts a few kilobytes through an interpreter that often uploads, nothing fires.

**A tampered extension that plants an SSH backdoor** (the Cursor pattern). The `authorized_keys` change and the LaunchAgent each raise an incident.

## Settings

`~/Library/Application Support/ActivityObserver UI/UI/settings.json` is optional and must be writable only by you.

```json
{
  "schema": 1,
  "expectedAccess": [
    { "app": "com.example.remote", "path": "/Applications/Example Remote.app", "access": ["keyboard", "screen", "audio"] }
  ],
  "programGroups": [
    { "id": "remote", "name": "Example Remote", "match": { "app": ["com.example.remote", "com.example.remote.helper"] } }
  ]
}
```

- `expectedAccess` exempts a program from `changed_program_access` for the listed kinds: `keyboard`, `hid`, `screen`, `audio`, `camera`. Unusual sends and signer changes are still reported.
- `programGroups` only affects how records are grouped and named in the dashboard. `match` accepts `app`, `appPrefix`, `pathPrefix` and `pathContains`.

An invalid file is ignored as a whole, which means no allowances. Every change raises `settings_changed`.

## Measuring a rule change

The detector can replay the retained log from the beginning with a fresh state and print the incidents it would have raised, without touching the live state or sending anything:

```sh
"$HOME/Library/Application Support/ActivityObserver UI/UI/observer" alerts replay
```

Before changing a threshold or adding a rule, replay with and without the change and compare: how many incidents per day, how many of them you would have wanted, and whether a known bad pattern is still caught. On the author's Mac the current rules raised six incidents over the last two of three replayed days, the first being the learning day: one autostart item, two first-seen executables that connected out, and three programs sending to new addresses.

## Blind spots

- Uploads to a destination the program already uses, and uploads that stay under the thresholds.
- Anything a program reads. File access is not recorded.
- Code that runs inside a trusted interpreter or app and behaves like it.
- Processes that never use the network or a watched location. Process starts are not recorded yet.
- Destinations are IP addresses. Many services share the addresses of a content delivery network, which makes "new destination" both noisier and easier to hide in.
- A program that was already active during the learning day.
