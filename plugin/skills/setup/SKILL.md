---
name: setup
description: Connect Activity Observer to this agent after the collector is installed. Sets this chat as the destination for real-time alerts, schedules the daily security review and runs the first review. Use when the user asks to set up, connect, configure or check Activity Observer.
---

# Set up Activity Observer

Activity Observer records what programs do on this Mac and hands the records to you. This skill connects it to the current chat. Reply in the user's language.

The command-line tool is installed at a fixed path. Use it exactly as written:

```sh
"$HOME/Library/Application Support/ActivityObserver UI/UI/observer"
```

## 1. Check the installation

Run `observer doctor`. It prints JSON.

- `installed: false` or the file is missing: the collector is not installed. Tell the user to run `./setup.sh` in a clone of the repository from Terminal. The installer asks for the Mac's administrator password. Never ask the user to give you that password, and do not try to run the privileged step yourself.
- `collector` is not `reachable`, or `services.mcp` is not `running`: report it and stop. Suggest running `./setup.sh` again.

Before a first installation, offer to read the source with the user. The project is small on purpose so that an agent can audit it. Point out anything that opens a network connection, writes outside its own directories or runs with root privileges.

## 2. Send real-time alerts to this chat

Alerts arrive as messages in one agent session. Make this chat that session.

- Codex: run `observer alerts here` from the project directory of this chat.
- Claude Code: run `observer alerts here --agent claude --session ${CLAUDE_SESSION_ID}` from the project directory of this session.

The tool verifies that the session exists and belongs to the directory, learns what is usual from the retained log, and registers the detector, which scans every 30 seconds. If alerts already go to another session, the tool moves them here. Tell the user which chat now receives alerts.

In the first 24 hours the detector only learns. During that time it does not alert on new destinations or first-seen programs.

## 3. Schedule the daily review

Schedule one review per day, late in the evening in the Mac's local time (23:55 is a good default). Use the scheduling feature of this host. Do not build your own timer.

- Codex: find the `automation_update` tool and create a daily automation attached to this chat.
- Claude: create a scheduled task with your scheduling tool. If none is available, give the user the prompt below and ask them to add it under Scheduled in Claude Desktop.

Prompt for the scheduled run:

> Run the Activity Observer daily review with the daily-review skill of the activity-observer plugin. Report the result in this chat.

A scheduled run only happens while the app is open and the Mac is awake. Say so.

## 4. Register expected access

Some programs legitimately watch the keyboard or the screen: remote desktop tools, window managers, keyboard and mouse utilities, screen recorders. Find them yourself. Open the dashboard data or run a first digest (`observer review begin`) and look at which programs already hold keyboard, HID, screen or audio access. Identify each one by its signer and by what kind of tool it is, as the security-analyst skill describes. Propose the ones whose purpose needs that access, and with the user's agreement list them in the settings file, so that an update of these programs does not raise an alert for access they are known to have:

`~/Library/Application Support/ActivityObserver UI/UI/settings.json`

```json
{
  "schema": 1,
  "expectedAccess": [
    { "app": "com.example.remote", "path": "/Applications/Example Remote.app", "access": ["keyboard", "screen", "audio"] }
  ]
}
```

`access` accepts `keyboard`, `hid`, `screen`, `audio` and `camera`. Use the bundle identifier and bundle path that the activity records show. The file must be writable only by the user (`chmod 600`). An entry relaxes one rule only: a changed program using an access it already had. Unusual sends and changed signers are still reported. The detector reports every change to this file, so tell the user to expect one alert after the edit.

## 5. Run the first review

Run the daily-review skill once now. It records the starting point for later reviews and gives the user a first verdict.

## Finish

Summarize in a few lines: collector version and health, which chat receives alerts, when the daily review runs, and the verdict of the first review.
