# Contributing

This repository changes as little as possible. That is a security decision: every change to a tool that watches your computer is something each user would have to review again.

## How to take part

- **Fork it.** If you need a different rule, another sensor or support for another agent, change your own copy. The code is small and MIT licensed for that reason.
- **Report problems.** Bugs, missed detections and false alarms are useful as issues, especially with a replay result (see [docs/DETECTION.md](docs/DETECTION.md)). Remove personal paths and addresses first. Security problems go through [SECURITY.md](SECURITY.md).
- **Propose rules with evidence.** A detection rule is judged by what it raises on real logs. Say how many incidents it produced on yours over how many days, and which of them mattered.

## Pull requests

Only the repository owner merges into `main`. Pull requests are read as proposals. A change may be reimplemented by the owner instead of merged, so that everything in `main` has one reviewer who is accountable for it. Small, single-purpose changes with a clear reason have the best chance.

A change is not accepted if it adds a network connection, an updater, telemetry, a downloaded rule or reputation list, a prebuilt binary, or a tool that lets an agent change the system.

## Building and testing

```sh
./build.sh                         # compiles the collector and runs its self-tests
cd UI && npm ci --ignore-scripts   # pinned build dependencies
node build-mcp-app.mjs             # builds the widgets for local preview
```

`./setup.sh` installs the result on your own Mac. Test there before proposing a change.
