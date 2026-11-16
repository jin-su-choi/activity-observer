# Security

Activity Observer runs with administrator-installed components and watches the computer it runs on. A flaw in it matters more than a flaw in most tools, so reports are welcome and taken seriously.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Please do not open a public issue for something that could be exploited.

Include the commit you tested, what an attacker needs beforehand (for example, code running as the logged-in user) and what they gain. A proof of concept helps but is not required.

Reports of particular interest:

- A way for a program running as the user to alter or delete log records, or forge a signed anchor, without verification failing.
- A way to make the collector, the detector's scanner or the MCP server open an internet connection.
- A way for text in a log record, such as a file name or program name, to make a reviewing agent act.
- A way to make the installer run or install a file that differs from the pinned build.
- Privilege escalation through the root-owned writer or its socket.

## What the design does and does not defend

The design, its trust boundaries and how to verify an installation are described in [docs/TRUST.md](docs/TRUST.md). Known gaps are listed in [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md). An attack that needs root on the Mac is outside what the log can defend: the signing key is on the same machine.

## Releases

There are no binary releases and no automatic updates. A release is a signed git tag. Verify it before building:

```sh
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v v0.4.0
```

The tag is signed with the maintainer's SSH key, which is listed in `allowed_signers`. The same key is published at <https://github.com/jin-su-choi.keys>, so you can compare the two instead of trusting the file in your checkout.
