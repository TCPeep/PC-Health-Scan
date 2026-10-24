# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's **private vulnerability reporting** on this repo: Security tab &rarr; **Report a vulnerability**. Or email the maintainer at the address listed on <https://github.com/TCPeep>.

Please include:
- What you did (one or two sentences).
- What happened that shouldn't have.
- Which version (shown in the report footer and the scan's start-up banner).

The maintainer will acknowledge within a week, agree on a fix date with you, and credit you in the release notes unless you'd rather stay anonymous.

## Supported versions

Only the latest release is supported.

## In scope

Especially welcome:
- Any way to make the Repair Console change something **not** in its pre-defined fix types.
- Any way to bypass the hard rules in [docs/safety.md](docs/safety.md) (killing a protected process, quarantining a system folder, &hellip;).
- Any way for a crafted `findings.json` to escape its parameter shape and inject commands.
- Any way for a browser page (other than the one the Repair Console opens itself) to drive the local HTTP server.
- CSRF on the Repair Console despite the session token.

## Out of scope

- Anyone with physical access or admin on the account.
- Reports that the scan "detects adware" that is a legitimate product &mdash; please open an issue for those instead, with the exact program and why you believe it's legitimate.
