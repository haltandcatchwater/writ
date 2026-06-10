# Security Policy

## Reporting a vulnerability

If you find a security issue in Writ, please report it privately rather than opening a public issue.

Email the maintainer with:
- a description of the issue,
- a minimal reproduction (a failing scope check, an escape, a leaked secret path),
- the affected version.

You'll get an acknowledgement and a fix timeline. Please give a reasonable window to ship a fix before any public disclosure.

## Scope of guarantees

Writ provides **scope enforcement at the channel boundary**: typed allow-lists, caps, deny-lists, and credential isolation, all frozen at construction. That boundary is the load-bearing guarantee — a denial holds regardless of what the model decides to do.

Writ does **not** provide:
- a process/network sandbox (it governs semantic scope, not physical egress — pair it with a container or microVM),
- a complete prompt-injection defense (the guard is defense in depth and produces audit signal; it does not claim completeness),
- protection against code running *inside your own process* that bypasses `send()` and calls the underlying API directly.

A finding that demonstrates an agent **widening its own scope through the channel API**, **reading an injected secret**, or **escaping a path/host/operation allow-list** is in scope and valued.
