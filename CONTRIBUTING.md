# Contributing to Writ

Thanks for considering a contribution.

## Ground rules

- **Scope is the product.** Any new channel must enforce a meaningful, typed scope — allow-lists, caps, deny-lists. A thin passthrough wrapper around an API is not a Writ channel.
- **Secrets never reach the agent.** Resolve credentials from `process.env` in the constructor; inject in `execute`. Never place a secret on an intent or a scope object.
- **Fail closed.** If a check can't be evaluated, deny.
- **Tests required.** Every channel needs scope tests proving that out-of-scope intents are denied and in-scope intents pass. See `tests/scopes.test.ts`.

## Development

```
npm install
npm run build
npm test
npm run demo
```

## Adding a channel

See [AGENTS.md](AGENTS.md) for the channel template and rules of thumb. In short: extend `ScopedChannel`, implement `validateIntent` (sync, in-scope check) and `execute` (the I/O), override `preflight`/`sanitizeRequest` if needed, export from `src/index.ts`, and add tests.

## Commits & PRs

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, …).
- Keep changes scoped to one concern.
- Don't add runtime dependencies to the core without discussion — Writ's core is dependency-free by design, and MCP support is an optional peer dependency.

## Reporting a vulnerability

Please do not open a public issue for security problems. See [SECURITY.md](SECURITY.md).
