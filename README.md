# AgentGuard

**Local policy guard for AI coding agents before shell, filesystem, and network actions.**

> **Status:** early development. No stable release has been published yet.

AgentGuard is a Linux-first Rust CLI project exploring a local policy layer between AI coding agents and risky system actions. The first milestone focuses on deterministic command inspection and conservative local rules before broader integrations are attempted.

## Planned v0.1 scope

- inspect proposed shell commands before execution
- flag destructive filesystem operations
- flag access to common sensitive credential paths
- flag shell-pipe download-and-execute patterns
- machine-readable exit behavior for wrappers and agent integrations
- local-only operation with no telemetry or backend

AgentGuard is intended as a guardrail, not a complete sandbox or a replacement for operating-system isolation.

## Build

Requires Rust 1.74 or newer.

```bash
cargo build
cargo test
```

## Development principles

- deny dangerous operations conservatively
- explain why an action was flagged
- never silently execute blocked commands
- keep policy evaluation local
- avoid claims of complete security coverage

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting once the development scaffold lands.

## License

MIT © BLC Core Studio
