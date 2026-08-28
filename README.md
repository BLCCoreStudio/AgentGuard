# AgentGuard

**Local policy checks for risky commands before AI-assisted shell execution.**

> **Status:** development preview. No stable release has been published.

AgentGuard is a Linux-first Rust CLI exploring a local policy layer between AI-assisted development workflows and risky shell actions. The current implementation performs a deliberately small set of deterministic command checks and does not claim to be a complete sandbox or security boundary.

## Current preview

```bash
agentguard check -- <COMMAND> [ARGS...]
```

Current checks flag:

- destructive recursive deletion aimed at critical paths such as `/` or the home directory
- references to common credential locations such as SSH or AWS credential paths
- `curl` / `wget` download-and-pipe-to-shell patterns

Exit behavior is script-friendly:

- `0` — no current preview rule matched
- `2` — invalid usage
- `3` — one or more current rules matched and the command was blocked by the check

AgentGuard only evaluates the command text supplied to `check`; it does not execute the command, monitor the operating system, or provide process isolation.

## Build

Requires Rust 1.74 or newer.

```bash
cargo build --locked
cargo test --locked
```

## Development principles

- keep rules deterministic and explainable
- default conservatively around destructive actions
- never silently execute a command being inspected
- keep evaluation local
- avoid claims of complete security coverage

## Security

See [SECURITY.md](SECURITY.md) for reporting guidance and current limitations.

## License

MIT © BLC Core Studio
