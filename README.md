# AgentGuard

**Local policy checks and an optional Linux execution boundary for AI-assisted development commands.**

> **Status:** development preview. No stable release has been published.

AgentGuard is a Linux-first Rust CLI exploring a local control layer between AI-assisted development workflows and risky actions. The current development line combines four deliberately explainable controls:

- deterministic checks for risky shell commands
- local prompt-risk scanning for text files
- experimental auditing for `AGENTS.md` and Agent Skills `SKILL.md` assets
- optional process isolation through Linux bubblewrap (`bwrap`)

AgentGuard is not a complete security boundary, malware detector, or proof that an AI-generated action is safe. Its current rules and sandbox are defense-in-depth controls with documented limits.

## Command policy checks

```bash
agentguard check -- <COMMAND> [ARGS...]
```

Current command checks include:

- `AG001` — destructive recursive deletion aimed at critical paths
- `AG002` — references to common credential locations such as SSH or AWS credentials
- `AG003` — `curl` / `wget` download-and-pipe-to-shell patterns
- `AG004` — explicit `sudo` privilege-escalation commands
- `AG005` — `chmod 777` world-writable permission changes

A blocked command is **not executed** by `check`.

## Prompt-risk scanning

```bash
agentguard scan-prompt <FILE>
```

The current prompt rules flag a small set of high-signal patterns such as instruction overrides, system-prompt extraction requests, possible secret-exfiltration language, and Unicode bidirectional-control characters.

Findings are review signals, not proof that content is malicious.

## Agent asset audit

The development tree now includes an experimental `agentguard-assets` binary for repositories that use coding-agent instructions and reusable Agent Skills:

```bash
cargo run --bin agentguard-assets -- ./project
```

It recursively discovers `AGENTS.md` and `SKILL.md` files, then performs a focused audit of:

- required Agent Skills YAML frontmatter
- `name` length, character, hyphen, and parent-directory rules
- required `description` and documented field-length limits
- the recommended `SKILL.md` size boundary for progressive disclosure
- high-signal instruction-override, prompt-extraction, secret-exfiltration, and bidirectional-text patterns

The format checks follow the public Agent Skills specification where implemented. This prototype intentionally does **not** claim full YAML/spec validation or prove that an agent instruction file is safe. It is being developed inside AgentGuard first so the idea can be validated before considering any separate project.

## Linux sandbox mode

Check whether the current isolation backend is available:

```bash
agentguard status
```

Inspect the exact bubblewrap plan without executing it:

```bash
agentguard plan ./project -- cargo test
```

Run a command inside the restricted workspace:

```bash
agentguard run ./project -- cargo test
```

Before sandbox execution, AgentGuard runs its current command-policy checks. If a blocking rule matches, the command is not launched.

The current bubblewrap backend:

- exposes only the selected project as writable at `/workspace`
- exposes core system paths read-only when present
- clears the inherited environment and installs a minimal `PATH`
- uses a private temporary `/tmp`
- unshares Linux namespaces, including network access, by default
- performs no privilege escalation

## Companion research

AgentGuard now incorporates the core directions previously explored by two BLCCoreStudio companion repositories:

- **SafeWorkspace** — Linux bubblewrap isolation experiments
- **PromptShield** — deterministic prompt-injection signal scanning

Those repositories remain useful as focused research histories, while AgentGuard is the primary integration target for runtime policy and isolation work.

## Exit behavior

For the main `agentguard` binary:

- `0` — requested check or command completed successfully
- `2` — invalid usage, read failure, or sandbox setup failure
- `3` — current policy/risk rule matched, or requested backend is unavailable

For `agentguard-assets`, `0` means the current audit found no matching rule, `2` is an input/read error, and `3` means one or more review findings were reported.

A command executed inside the sandbox may return its own non-zero exit status.

## Build

Requires Rust 1.74 or newer.

```bash
cargo build --locked
cargo test --locked --all-targets
```

## Security model and limitations

- Linux sandbox mode currently requires `bwrap` / bubblewrap.
- The sandbox is not a virtual machine; the Linux kernel, bubblewrap, exposed read-only system files, and invoked tools remain part of the trusted computing base.
- The command checks are deterministic text rules and can have false positives or false negatives.
- Prompt and agent-asset scanning does not execute or upload scanned content.
- Agent Skills parsing in the experimental asset audit is intentionally narrow and is not a general-purpose YAML validator.
- A clean result is not proof that an action, prompt, `AGENTS.md`, or skill is safe.

See [SECURITY.md](SECURITY.md) for reporting guidance and the current security scope.

## License

MIT © BLC Core Studio
