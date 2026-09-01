<div align="center">

# AgentGuard

### Explainable safety checks for AI-assisted development

[![CI](https://github.com/BLCCoreStudio/AgentGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/BLCCoreStudio/AgentGuard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/BLCCoreStudio/AgentGuard/actions/workflows/codeql-security.yml/badge.svg)](https://github.com/BLCCoreStudio/AgentGuard/actions/workflows/codeql-security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.74+](https://img.shields.io/badge/Rust-1.74%2B-000000?logo=rust)](Cargo.toml)
[![Platform](https://img.shields.io/badge/platform-Linux-111827?logo=linux&logoColor=white)](#linux-sandbox-mode)

**Review risky commands before they run, scan instruction text for high-signal risks, enforce Git metadata policy, and optionally execute approved commands inside a restricted Linux workspace.**

[Quick start](#quick-start) · [GitHub Actions](#github-actions) · [Security model](#security-model-and-limitations) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

> [!IMPORTANT]
> **Status:** development preview. No stable release has been published yet. AgentGuard is useful for evaluation and CI experiments today, but its CLI and policy surface may still change before the first stable release.

AgentGuard is a local, Linux-first Rust CLI that adds an explainable checkpoint between AI-assisted development workflows and potentially risky actions. Its controls are deterministic and inspectable: it does not ask an LLM to decide whether an action is safe.

## Why AgentGuard

AI coding agents can write files, propose shell commands, modify Git metadata, and operate across increasingly powerful development environments. AgentGuard focuses on a narrower question: **what high-signal risks can be detected or constrained locally before they become an incident?**

| Control | What it does | What it does not claim |
| --- | --- | --- |
| Command policy | Blocks selected high-risk command patterns before execution | General malware detection or complete shell understanding |
| Prompt-risk scan | Flags high-signal risky instruction text | Proof that a prompt is malicious or safe |
| Agent asset audit | Audits `AGENTS.md` and Agent Skills `SKILL.md` structure/signals | Full Agent Skills/YAML validation |
| Git metadata guard | Detects selected sensitive or unwanted AI-related Git metadata | Complete privacy scanning of repository history |
| Linux sandbox | Runs approved commands with a restricted writable workspace and no network by default | A VM, kernel isolation, or a complete security boundary |

The goal is **defense in depth with explicit limits**, not a green checkmark that pretends an AI-generated action has been proven safe.

## Quick start

Build the current preview from source:

```bash
git clone https://github.com/BLCCoreStudio/AgentGuard.git
cd AgentGuard
cargo build --release --locked
```

Try the main controls:

```bash
./target/release/agentguard check -- cargo test
./target/release/agentguard scan-prompt AGENTS.md
./target/release/agentguard init-policy . --policy privacy
./target/release/agentguard install-hook .
./target/release/agentguard scan-git . --rev origin/main..HEAD
./target/release/agentguard plan ./project -- cargo test
```

The current development line combines five deliberately explainable controls:

- deterministic checks for risky shell commands;
- local prompt-risk scanning for text files;
- experimental auditing for `AGENTS.md` and Agent Skills `SKILL.md` assets;
- Git commit/remote metadata policy checks for AI-assisted workflows;
- optional process isolation through Linux bubblewrap (`bwrap`).

## GitHub Actions

AgentGuard includes a composite GitHub Action for repository Git-metadata policy checks. Start in the least surprising mode: read the repository and apply the default `privacy` policy.

```yaml
name: AgentGuard

on:
  pull_request:

permissions:
  contents: read

jobs:
  agentguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - name: Check AI-assisted Git metadata
        uses: BLCCoreStudio/AgentGuard@main
        with:
          path: .
          policy: privacy
          format: text
```

> [!NOTE]
> Until AgentGuard publishes a stable versioned Action release, `@main` is appropriate for evaluation only. Production workflows should prefer an immutable commit SHA or a future versioned release tag.

Supported Action inputs:

| Input | Default | Purpose |
| --- | --- | --- |
| `path` | `.` | Checked-out repository path to scan |
| `revision` | automatic for pull requests | Optional Git revision or range |
| `policy` | `privacy` | `privacy` or `clean` Git-metadata policy |
| `format` | `text` | `text` or `json` output |

The Action currently builds AgentGuard with Rust 1.74 and runs the repository metadata policy locally in the GitHub Actions runner.

## Command policy checks

```bash
agentguard check -- <COMMAND> [ARGS...]
```

Current command checks include:

- `AG001` — destructive recursive deletion aimed at critical paths;
- `AG002` — references to common credential locations such as SSH or AWS credentials;
- `AG003` — `curl` / `wget` download-and-pipe-to-shell patterns;
- `AG004` — explicit `sudo` privilege-escalation commands;
- `AG005` — `chmod 777` world-writable permission changes.

A blocked command is **not executed** by `check`.

## Prompt-risk scanning

```bash
agentguard scan-prompt <FILE>
```

The current prompt rules flag a focused set of high-signal patterns including instruction overrides, system-prompt extraction requests, possible secret-exfiltration language, and Unicode bidirectional-control characters.

Findings are review signals, not proof that content is malicious.

## Agent asset audit

The development tree includes an experimental `agentguard-assets` binary for repositories that use coding-agent instructions and reusable Agent Skills:

```bash
cargo run --bin agentguard-assets -- ./project
```

It recursively discovers `AGENTS.md` and `SKILL.md` files and performs a focused audit of:

- required Agent Skills YAML frontmatter;
- `name` length, character, hyphen, and parent-directory rules;
- required `description` and documented field-length limits;
- the recommended `SKILL.md` size boundary for progressive disclosure;
- high-signal instruction-override, prompt-extraction, secret-exfiltration, and bidirectional-text patterns.

The format checks follow the public Agent Skills specification where implemented. This prototype intentionally does **not** claim full YAML/spec validation or prove that an agent instruction file is safe.

## Git metadata guard

AI coding agents can add metadata to commits, pull-request text, local session records, or repository configuration. Some metadata is useful provenance; other metadata may be unexpected, vendor-specific, or sensitive.

AgentGuard separates those concerns instead of treating all AI attribution as unsafe.

### Repository policy

Create a policy file at the Git repository root:

```bash
agentguard init-policy . --policy privacy
```

This writes:

```toml
# AgentGuard repository policy
# Supported values: privacy, clean
git_metadata_policy = "privacy"
```

`scan-git` and AgentGuard-managed commit hooks automatically read `.agentguard.toml` from the repository root. A command-line `--policy` explicitly overrides the repository policy.

`init-policy` refuses to overwrite an existing file so repository policy changes remain intentional and reviewable.

### Policies

`privacy` is the default. It currently blocks only high-confidence sensitive metadata:

- `GM001` — Claude session URL/trailer in commit metadata;
- `GM005` — credential-like token or username/password embedded in a Git remote URL.

`clean` includes the privacy rules and additionally blocks selected vendor/session attribution:

- `GM002` — Codex session identifier;
- `GM003` — AI-agent `Co-authored-by` trailer;
- `GM004` — AI-tool `Generated with`, `Generated-by`, or `Made-with` signature.

This distinction is intentional: AgentGuard does not assume AI provenance is bad. Teams that want provenance can keep `privacy`; teams that require attribution-free history can opt into `clean`.

### Scan Git history and remotes

```bash
# Latest 50 commits plus configured Git remotes
agentguard scan-git .

# One revision or range
agentguard scan-git . --rev origin/main..HEAD

# Override repository policy for one run
agentguard scan-git . --rev origin/main..HEAD --policy clean

# Machine-readable output
agentguard scan-git . --rev origin/main..HEAD --format json
```

A policy match exits with status `3`, allowing CI to block the change.

### Block metadata before a commit lands

Install an AgentGuard-managed `commit-msg` hook:

```bash
agentguard install-hook .
```

The hook reads the repository policy every time it runs, so changing `.agentguard.toml` does not require reinstalling the hook.

For safety, `install-hook`:

- creates or refreshes hooks that contain AgentGuard's management marker;
- refuses to overwrite an existing hook it does not manage;
- marks the managed hook executable on Unix platforms.

Manual checking is also available:

```bash
agentguard check-commit-msg .git/COMMIT_EDITMSG --repo .
agentguard check-commit-msg .git/COMMIT_EDITMSG --repo . --format json
```

The current implementation remains deliberately **detect + block**. It does not automatically rewrite Git history.

### Why this exists

This direction is grounded in real failures and policy friction across AI-assisted development rather than a single vendor-specific footer:

- Claude Code users reported `Claude-Session` URLs appearing despite disabled attribution: [anthropics/claude-code#77830](https://github.com/anthropics/claude-code/issues/77830)
- Claude Code users reported personal account email exposure in `Co-authored-by` metadata: [anthropics/claude-code#66079](https://github.com/anthropics/claude-code/issues/66079)
- Codex users reported Git remote metadata containing embedded credentials: [openai/codex#31588](https://github.com/openai/codex/issues/31588)
- Apache Pinot added project-level handling for unwanted AI co-author trailers in squash-merged history: [apache/pinot#18688](https://github.com/apache/pinot/issues/18688)

AgentGuard only implements rules that can be checked deterministically with a documented scope. A clean result is not proof that Git metadata contains no private information.

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

- exposes only the selected project as writable at `/workspace`;
- exposes core system paths read-only when present;
- clears the inherited environment and installs a minimal `PATH`;
- uses a private temporary `/tmp`;
- unshares Linux namespaces, including network access, by default;
- performs no privilege escalation.

## Companion research

AgentGuard incorporates the core directions previously explored by two BLCCoreStudio companion repositories:

- **SafeWorkspace** — Linux bubblewrap isolation experiments;
- **PromptShield** — deterministic prompt-injection signal scanning.

Those repositories remain useful as focused research histories, while AgentGuard is the primary integration target for runtime policy and isolation work.

## Exit behavior

For the main `agentguard` binary:

- `0` — requested check or command completed successfully;
- `2` — invalid usage, read failure, Git failure, or sandbox setup failure;
- `3` — current policy/risk rule matched, or requested backend is unavailable.

For `agentguard-assets`, `0` means the current audit found no matching rule, `2` is an input/read error, and `3` means one or more review findings were reported.

A command executed inside the sandbox may return its own non-zero exit status.

## Build and test

Requires Rust 1.74 or newer and Git for Git metadata workflows.

```bash
cargo build --locked
cargo test --locked --all-targets
```

## Security model and limitations

- Linux sandbox mode currently requires `bwrap` / bubblewrap.
- The sandbox is not a virtual machine; the Linux kernel, bubblewrap, exposed read-only system files, and invoked tools remain part of the trusted computing base.
- The command checks are deterministic text rules and can have false positives or false negatives.
- Prompt and agent-asset scanning does not execute or upload scanned content.
- Git metadata checks inspect only local Git output and commit-message files; they do not upload repository content.
- `scan-git` currently inspects at most 50 commits from the selected revision/range plus configured Git remotes.
- `.agentguard.toml` currently supports only the documented `git_metadata_policy` key; AgentGuard does not claim to implement general TOML parsing.
- `install-hook` will not merge itself into an unrelated existing hook; manual integration is required in that case.
- The Git metadata rules intentionally do not attempt to infer whether every human-looking email address is private; that would create unacceptable false positives without stronger context.
- Agent Skills parsing in the experimental asset audit is intentionally narrow and is not a general-purpose YAML validator.
- A clean result is not proof that an action, prompt, `AGENTS.md`, skill, or Git history is safe.

See [SECURITY.md](SECURITY.md) for reporting guidance and the current security scope.

## Contributing

Bug reports and focused pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Security-sensitive reports should follow [SECURITY.md](SECURITY.md) instead of being opened publicly.

## License

MIT © BLC Core Studio
