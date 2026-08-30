# AgentGuard

**Review risky AI-assisted development commands before they run, scan instruction text for high-signal risks, enforce Git metadata policies, and optionally execute approved commands inside a restricted Linux workspace.**

> **Status:** development preview. No stable release has been published.

AgentGuard is a local, Linux-first Rust CLI for adding an explainable safety check between AI-assisted development workflows and potentially risky actions.

Start with the current preview:

```bash
agentguard check -- cargo test
agentguard scan-prompt AGENTS.md
agentguard init-policy . --policy privacy
agentguard install-hook .
agentguard scan-git . --rev origin/main..HEAD
agentguard plan ./project -- cargo test
```

The current development line combines five deliberately explainable controls:

- deterministic checks for risky shell commands
- local prompt-risk scanning for text files
- experimental auditing for `AGENTS.md` and Agent Skills `SKILL.md` assets
- Git commit/remote metadata policy checks for AI-assisted workflows
- optional process isolation through Linux bubblewrap (`bwrap`)

AgentGuard is not a complete security boundary, malware detector, secret scanner, or proof that an AI-generated action is safe. Its current rules and sandbox are defense-in-depth controls with documented limits.

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

The development tree includes an experimental `agentguard-assets` binary for repositories that use coding-agent instructions and reusable Agent Skills:

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

- `GM001` — Claude session URL/trailer in commit metadata
- `GM005` — credential-like token or username/password embedded in a Git remote URL

`clean` includes the privacy rules and additionally blocks selected vendor/session attribution:

- `GM002` — Codex session identifier
- `GM003` — AI-agent `Co-authored-by` trailer
- `GM004` — AI-tool `Generated with`, `Generated-by`, or `Made-with` signature

This distinction is intentional: AgentGuard does not assume AI provenance is bad. Teams that want provenance can keep `privacy`; teams that require attribution-free history can opt into `clean`.

### Scan Git history and remotes

Scan the latest 50 commits plus configured Git remotes:

```bash
agentguard scan-git .
```

Scan only a revision/range:

```bash
agentguard scan-git . --rev origin/main..HEAD
```

Override the repository policy for one run:

```bash
agentguard scan-git . --rev origin/main..HEAD --policy clean
```

### Machine-readable CI output

Use JSON when a workflow or another tool needs structured findings:

```bash
agentguard scan-git . --rev origin/main..HEAD --format json
```

Example shape:

```json
{"ok":false,"findings":[{"code":"GM001","scope":"abc123","message":"Claude session URL/trailer detected in Git metadata"}]}
```

Exit codes stay unchanged, so CI can use both the JSON payload and status `3` to block a change.

### Block metadata before a commit lands

Install an AgentGuard-managed `commit-msg` hook:

```bash
agentguard install-hook .
```

The hook reads the repository policy every time it runs, so changing `.agentguard.toml` does not require reinstalling the hook.

For safety, `install-hook`:

- creates or refreshes hooks that contain AgentGuard's management marker
- refuses to overwrite an existing hook it does not manage
- marks the managed hook executable on Unix platforms

Manual checking is also available:

```bash
agentguard check-commit-msg .git/COMMIT_EDITMSG --repo .
agentguard check-commit-msg .git/COMMIT_EDITMSG --repo . --format json
```

A matching rule exits with status `3`, allowing Git hooks and CI jobs to stop unwanted metadata before it is recorded.

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
- `2` — invalid usage, read failure, Git failure, or sandbox setup failure
- `3` — current policy/risk rule matched, or requested backend is unavailable

For `agentguard-assets`, `0` means the current audit found no matching rule, `2` is an input/read error, and `3` means one or more review findings were reported.

A command executed inside the sandbox may return its own non-zero exit status.

## Build

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

## License

MIT © BLC Core Studio