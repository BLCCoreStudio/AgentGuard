# Contributing

AgentGuard is in early development. Focused bug reports, tests, documentation fixes, portability work, and narrowly scoped policy-rule proposals are welcome.

Before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Keep changes small and explain the behavior being changed. Security vulnerabilities should follow `SECURITY.md` rather than public issues.
