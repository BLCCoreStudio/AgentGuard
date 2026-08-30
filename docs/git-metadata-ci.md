# Git metadata checks in pull request CI

AgentGuard can use the same repository policy for commit metadata and text that will be published as pull-request metadata.

## What CI can catch

A pull-request workflow can scan the commits introduced by the pull request:

```bash
agentguard scan-git . --rev "$BASE_SHA..$HEAD_SHA"
```

It can also write the pull-request body to a temporary file and apply the same deterministic metadata rules:

```bash
printf '%s' "$PR_BODY" > "$RUNNER_TEMP/agentguard-pr-body.txt"
agentguard check-git-text "$RUNNER_TEMP/agentguard-pr-body.txt" --repo .
```

`check-git-text` is the generic outbound-text command for PR descriptions, release notes, generated changelogs, issue text, or other files that should obey the repository Git metadata policy. `check-commit-msg` remains available for Git hooks and existing integrations; both commands intentionally use the same deterministic rule engine and exit codes.

## Important boundary

A GitHub Actions check runs **after** the pull request body has reached GitHub. It is therefore a detection and enforcement layer for review/merge, not a guarantee that sensitive PR text was never published.

For commit messages, the locally installed `commit-msg` hook can block matching metadata before the commit is created:

```bash
agentguard install-hook .
```

For PR descriptions, review the body locally before publishing when confidentiality requires prevention rather than rapid detection. For example, save a draft body locally and run:

```bash
agentguard check-git-text pr-body.md --repo .
```

before passing that file to your Git hosting workflow.

## Safe workflow handling

Do not interpolate untrusted pull-request body text directly into a shell command. Pass it through an environment variable and write it with `printf`:

```yaml
- name: Write pull request body safely
  env:
    PR_BODY: ${{ github.event.pull_request.body }}
  run: printf '%s' "$PR_BODY" > "$RUNNER_TEMP/agentguard-pr-body.txt"
```

The AgentGuard repository dogfoods this pattern in its own CI workflow.
