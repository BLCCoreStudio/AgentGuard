use std::{fs, path::Path, process::Command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    Privacy,
    Clean,
}

impl Policy {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "privacy" => Ok(Self::Privacy),
            "clean" => Ok(Self::Clean),
            _ => Err(format!(
                "unsupported git metadata policy '{value}'; expected 'privacy' or 'clean'"
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub code: &'static str,
    pub message: String,
}

fn is_agent_identity(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "claude", "cursor", "codex", "copilot", "gemini", "windsurf", "opencode",
    ]
    .iter()
    .any(|agent| lower.contains(agent))
}

pub fn message_findings(text: &str, policy: Policy) -> Vec<Finding> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();

    if lower.contains("claude-session:") || lower.contains("https://claude.ai/code/session_") {
        out.push(Finding {
            code: "GM001",
            message: "Claude session URL/trailer detected in Git metadata".to_owned(),
        });
    }

    if policy == Policy::Clean {
        if lower.contains("codex-session-id:") {
            out.push(Finding {
                code: "GM002",
                message: "Codex session identifier detected in Git metadata".to_owned(),
            });
        }

        if text.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("co-authored-by:") && is_agent_identity(line)
        }) {
            out.push(Finding {
                code: "GM003",
                message: "AI-agent Co-authored-by trailer detected".to_owned(),
            });
        }

        if [
            "generated with claude code",
            "generated with cursor",
            "generated with codex",
            "generated-by:",
            "made-with:",
        ]
        .iter()
        .any(|pattern| lower.contains(pattern))
        {
            out.push(Finding {
                code: "GM004",
                message: "AI-tool attribution signature detected".to_owned(),
            });
        }
    }

    out
}

fn credential_remote_reason(url: &str) -> Option<&'static str> {
    let lower = url.to_ascii_lowercase();
    if ["github_pat_", "ghp_", "glpat-", "?token=", "&token="]
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        return Some("credential-like token detected in Git remote URL");
    }

    let scheme_end = url.find("://")? + 3;
    let authority = url.get(scheme_end..)?.split('/').next()?;
    let userinfo = authority.split('@').next()?;
    if authority.contains('@') && userinfo.contains(':') {
        return Some("username/password credentials detected in Git remote URL");
    }

    None
}

pub fn remote_findings(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for line in text.lines() {
        let url = line.split_whitespace().nth(1).unwrap_or(line);
        if let Some(reason) = credential_remote_reason(url) {
            out.push(Finding {
                code: "GM005",
                message: reason.to_owned(),
            });
            break;
        }
    }
    out
}

fn git_output(path: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .map_err(|error| format!("failed to launch git: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            "git command failed".to_owned()
        } else {
            stderr
        });
    }
    String::from_utf8(output.stdout).map_err(|error| format!("git output was not UTF-8: {error}"))
}

pub fn scan_repository(
    path: &Path,
    revision: Option<&str>,
    policy: Policy,
) -> Result<Vec<(String, Finding)>, String> {
    let revision = revision.unwrap_or("HEAD");
    let log = git_output(
        path,
        &["log", "--max-count=50", "--format=%x1e%H%x1f%B", revision],
    )?;

    let mut findings = Vec::new();
    for record in log
        .split('\u{1e}')
        .filter(|record| !record.trim().is_empty())
    {
        let Some((sha, body)) = record.split_once('\u{1f}') else {
            continue;
        };
        let sha = sha.trim().to_owned();
        for finding in message_findings(body, policy) {
            findings.push((sha.clone(), finding));
        }
    }

    let remotes = git_output(path, &["remote", "-v"])?;
    for finding in remote_findings(&remotes) {
        findings.push(("repository config".to_owned(), finding));
    }

    Ok(findings)
}

pub fn check_commit_message(path: &Path, policy: Policy) -> Result<Vec<Finding>, String> {
    let text = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read commit message '{}': {error}",
            path.display()
        )
    })?;
    Ok(message_findings(&text, policy))
}

#[cfg(test)]
mod tests {
    use super::{message_findings, remote_findings, Policy};

    #[test]
    fn privacy_policy_blocks_claude_session_urls() {
        let findings = message_findings(
            "Fix parser\n\nClaude-Session: https://claude.ai/code/session_abc123",
            Policy::Privacy,
        );
        assert!(findings.iter().any(|finding| finding.code == "GM001"));
    }

    #[test]
    fn privacy_policy_allows_plain_ai_attribution() {
        let findings = message_findings(
            "Fix parser\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            Policy::Privacy,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn clean_policy_flags_agent_coauthor() {
        let findings = message_findings(
            "Fix parser\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            Policy::Clean,
        );
        assert!(findings.iter().any(|finding| finding.code == "GM003"));
    }

    #[test]
    fn clean_policy_flags_codex_session_id() {
        let findings = message_findings("Codex-Session-Id: ses_123", Policy::Clean);
        assert!(findings.iter().any(|finding| finding.code == "GM002"));
    }

    #[test]
    fn remote_scanner_flags_embedded_pat() {
        let findings =
            remote_findings("origin https://github_pat_123456@github.com/example/repo.git (fetch)");
        assert!(findings.iter().any(|finding| finding.code == "GM005"));
    }

    #[test]
    fn remote_scanner_allows_normal_https_remote() {
        let findings = remote_findings("origin https://github.com/example/repo.git (fetch)");
        assert!(findings.is_empty());
    }
}
