use crate::git_metadata::{Finding, Policy};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const CONFIG_NAME: &str = ".agentguard.toml";
const HOOK_MARKER: &str = "# agentguard-managed-hook";

pub fn parse_policy_config(text: &str) -> Result<Policy, String> {
    let mut policy = None;

    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "unsupported {CONFIG_NAME} syntax on line {}",
                index + 1
            ));
        };
        if key.trim() != "git_metadata_policy" {
            return Err(format!(
                "unsupported {CONFIG_NAME} key '{}' on line {}",
                key.trim(),
                index + 1
            ));
        }
        if policy.is_some() {
            return Err(format!(
                "duplicate git_metadata_policy in {CONFIG_NAME} on line {}",
                index + 1
            ));
        }

        let value = value.trim();
        if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
            return Err(format!(
                "git_metadata_policy must be a quoted string in {CONFIG_NAME}"
            ));
        }
        policy = Some(Policy::parse(&value[1..value.len() - 1])?);
    }

    Ok(policy.unwrap_or(Policy::Privacy))
}

pub fn resolve_policy(repo: &Path, explicit: Option<Policy>) -> Result<Policy, String> {
    if let Some(policy) = explicit {
        return Ok(policy);
    }

    let root = repository_root(repo)?;
    let config = root.join(CONFIG_NAME);
    if !config.exists() {
        return Ok(Policy::Privacy);
    }

    let text = fs::read_to_string(&config)
        .map_err(|error| format!("failed to read '{}': {error}", config.display()))?;
    parse_policy_config(&text)
}

pub fn write_policy_config(repo: &Path, policy: Policy) -> Result<PathBuf, String> {
    let root = repository_root(repo)?;
    let path = root.join(CONFIG_NAME);
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing '{}'; edit it explicitly instead",
            path.display()
        ));
    }

    let value = match policy {
        Policy::Privacy => "privacy",
        Policy::Clean => "clean",
    };
    let content = format!(
        "# AgentGuard repository policy\n# Supported values: privacy, clean\ngit_metadata_policy = \"{value}\"\n"
    );
    fs::write(&path, content)
        .map_err(|error| format!("failed to write '{}': {error}", path.display()))?;
    Ok(path)
}

fn git_command(path: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .map_err(|error| format!("failed to launch git: {error}"))
}

fn git_output(path: &Path, args: &[&str]) -> Result<String, String> {
    let output = git_command(path, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            "git command failed".to_owned()
        } else {
            stderr
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_optional_output(path: &Path, args: &[&str]) -> Result<Option<String>, String> {
    let output = git_command(path, args)?;
    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        return Ok((!value.is_empty()).then_some(value));
    }
    if output.status.code() == Some(1) && output.stderr.is_empty() {
        return Ok(None);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(if stderr.is_empty() {
        "git command failed".to_owned()
    } else {
        stderr
    })
}

fn repository_root(path: &Path) -> Result<PathBuf, String> {
    let root = git_output(path, &["rev-parse", "--show-toplevel"])?;
    if root.is_empty() {
        return Err("git did not return a repository root".to_owned());
    }
    Ok(PathBuf::from(root))
}

fn hooks_directory(root: &Path) -> Result<PathBuf, String> {
    if let Some(configured) =
        git_optional_output(root, &["config", "--path", "--get", "core.hooksPath"])?
    {
        let path = PathBuf::from(configured);
        return Ok(if path.is_absolute() {
            path
        } else {
            root.join(path)
        });
    }

    let raw = PathBuf::from(git_output(root, &["rev-parse", "--git-path", "hooks"])?);
    Ok(if raw.is_absolute() {
        raw
    } else {
        root.join(raw)
    })
}

pub fn managed_hook_script() -> &'static str {
    "#!/bin/sh\n# agentguard-managed-hook\nrepo=\"$(git rev-parse --show-toplevel 2>/dev/null)\" || exit 0\nexec agentguard check-commit-msg \"$1\" --repo \"$repo\"\n"
}

pub fn install_commit_hook(path: &Path) -> Result<PathBuf, String> {
    let root = repository_root(path)?;
    let hook_path = hooks_directory(&root)?.join("commit-msg");

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path).map_err(|error| {
            format!(
                "failed to inspect existing hook '{}': {error}",
                hook_path.display()
            )
        })?;
        if !existing.contains(HOOK_MARKER) {
            return Err(format!(
                "refusing to overwrite existing unmanaged hook '{}'; integrate AgentGuard manually",
                hook_path.display()
            ));
        }
    }

    if let Some(parent) = hook_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create hook directory '{}': {error}",
                parent.display()
            )
        })?;
    }
    fs::write(&hook_path, managed_hook_script())
        .map_err(|error| format!("failed to write hook '{}': {error}", hook_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&hook_path)
            .map_err(|error| format!("failed to inspect hook permissions: {error}"))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook_path, permissions)
            .map_err(|error| format!("failed to mark hook executable: {error}"))?;
    }

    Ok(hook_path)
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

pub fn repository_findings_json(findings: &[(String, Finding)]) -> String {
    let items = findings
        .iter()
        .map(|(scope, finding)| {
            format!(
                "{{\"code\":\"{}\",\"scope\":\"{}\",\"message\":\"{}\"}}",
                json_escape(finding.code),
                json_escape(scope),
                json_escape(&finding.message)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"ok\":{},\"findings\":[{}]}}",
        if findings.is_empty() { "true" } else { "false" },
        items
    )
}

pub fn commit_findings_json(findings: &[Finding]) -> String {
    let items = findings
        .iter()
        .map(|finding| {
            format!(
                "{{\"code\":\"{}\",\"message\":\"{}\"}}",
                json_escape(finding.code),
                json_escape(&finding.message)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"ok\":{},\"findings\":[{}]}}",
        if findings.is_empty() { "true" } else { "false" },
        items
    )
}

#[cfg(test)]
mod tests {
    use super::{
        commit_findings_json, install_commit_hook, managed_hook_script, parse_policy_config,
        resolve_policy, write_policy_config,
    };
    use crate::git_metadata::{Finding, Policy};
    use std::{
        env, fs,
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_repo(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after unix epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "agentguard-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test repo directory");
        let status = Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(&path)
            .status()
            .expect("launch git init");
        assert!(status.success());
        path
    }

    #[test]
    fn config_defaults_to_privacy() {
        assert_eq!(
            parse_policy_config("# empty policy\n").unwrap(),
            Policy::Privacy
        );
    }

    #[test]
    fn config_accepts_clean_policy() {
        assert_eq!(
            parse_policy_config("git_metadata_policy = \"clean\"\n").unwrap(),
            Policy::Clean
        );
    }

    #[test]
    fn config_rejects_unknown_keys() {
        assert!(parse_policy_config("mystery = \"clean\"\n").is_err());
    }

    #[test]
    fn repository_policy_round_trips_from_git_root() {
        let repo = test_repo("policy");
        let nested = repo.join("nested");
        fs::create_dir_all(&nested).expect("create nested directory");

        let path = write_policy_config(&nested, Policy::Clean).expect("write policy");
        assert_eq!(path, repo.join(".agentguard.toml"));
        assert_eq!(
            resolve_policy(&nested, None).expect("resolve policy"),
            Policy::Clean
        );

        fs::remove_dir_all(repo).expect("remove test repo");
    }

    #[test]
    fn managed_hook_uses_repository_policy() {
        let script = managed_hook_script();
        assert!(script.contains("agentguard-managed-hook"));
        assert!(script.contains("--repo"));
    }

    #[test]
    fn hook_installer_honors_core_hooks_path() {
        let repo = test_repo("hooks-path");
        let status = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["config", "core.hooksPath", ".githooks"])
            .status()
            .expect("configure hooks path");
        assert!(status.success());

        let hook = install_commit_hook(&repo).expect("install managed hook");
        assert_eq!(hook, repo.join(".githooks/commit-msg"));
        assert!(fs::read_to_string(&hook)
            .expect("read managed hook")
            .contains("agentguard-managed-hook"));

        fs::remove_dir_all(repo).expect("remove test repo");
    }

    #[test]
    fn hook_installer_refuses_unmanaged_hook() {
        let repo = test_repo("unmanaged-hook");
        let hooks = repo.join(".git/hooks");
        fs::create_dir_all(&hooks).expect("create hooks directory");
        let hook = hooks.join("commit-msg");
        fs::write(&hook, "#!/bin/sh\necho existing\n").expect("write unmanaged hook");

        let error = install_commit_hook(&repo).expect_err("must refuse unmanaged hook");
        assert!(error.contains("refusing to overwrite existing unmanaged hook"));
        assert_eq!(
            fs::read_to_string(&hook).expect("read unmanaged hook"),
            "#!/bin/sh\necho existing\n"
        );

        fs::remove_dir_all(repo).expect("remove test repo");
    }

    #[test]
    fn json_output_escapes_messages() {
        let json = commit_findings_json(&[Finding {
            code: "GM999",
            message: "quote \" and newline\n".to_owned(),
        }]);
        assert!(json.contains("\\\""));
        assert!(json.contains("\\n"));
        assert!(json.contains("\"ok\":false"));
    }
}
