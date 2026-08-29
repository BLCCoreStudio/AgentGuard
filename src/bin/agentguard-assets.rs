use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    code: &'static str,
    path: PathBuf,
    message: String,
}

fn prompt_risks(text: &str) -> Vec<(&'static str, &'static str)> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();

    if lower.contains("ignore previous instructions")
        || lower.contains("ignore all previous instructions")
    {
        out.push(("AS101", "instruction-override phrase detected"));
    }
    if lower.contains("reveal your system prompt") || lower.contains("show your system prompt") {
        out.push(("AS102", "system-prompt extraction phrase detected"));
    }
    if lower.contains("send")
        && (lower.contains("api key") || lower.contains("private key") || lower.contains("token"))
    {
        out.push(("AS103", "possible secret-exfiltration instruction detected"));
    }
    if text
        .chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    {
        out.push(("AS104", "bidirectional-control character detected"));
    }

    out
}

fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn frontmatter_value<'a>(frontmatter: &'a str, key: &str) -> Option<&'a str> {
    frontmatter.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        if candidate.trim() == key {
            Some(value.trim().trim_matches('"').trim_matches('\''))
        } else {
            None
        }
    })
}

fn skill_findings(path: &Path, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut lines = text.lines();

    if lines.next() != Some("---") {
        findings.push(Finding {
            code: "AS001",
            path: path.to_path_buf(),
            message: "SKILL.md must start with YAML frontmatter".to_owned(),
        });
        return findings;
    }

    let rest: Vec<&str> = lines.collect();
    let Some(end) = rest.iter().position(|line| *line == "---") else {
        findings.push(Finding {
            code: "AS002",
            path: path.to_path_buf(),
            message: "SKILL.md frontmatter is missing its closing delimiter".to_owned(),
        });
        return findings;
    };

    let frontmatter = rest[..end].join("\n");
    let body = rest[end + 1..].join("\n");

    match frontmatter_value(&frontmatter, "name") {
        None | Some("") => findings.push(Finding {
            code: "AS003",
            path: path.to_path_buf(),
            message: "required frontmatter field 'name' is missing".to_owned(),
        }),
        Some(name) => {
            if !valid_skill_name(name) {
                findings.push(Finding {
                    code: "AS004",
                    path: path.to_path_buf(),
                    message: format!(
                        "skill name '{name}' must be 1-64 lowercase letters, numbers, or hyphens; it cannot start/end with a hyphen or contain '--'"
                    ),
                });
            }
            if let Some(parent) = path.parent().and_then(Path::file_name).and_then(|v| v.to_str()) {
                if parent != name {
                    findings.push(Finding {
                        code: "AS005",
                        path: path.to_path_buf(),
                        message: format!(
                            "skill name '{name}' does not match parent directory '{parent}'"
                        ),
                    });
                }
            }
        }
    }

    match frontmatter_value(&frontmatter, "description") {
        None | Some("") => findings.push(Finding {
            code: "AS006",
            path: path.to_path_buf(),
            message: "required frontmatter field 'description' is missing".to_owned(),
        }),
        Some(description) if description.len() > 1024 => findings.push(Finding {
            code: "AS007",
            path: path.to_path_buf(),
            message: "description exceeds the Agent Skills 1024-character limit".to_owned(),
        }),
        _ => {}
    }

    if let Some(compatibility) = frontmatter_value(&frontmatter, "compatibility") {
        if compatibility.len() > 500 {
            findings.push(Finding {
                code: "AS008",
                path: path.to_path_buf(),
                message: "compatibility exceeds the Agent Skills 500-character limit".to_owned(),
            });
        }
    }

    if body.lines().count() > 500 {
        findings.push(Finding {
            code: "AS009",
            path: path.to_path_buf(),
            message: "SKILL.md body exceeds the recommended 500-line size; consider progressive disclosure"
                .to_owned(),
        });
    }

    for (code, message) in prompt_risks(text) {
        findings.push(Finding {
            code,
            path: path.to_path_buf(),
            message: message.to_owned(),
        });
    }

    findings
}

fn agents_findings(path: &Path, text: &str) -> Vec<Finding> {
    prompt_risks(text)
        .into_iter()
        .map(|(code, message)| Finding {
            code,
            path: path.to_path_buf(),
            message: message.to_owned(),
        })
        .collect()
}

fn collect_assets(root: &Path, assets: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(root)
        .map_err(|error| format!("failed to read '{}': {error}", root.display()))?;

    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to read directory entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect '{}': {error}", path.display()))?;

        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_assets(&path, assets)?;
            continue;
        }
        if matches!(path.file_name().and_then(|v| v.to_str()), Some("AGENTS.md" | "SKILL.md")) {
            assets.push(path);
        }
    }

    Ok(())
}

fn audit(root: &Path) -> Result<(usize, Vec<Finding>), String> {
    if !root.is_dir() {
        return Err(format!("'{}' is not a directory", root.display()));
    }

    let mut assets = Vec::new();
    collect_assets(root, &mut assets)?;
    assets.sort();

    let mut findings = Vec::new();
    for path in &assets {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("failed to read '{}': {error}", path.display()))?;
        match path.file_name().and_then(|v| v.to_str()) {
            Some("SKILL.md") => findings.extend(skill_findings(path, &text)),
            Some("AGENTS.md") => findings.extend(agents_findings(path, &text)),
            _ => {}
        }
    }

    Ok((assets.len(), findings))
}

fn help() {
    println!(
        "agentguard-assets 0.2.0-dev\n\nUSAGE:\n  agentguard-assets <DIRECTORY>\n\nAudits AGENTS.md and SKILL.md files for a focused set of Agent Skills format checks and high-signal prompt-risk patterns. This is an experimental lint/risk signal, not proof that agent instructions are safe."
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        help();
        return;
    }
    if matches!(args[0].as_str(), "--version" | "-V") {
        println!("agentguard-assets 0.2.0-dev");
        return;
    }
    if args.len() != 1 {
        eprintln!("agentguard-assets: expected exactly one directory");
        process::exit(2);
    }

    match audit(Path::new(&args[0])) {
        Ok((checked, findings)) if findings.is_empty() => {
            println!("PASS: checked {checked} agent asset(s); no current rule matched");
        }
        Ok((checked, findings)) => {
            println!("WARN: checked {checked} agent asset(s); {} finding(s)", findings.len());
            for finding in findings {
                println!("- {} {}: {}", finding.code, finding.path.display(), finding.message);
            }
            process::exit(3);
        }
        Err(error) => {
            eprintln!("agentguard-assets: {error}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{skill_findings, valid_skill_name};
    use std::path::Path;

    #[test]
    fn accepts_spec_style_skill_names() {
        assert!(valid_skill_name("code-review"));
        assert!(valid_skill_name("pdf2"));
    }

    #[test]
    fn rejects_invalid_skill_names() {
        assert!(!valid_skill_name("Code-Review"));
        assert!(!valid_skill_name("-code-review"));
        assert!(!valid_skill_name("code--review"));
    }

    #[test]
    fn accepts_minimal_valid_skill() {
        let text = "---\nname: code-review\ndescription: Reviews code when asked for a focused review.\n---\n# Review\n";
        assert!(skill_findings(Path::new("skills/code-review/SKILL.md"), text).is_empty());
    }

    #[test]
    fn detects_directory_name_mismatch() {
        let text = "---\nname: code-review\ndescription: Reviews code when asked for a focused review.\n---\n# Review\n";
        let findings = skill_findings(Path::new("skills/other-name/SKILL.md"), text);
        assert!(findings.iter().any(|finding| finding.code == "AS005"));
    }

    #[test]
    fn detects_missing_frontmatter() {
        let findings = skill_findings(Path::new("skills/demo/SKILL.md"), "# No frontmatter");
        assert!(findings.iter().any(|finding| finding.code == "AS001"));
    }
}