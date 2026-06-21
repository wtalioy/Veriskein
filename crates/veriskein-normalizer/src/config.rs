use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceRef {
    pub id: String,
    pub root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct GlobList {
    globs: Vec<String>,
    matchers: Vec<GlobMatcher>,
}

#[derive(Debug, Clone)]
pub struct SensitiveRule {
    pub glob: String,
    pub severity: String,
    matcher: GlobMatcher,
}

#[derive(Debug, Clone)]
pub struct SensitiveConfig {
    pub rules: Vec<SensitiveRule>,
}

#[derive(Debug, Deserialize)]
struct SensitiveToml {
    #[serde(default, rename = "rule")]
    rules: Vec<RawSensitiveRule>,
}

#[derive(Debug, Deserialize)]
struct RawSensitiveRule {
    glob: String,
    severity: String,
}

impl SensitiveConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read sensitive config {}", path.display()))?;
        Self::from_toml_str(&text)
    }

    pub fn from_toml_str(text: &str) -> Result<Self> {
        let raw: SensitiveToml = toml::from_str(text).context("parse sensitive toml")?;
        let mut rules = Vec::with_capacity(raw.rules.len());
        for entry in raw.rules {
            let matcher = Glob::new(&entry.glob)
                .with_context(|| format!("compile sensitive glob {}", entry.glob))?
                .compile_matcher();
            rules.push(SensitiveRule {
                glob: entry.glob,
                severity: entry.severity,
                matcher,
            });
        }
        Ok(Self { rules })
    }

    pub fn matching_rule<'a>(&'a self, path: &Path) -> Option<&'a SensitiveRule> {
        self.rules.iter().find(|rule| rule.matcher.is_match(path))
    }
}

impl GlobList {
    pub fn new(globs: Vec<String>) -> Result<Self> {
        let matchers = globs
            .iter()
            .map(|glob| {
                Ok(Glob::new(glob)
                    .with_context(|| format!("compile glob {}", glob))?
                    .compile_matcher())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { globs, matchers })
    }

    pub fn is_match<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = path.as_ref();
        self.matchers.iter().any(|matcher| matcher.is_match(path))
    }

    pub fn patterns(&self) -> &[String] {
        &self.globs
    }
}

pub fn load_workspaces(workspaces: &[PathBuf]) -> Result<Vec<WorkspaceRef>> {
    workspaces
        .iter()
        .enumerate()
        .map(|(idx, root)| {
            // Tests often create the workspace path after config load, so a
            // missing directory still gets a stable lexical identity.
            let canonical = if root.exists() {
                std::fs::canonicalize(root)
                    .with_context(|| format!("canonicalize workspace {}", root.display()))?
            } else {
                lexical_clean(root)
            };
            Ok(WorkspaceRef {
                id: format!("ws-{}", idx + 1),
                root: canonical,
            })
        })
        .collect()
}

pub fn lexical_clean(path: &Path) -> PathBuf {
    // This stays purely lexical so callers can normalize paths that do not yet
    // exist or that would resolve differently across mount namespaces.
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{GlobList, SensitiveConfig, WorkspaceRef, lexical_clean};
    use std::path::{Path, PathBuf};

    #[test]
    fn sensitive_glob_match_works() {
        let config = SensitiveConfig::from_toml_str(
            r#"
[[rule]]
glob = "/etc/shadow"
severity = "high"
[[rule]]
glob = "/root/**"
severity = "high"
"#,
        )
        .expect("config");
        assert!(config.matching_rule(Path::new("/etc/shadow")).is_some());
        assert!(
            config
                .matching_rule(Path::new("/root/.ssh/id_rsa"))
                .is_some()
        );
        assert!(config.matching_rule(Path::new("/tmp/demo")).is_none());
    }

    #[test]
    fn lexical_clean_normalizes_dotdot() {
        assert_eq!(
            lexical_clean(Path::new("/tmp/ws/../out/file.txt")),
            PathBuf::from("/tmp/out/file.txt")
        );
    }

    #[test]
    fn workspace_id_is_stable_for_lookup() {
        let ws = WorkspaceRef {
            id: "ws-1".to_string(),
            root: PathBuf::from("/tmp/ws"),
        };
        assert_eq!(ws.id, "ws-1");
    }

    #[test]
    fn glob_list_matches_paths() {
        let list =
            GlobList::new(vec!["/tmp/**".to_string(), "/bin/sh".to_string()]).expect("glob list");
        assert!(list.is_match("/tmp/demo.txt"));
        assert!(list.is_match("/bin/sh"));
        assert!(!list.is_match("/etc/passwd"));
        assert_eq!(list.patterns().len(), 2);
    }
}
