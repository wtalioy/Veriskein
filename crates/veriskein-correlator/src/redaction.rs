use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RedactionMode {
    None,
    Masked,
}

impl RedactionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Masked => "masked",
        }
    }
}

pub fn redact_excerpt(bytes: &[u8]) -> (Vec<u8>, RedactionMode) {
    let text = String::from_utf8_lossy(bytes);
    let (redacted, mode) = redact_excerpt_string(&text);
    (redacted.into_bytes(), mode)
}

pub fn redact_excerpt_string(text: &str) -> (String, RedactionMode) {
    let mut changed = false;
    let mut out = Vec::new();
    let mut in_pem = false;
    for token in text.split_whitespace() {
        let masked = if token.contains("-----BEGIN") || token.contains("-----END") {
            in_pem = !token.contains("-----END");
            changed = true;
            "[REDACTED_PEM]"
        } else if in_pem {
            changed = true;
            "[REDACTED_PEM]"
        } else if is_secret_like(token) {
            changed = true;
            "[REDACTED_SECRET]"
        } else if token.starts_with("/home/") {
            changed = true;
            "/home/[REDACTED]"
        } else {
            token
        };
        if out.last().is_some_and(|last| *last == masked) && masked.starts_with("[REDACTED_") {
            continue;
        }
        out.push(masked);
    }
    (
        out.join(" "),
        if changed {
            RedactionMode::Masked
        } else {
            RedactionMode::None
        },
    )
}

fn is_secret_like(token: &str) -> bool {
    let trimmed =
        token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-');
    trimmed.starts_with("sk-")
        || trimmed.starts_with("AKIA")
        || (trimmed.len() >= 32 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()))
        || (trimmed.len() >= 40
            && trimmed
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-')))
}

#[cfg(test)]
mod tests {
    use super::{RedactionMode, redact_excerpt_string};

    #[test]
    fn masks_secret_shapes() {
        let (text, mode) = redact_excerpt_string(
            "key sk-test1234567890 /home/alice/.ssh/id_rsa deadbeefdeadbeefdeadbeefdeadbeef",
        );
        assert_eq!(mode, RedactionMode::Masked);
        assert!(text.contains("[REDACTED_SECRET]"));
        assert!(text.contains("/home/[REDACTED]"));
        assert!(!text.contains("sk-test"));
        assert!(!text.contains("alice"));
    }
}
