use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Value};

use super::{Criterion, MatchSpec, get_map_path};

impl<'de> Deserialize<'de> for MatchSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| de::Error::custom("match must be a JSON object"))?;
        let mut parser = MatchParser::new(object);

        parser.parse_type()?;
        parser.parse_string_eq("reason_code", &["reason_code"], "reason_code")?;
        parser.parse_string_in("severity_in", &["severity"], &["severity"], "severity_in")?;
        parser.parse_string_in(
            "confidence_band_in",
            &["confidence_band"],
            &["confidence_band"],
            "confidence_band_in",
        )?;
        parser.parse_array_includes(
            "objects.paths_include",
            &["objects", "paths_include"],
            &["objects", "paths"],
            "objects.paths_include",
        )?;
        parser.parse_array_includes(
            "objects.ips_include",
            &["objects", "ips_include"],
            &["objects", "ips"],
            "objects.ips_include",
        )?;
        parser.parse_array_includes(
            "objects.ports_include",
            &["objects", "ports_include"],
            &["objects", "ports"],
            "objects.ports_include",
        )?;
        parser.parse_evidence_kind()?;
        parser.parse_string_in(
            "fallback.mode_in",
            &["fallback", "mode_in"],
            &["fallback", "mode"],
            "fallback.mode_in",
        )?;
        parser.parse_string_in(
            "fallback.visibility_in",
            &["fallback", "visibility_in"],
            &["fallback", "visibility"],
            "fallback.visibility_in",
        )?;
        parser.parse_string_in(
            "fallback.prompt_evidence_in",
            &["fallback", "prompt_evidence_in"],
            &["fallback", "prompt_evidence"],
            "fallback.prompt_evidence_in",
        )?;
        parser.parse_string_in(
            "capture.mode_in",
            &["capture", "mode_in"],
            &["capture", "mode"],
            "capture.mode_in",
        )?;
        parser.parse_string_in(
            "capture.redaction_in",
            &["capture", "redaction_in"],
            &["capture", "redaction"],
            "capture.redaction_in",
        )?;
        parser.parse_objects_length_gte()?;
        parser.parse_present()?;
        parser.parse_numeric_gte()?;
        parser.parse_sessions_differ()?;
        parser.parse_not_contains_text()?;
        parser.finish()
    }
}

struct MatchParser<'a> {
    root: &'a Map<String, Value>,
    used: Vec<String>,
    criteria: Vec<Criterion>,
}

impl<'a> MatchParser<'a> {
    fn new(root: &'a Map<String, Value>) -> Self {
        Self {
            root,
            used: Vec::new(),
            criteria: Vec::new(),
        }
    }

    fn parse_type<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        if let Some(value) = self.root.get("type") {
            self.used.push("type".to_string());
            self.criteria
                .push(Criterion::Type(expect_string::<E>(value, "type")?));
        }
        Ok(())
    }

    fn parse_string_eq<E>(
        &mut self,
        dotted_key: &'static str,
        actual_path: &'static [&'static str],
        label: &'static str,
    ) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        if let Some(value) = self.root.get(dotted_key) {
            self.used.push(dotted_key.to_string());
            self.criteria.push(Criterion::FieldIn {
                path: actual_path,
                label,
                values: vec![expect_string::<E>(value, label)?],
            });
        }
        Ok(())
    }

    fn parse_string_in<E>(
        &mut self,
        dotted_key: &'static str,
        nested_path: &[&str],
        actual_path: &'static [&'static str],
        label: &'static str,
    ) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        if let Some((key, value)) = self.lookup(dotted_key, nested_path) {
            self.used.push(key);
            self.criteria.push(Criterion::FieldIn {
                path: actual_path,
                label,
                values: expect_string_array::<E>(value, label)?,
            });
        }
        Ok(())
    }

    fn parse_array_includes<E>(
        &mut self,
        dotted_key: &'static str,
        nested_path: &[&str],
        actual_path: &'static [&'static str],
        label: &'static str,
    ) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        if let Some((key, value)) = self.lookup(dotted_key, nested_path) {
            self.used.push(key);
            self.criteria.push(Criterion::ArrayIncludes {
                path: actual_path,
                label,
                values: expect_array::<E>(value, label)?,
            });
        }
        Ok(())
    }

    fn parse_evidence_kind<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        if let Some((key, value)) = self.lookup("evidence.has_kind", &["evidence", "has_kind"]) {
            self.used.push(key);
            if value.is_array() {
                self.criteria
                    .push(Criterion::EvidenceHasKinds(expect_string_array::<E>(
                        value,
                        "evidence.has_kind",
                    )?));
            } else {
                self.criteria
                    .push(Criterion::EvidenceHasKind(expect_string::<E>(
                        value,
                        "evidence.has_kind",
                    )?));
            }
        }
        Ok(())
    }

    fn parse_objects_length_gte<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        let Some(objects) = self.root.get("objects").and_then(Value::as_object) else {
            self.parse_dotted_objects_length_gte::<E>()?;
            return Ok(());
        };

        for (field, field_value) in objects {
            if field.ends_with("_include") {
                continue;
            }
            let Some(length_gte) = field_value
                .as_object()
                .and_then(|value| value.get("length_gte"))
            else {
                continue;
            };
            let label = format!("objects.{field}.length_gte");
            self.used.push(format!("objects.{field}.length_gte"));
            self.criteria.push(Criterion::LengthGte {
                path: vec!["objects".to_string(), field.clone()],
                min: expect_usize::<E>(length_gte, &label)?,
                label,
            });
        }

        self.parse_dotted_objects_length_gte::<E>()?;
        Ok(())
    }

    fn parse_present<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        for key in [
            "objects.chain_id.present",
            "objects.root_session_id.present",
            "objects.downstream_session_id.present",
        ] {
            let Some(value) = self.root.get(key) else {
                continue;
            };
            if value.as_bool() != Some(true) {
                return Err(E::custom(format!("{key} only supports true")));
            }
            self.used.push(key.to_string());
            self.criteria.push(Criterion::Present {
                path: key
                    .trim_end_matches(".present")
                    .split('.')
                    .map(ToOwned::to_owned)
                    .collect(),
                label: key.to_string(),
            });
        }
        Ok(())
    }

    fn parse_numeric_gte<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        if let Some(value) = self.root.get("causal_score_gte") {
            self.used.push("causal_score_gte".to_string());
            self.criteria.push(Criterion::NumericGte {
                path: vec![
                    "policy".to_string(),
                    "component_scores".to_string(),
                    "causal_score".to_string(),
                ],
                min: expect_f64::<E>(value, "causal_score_gte")?,
                label: "causal_score_gte".to_string(),
            });
        }
        self.parse_component_score_gte::<E>()?;
        Ok(())
    }

    fn parse_component_score_gte<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        for (key, value) in self.root {
            let Some(score_name) = key
                .strip_prefix("policy.component_scores.")
                .and_then(|remaining| remaining.strip_suffix("_gte"))
            else {
                continue;
            };
            let label = key.clone();
            self.used.push(label.clone());
            self.criteria.push(Criterion::NumericGte {
                path: vec![
                    "policy".to_string(),
                    "component_scores".to_string(),
                    score_name.to_string(),
                ],
                min: expect_f64::<E>(value, &label)?,
                label,
            });
        }

        let Some(scores) =
            get_map_path(self.root, &["policy", "component_scores"]).and_then(Value::as_object)
        else {
            return Ok(());
        };
        for (field, value) in scores {
            let Some(score_name) = field.strip_suffix("_gte") else {
                continue;
            };
            let label = format!("policy.component_scores.{field}");
            self.used.push(label.clone());
            self.criteria.push(Criterion::NumericGte {
                path: vec![
                    "policy".to_string(),
                    "component_scores".to_string(),
                    score_name.to_string(),
                ],
                min: expect_f64::<E>(value, &label)?,
                label,
            });
        }
        Ok(())
    }

    fn parse_sessions_differ<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        let Some(value) = self.root.get("objects.sessions_differ") else {
            return Ok(());
        };
        if value.as_bool() != Some(true) {
            return Err(E::custom("objects.sessions_differ only supports true"));
        }
        self.used.push("objects.sessions_differ".to_string());
        self.criteria.push(Criterion::SessionsDiffer);
        Ok(())
    }

    fn parse_not_contains_text<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        let Some(value) = self.root.get("not_contains_text") else {
            return Ok(());
        };
        self.used.push("not_contains_text".to_string());
        let values = if value.is_array() {
            expect_string_array::<E>(value, "not_contains_text")?
        } else {
            vec![expect_string::<E>(value, "not_contains_text")?]
        };
        self.criteria.push(Criterion::NotContainsText(values));
        Ok(())
    }

    fn parse_dotted_objects_length_gte<E>(&mut self) -> std::result::Result<(), E>
    where
        E: de::Error,
    {
        for (key, value) in self.root {
            let Some(field) = key
                .strip_prefix("objects.")
                .and_then(|remaining| remaining.strip_suffix(".length_gte"))
            else {
                continue;
            };
            let label = key.clone();
            self.used.push(label.clone());
            self.criteria.push(Criterion::LengthGte {
                path: vec!["objects".to_string(), field.to_string()],
                min: expect_usize::<E>(value, &label)?,
                label,
            });
        }
        Ok(())
    }

    fn finish<E>(self) -> std::result::Result<MatchSpec, E>
    where
        E: de::Error,
    {
        if self.criteria.is_empty() {
            return Err(E::custom("match must contain at least one supported key"));
        }
        let unknown = collect_unknown_keys(self.root, &self.used);
        if !unknown.is_empty() {
            return Err(E::custom(format!(
                "unsupported match key(s): {}; supported keys are type, reason_code, severity_in, confidence_band_in, objects.paths_include, objects.ips_include, objects.ports_include, objects.<field>.length_gte, evidence.has_kind, fallback.mode_in, fallback.visibility_in, fallback.prompt_evidence_in, capture.mode_in, capture.redaction_in, causal_score_gte, policy.component_scores.<name>_gte, objects.sessions_differ, not_contains_text",
                unknown.join(", ")
            )));
        }
        Ok(MatchSpec::new(self.criteria))
    }

    fn lookup(
        &self,
        dotted_key: &'static str,
        nested_path: &[&str],
    ) -> Option<(String, &'a Value)> {
        self.root
            .get(dotted_key)
            .map(|value| (dotted_key.to_string(), value))
            .or_else(|| {
                get_map_path(self.root, nested_path).map(|value| (nested_path.join("."), value))
            })
    }
}

fn expect_string<E>(value: &Value, label: &str) -> std::result::Result<String, E>
where
    E: de::Error,
{
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| E::custom(format!("{label} must be a string")))
}

fn expect_string_array<E>(value: &Value, label: &str) -> std::result::Result<Vec<String>, E>
where
    E: de::Error,
{
    let values = expect_array::<E>(value, label)?;
    values
        .into_iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| E::custom(format!("{label} must contain only strings")))
        })
        .collect()
}

fn expect_array<E>(value: &Value, label: &str) -> std::result::Result<Vec<Value>, E>
where
    E: de::Error,
{
    value
        .as_array()
        .cloned()
        .ok_or_else(|| E::custom(format!("{label} must be an array")))
}

fn expect_usize<E>(value: &Value, label: &str) -> std::result::Result<usize, E>
where
    E: de::Error,
{
    let number = value
        .as_u64()
        .ok_or_else(|| E::custom(format!("{label} must be a non-negative integer")))?;
    usize::try_from(number).map_err(|_| E::custom(format!("{label} is too large")))
}

fn expect_f64<E>(value: &Value, label: &str) -> std::result::Result<f64, E>
where
    E: de::Error,
{
    value
        .as_f64()
        .ok_or_else(|| E::custom(format!("{label} must be a number")))
}

fn collect_unknown_keys(root: &Map<String, Value>, used: &[String]) -> Vec<String> {
    let mut unknown = Vec::new();
    for (key, value) in root {
        if used.iter().any(|used| used == key) {
            continue;
        }
        if key == "objects"
            || key == "fallback"
            || key == "evidence"
            || key == "capture"
            || key == "policy"
        {
            collect_unknown_nested_keys(key, value, used, &mut unknown);
        } else {
            unknown.push(key.clone());
        }
    }
    unknown
}

fn collect_unknown_nested_keys(
    prefix: &str,
    value: &Value,
    used: &[String],
    unknown: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        unknown.push(prefix.to_string());
        return;
    };
    for (key, nested_value) in object {
        let path = format!("{prefix}.{key}");
        if used
            .iter()
            .any(|used| used == &path || used.starts_with(&format!("{path}.")))
        {
            continue;
        }
        if nested_value.is_object() {
            collect_unknown_nested_keys(&path, nested_value, used, unknown);
        } else {
            unknown.push(path);
        }
    }
}
