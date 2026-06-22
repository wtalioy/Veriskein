//! Performance report types and rendering helpers.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Default title used by generated performance reports.
pub const DEFAULT_REPORT_TITLE: &str = "Veriskein Performance Report";

/// Runtime mode measured by the performance harness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PerfMode {
    #[serde(rename = "baseline")]
    Baseline,
    #[serde(rename = "kernel-only")]
    KernelOnly,
    #[serde(rename = "kernel+tls")]
    KernelTls,
    #[serde(rename = "full")]
    Full,
}

impl PerfMode {
    pub const ALL: [Self; 4] = [
        Self::Baseline,
        Self::KernelOnly,
        Self::KernelTls,
        Self::Full,
    ];

    pub const MEASURED: [Self; 3] = [Self::KernelOnly, Self::KernelTls, Self::Full];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::KernelOnly => "kernel-only",
            Self::KernelTls => "kernel+tls",
            Self::Full => "full",
        }
    }
}

impl fmt::Display for PerfMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PerfMode {
    type Err = ParsePerfModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "kernel-only" => Ok(Self::KernelOnly),
            "kernel+tls" => Ok(Self::KernelTls),
            "full" => Ok(Self::Full),
            _ => Err(ParsePerfModeError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsePerfModeError;

impl fmt::Display for ParsePerfModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown performance mode")
    }
}

impl std::error::Error for ParsePerfModeError {}

/// Raw performance counters for one harness mode.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PerfMeasurement {
    pub duration_ms: f64,
    pub events_total: u64,
    pub drops_total: u64,
    pub alerts_total: u64,
    pub rss_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
}

impl PerfMeasurement {
    pub const fn new(
        duration_ms: f64,
        events_total: u64,
        drops_total: u64,
        alerts_total: u64,
        rss_bytes: u64,
    ) -> Self {
        Self {
            duration_ms,
            events_total,
            drops_total,
            alerts_total,
            rss_bytes,
            cpu_percent: None,
        }
    }

    pub const fn with_cpu_percent(mut self, cpu_percent: f64) -> Self {
        self.cpu_percent = Some(cpu_percent);
        self
    }
}

/// Numeric delta between a measured mode and the baseline mode.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetricDelta {
    pub baseline: f64,
    pub measured: f64,
    pub delta: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overhead_percent: Option<f64>,
}

impl MetricDelta {
    pub fn new(baseline: f64, measured: f64) -> Self {
        let delta = measured - baseline;
        let overhead_percent = if baseline.abs() < f64::EPSILON {
            if measured.abs() < f64::EPSILON {
                Some(0.0)
            } else {
                None
            }
        } else {
            Some((delta / baseline) * 100.0)
        };

        Self {
            baseline,
            measured,
            delta,
            overhead_percent,
        }
    }
}

/// Comparison for one non-baseline mode.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PerfComparison {
    pub mode: PerfMode,
    pub duration_ms: MetricDelta,
    pub events_total: MetricDelta,
    pub drops_total: MetricDelta,
    pub alerts_total: MetricDelta,
    pub rss_bytes: MetricDelta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<MetricDelta>,
}

impl PerfComparison {
    pub fn new(mode: PerfMode, baseline: &PerfMeasurement, measured: &PerfMeasurement) -> Self {
        Self {
            mode,
            duration_ms: MetricDelta::new(baseline.duration_ms, measured.duration_ms),
            events_total: MetricDelta::new(
                baseline.events_total as f64,
                measured.events_total as f64,
            ),
            drops_total: MetricDelta::new(baseline.drops_total as f64, measured.drops_total as f64),
            alerts_total: MetricDelta::new(
                baseline.alerts_total as f64,
                measured.alerts_total as f64,
            ),
            rss_bytes: MetricDelta::new(baseline.rss_bytes as f64, measured.rss_bytes as f64),
            cpu_percent: baseline
                .cpu_percent
                .zip(measured.cpu_percent)
                .map(|(baseline, measured)| MetricDelta::new(baseline, measured)),
        }
    }
}

/// Optional thresholds used to mark a performance report as passing or failing.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct PerfBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_duration_overhead_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rss_overhead_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_overhead_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_drops_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_alerts_total: Option<u64>,
}

impl PerfBudget {
    pub const fn empty() -> Self {
        Self {
            max_duration_overhead_percent: None,
            max_rss_overhead_percent: None,
            max_cpu_overhead_percent: None,
            max_drops_total: None,
            max_alerts_total: None,
        }
    }

    pub const fn with_max_duration_overhead_percent(mut self, limit: f64) -> Self {
        self.max_duration_overhead_percent = Some(limit);
        self
    }

    pub const fn with_max_rss_overhead_percent(mut self, limit: f64) -> Self {
        self.max_rss_overhead_percent = Some(limit);
        self
    }

    pub const fn with_max_cpu_overhead_percent(mut self, limit: f64) -> Self {
        self.max_cpu_overhead_percent = Some(limit);
        self
    }

    pub const fn with_max_drops_total(mut self, limit: u64) -> Self {
        self.max_drops_total = Some(limit);
        self
    }

    pub const fn with_max_alerts_total(mut self, limit: u64) -> Self {
        self.max_alerts_total = Some(limit);
        self
    }

    pub fn evaluate(
        &self,
        mode: PerfMode,
        comparison: &PerfComparison,
        measurement: &PerfMeasurement,
    ) -> Vec<BudgetCheck> {
        let mut checks = Vec::new();

        if let Some(limit) = self.max_duration_overhead_percent {
            checks.push(BudgetCheck::percent(
                mode,
                BudgetMetric::DurationOverheadPercent,
                comparison.duration_ms.overhead_percent,
                limit,
            ));
        }
        if let Some(limit) = self.max_rss_overhead_percent {
            checks.push(BudgetCheck::percent(
                mode,
                BudgetMetric::RssOverheadPercent,
                comparison.rss_bytes.overhead_percent,
                limit,
            ));
        }
        if let Some(limit) = self.max_cpu_overhead_percent {
            checks.push(BudgetCheck::percent(
                mode,
                BudgetMetric::CpuOverheadPercent,
                comparison
                    .cpu_percent
                    .and_then(|delta| delta.overhead_percent),
                limit,
            ));
        }
        if let Some(limit) = self.max_drops_total {
            checks.push(BudgetCheck::absolute(
                mode,
                BudgetMetric::DropsTotal,
                measurement.drops_total,
                limit,
            ));
        }
        if let Some(limit) = self.max_alerts_total {
            checks.push(BudgetCheck::absolute(
                mode,
                BudgetMetric::AlertsTotal,
                measurement.alerts_total,
                limit,
            ));
        }

        checks
    }
}

/// Metric covered by a budget check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BudgetMetric {
    #[serde(rename = "duration-overhead-percent")]
    DurationOverheadPercent,
    #[serde(rename = "rss-overhead-percent")]
    RssOverheadPercent,
    #[serde(rename = "cpu-overhead-percent")]
    CpuOverheadPercent,
    #[serde(rename = "drops-total")]
    DropsTotal,
    #[serde(rename = "alerts-total")]
    AlertsTotal,
}

impl BudgetMetric {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DurationOverheadPercent => "duration-overhead-percent",
            Self::RssOverheadPercent => "rss-overhead-percent",
            Self::CpuOverheadPercent => "cpu-overhead-percent",
            Self::DropsTotal => "drops-total",
            Self::AlertsTotal => "alerts-total",
        }
    }
}

impl fmt::Display for BudgetMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result for a single budget threshold.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BudgetCheck {
    pub mode: PerfMode,
    pub metric: BudgetMetric,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<f64>,
    pub limit: f64,
    pub passed: bool,
}

impl BudgetCheck {
    fn percent(mode: PerfMode, metric: BudgetMetric, actual: Option<f64>, limit: f64) -> Self {
        let passed = actual.is_some_and(|actual| actual <= limit);
        Self {
            mode,
            metric,
            actual,
            limit,
            passed,
        }
    }

    fn absolute(mode: PerfMode, metric: BudgetMetric, actual: u64, limit: u64) -> Self {
        Self {
            mode,
            metric,
            actual: Some(actual as f64),
            limit: limit as f64,
            passed: actual <= limit,
        }
    }
}

/// Overall pass/fail result for a configured budget.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BudgetStatus {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "fail")]
    Fail,
}

impl BudgetStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl fmt::Display for BudgetStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reusable performance report input.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PerfReport {
    pub title: String,
    pub measurements: BTreeMap<PerfMode, PerfMeasurement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<PerfBudget>,
}

impl PerfReport {
    pub fn new(measurements: impl IntoIterator<Item = (PerfMode, PerfMeasurement)>) -> Self {
        Self {
            title: DEFAULT_REPORT_TITLE.to_owned(),
            measurements: measurements.into_iter().collect(),
            budget: None,
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_budget(mut self, budget: PerfBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    pub fn baseline(&self) -> Option<&PerfMeasurement> {
        self.measurements.get(&PerfMode::Baseline)
    }

    pub fn comparison(&self, mode: PerfMode) -> Option<PerfComparison> {
        if mode == PerfMode::Baseline {
            return None;
        }

        let baseline = self.baseline()?;
        let measured = self.measurements.get(&mode)?;
        Some(PerfComparison::new(mode, baseline, measured))
    }

    pub fn comparisons(&self) -> Vec<PerfComparison> {
        PerfMode::MEASURED
            .into_iter()
            .filter_map(|mode| self.comparison(mode))
            .collect()
    }

    pub fn budget_checks(&self) -> Vec<BudgetCheck> {
        let Some(budget) = &self.budget else {
            return Vec::new();
        };

        self.comparisons()
            .into_iter()
            .flat_map(|comparison| {
                let Some(measurement) = self.measurements.get(&comparison.mode) else {
                    return Vec::new();
                };
                budget.evaluate(comparison.mode, &comparison, measurement)
            })
            .collect()
    }

    pub fn budget_status(&self) -> Option<BudgetStatus> {
        self.budget.as_ref()?;

        if self.budget_checks().iter().all(|check| check.passed) {
            Some(BudgetStatus::Pass)
        } else {
            Some(BudgetStatus::Fail)
        }
    }

    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.snapshot())
    }

    pub fn to_markdown(&self) -> String {
        let mut markdown = String::new();
        markdown.push_str("# ");
        markdown.push_str(&self.title);
        markdown.push_str("\n\n## Measurements\n");
        markdown.push_str("| mode | duration_ms | events_total | drops_total | alerts_total | rss_bytes | cpu_percent |\n");
        markdown.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");

        for (mode, measurement) in &self.measurements {
            markdown.push_str("| ");
            markdown.push_str(mode.as_str());
            markdown.push_str(" | ");
            markdown.push_str(&format_f64(measurement.duration_ms));
            markdown.push_str(" | ");
            markdown.push_str(&measurement.events_total.to_string());
            markdown.push_str(" | ");
            markdown.push_str(&measurement.drops_total.to_string());
            markdown.push_str(" | ");
            markdown.push_str(&measurement.alerts_total.to_string());
            markdown.push_str(" | ");
            markdown.push_str(&measurement.rss_bytes.to_string());
            markdown.push_str(" | ");
            markdown.push_str(&format_optional_f64(measurement.cpu_percent));
            markdown.push_str(" |\n");
        }

        markdown.push_str("\n## Comparisons vs baseline\n");
        let comparisons = self.comparisons();
        if comparisons.is_empty() {
            markdown.push_str("No comparable measurements are available.\n");
        } else {
            markdown.push_str("| mode | duration overhead | rss overhead | cpu overhead | events delta | drops delta | alerts delta |\n");
            markdown.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
            for comparison in &comparisons {
                markdown.push_str("| ");
                markdown.push_str(comparison.mode.as_str());
                markdown.push_str(" | ");
                markdown.push_str(&format_percent(comparison.duration_ms.overhead_percent));
                markdown.push_str(" | ");
                markdown.push_str(&format_percent(comparison.rss_bytes.overhead_percent));
                markdown.push_str(" | ");
                markdown.push_str(&format_percent(
                    comparison
                        .cpu_percent
                        .and_then(|delta| delta.overhead_percent),
                ));
                markdown.push_str(" | ");
                markdown.push_str(&format_signed(comparison.events_total.delta));
                markdown.push_str(" | ");
                markdown.push_str(&format_signed(comparison.drops_total.delta));
                markdown.push_str(" | ");
                markdown.push_str(&format_signed(comparison.alerts_total.delta));
                markdown.push_str(" |\n");
            }
        }

        markdown.push_str("\n## Budget\n");
        match self.budget_status() {
            Some(status) => {
                markdown.push_str("Status: ");
                markdown.push_str(status.as_str());
                markdown.push('\n');

                let checks = self.budget_checks();
                if !checks.is_empty() {
                    markdown.push_str("\n| mode | metric | actual | limit | status |\n");
                    markdown.push_str("| --- | --- | ---: | ---: | --- |\n");
                    for check in checks {
                        markdown.push_str("| ");
                        markdown.push_str(check.mode.as_str());
                        markdown.push_str(" | ");
                        markdown.push_str(check.metric.as_str());
                        markdown.push_str(" | ");
                        markdown.push_str(&format_optional_f64(check.actual));
                        markdown.push_str(" | ");
                        markdown.push_str(&format_f64(check.limit));
                        markdown.push_str(" | ");
                        markdown.push_str(if check.passed { "pass" } else { "fail" });
                        markdown.push_str(" |\n");
                    }
                }
            }
            None => markdown.push_str("No budget configured.\n"),
        }

        markdown
    }

    fn snapshot(&self) -> PerfReportSnapshot<'_> {
        PerfReportSnapshot {
            title: &self.title,
            measurements: &self.measurements,
            comparisons: self.comparisons(),
            budget: self.budget.as_ref(),
            budget_status: self.budget_status(),
            budget_checks: self.budget_checks(),
        }
    }
}

#[derive(Serialize)]
struct PerfReportSnapshot<'a> {
    title: &'a str,
    measurements: &'a BTreeMap<PerfMode, PerfMeasurement>,
    comparisons: Vec<PerfComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget: Option<&'a PerfBudget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_status: Option<BudgetStatus>,
    budget_checks: Vec<BudgetCheck>,
}

fn format_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), format_f64)
}

fn format_percent(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.2}%"))
}

fn format_f64(value: f64) -> String {
    format!("{value:.2}")
}

fn format_signed(value: f64) -> String {
    format!("{value:+.2}")
}

#[cfg(test)]
mod tests;
