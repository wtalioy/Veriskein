use std::collections::BTreeMap;

use super::{
    BudgetMetric, BudgetStatus, MetricDelta, PerfBudget, PerfMeasurement, PerfMode, PerfReport,
};

fn sample_report() -> PerfReport {
    PerfReport::new(BTreeMap::from([
        (
            PerfMode::Baseline,
            PerfMeasurement::new(100.0, 1_000, 0, 0, 1_000_000).with_cpu_percent(10.0),
        ),
        (
            PerfMode::KernelOnly,
            PerfMeasurement::new(110.0, 1_010, 0, 0, 1_080_000).with_cpu_percent(11.0),
        ),
        (
            PerfMode::KernelTls,
            PerfMeasurement::new(125.0, 1_030, 1, 2, 1_160_000).with_cpu_percent(12.5),
        ),
        (
            PerfMode::Full,
            PerfMeasurement::new(135.0, 1_050, 2, 3, 1_220_000).with_cpu_percent(14.0),
        ),
    ]))
}

#[test]
fn perf_mode_parses_and_serializes_expected_names() {
    assert_eq!("kernel+tls".parse::<PerfMode>(), Ok(PerfMode::KernelTls));

    let encoded = serde_json::to_string(&PerfMode::KernelOnly);
    assert!(matches!(encoded.as_deref(), Ok("\"kernel-only\"")));
}

#[test]
fn metric_delta_calculates_overhead_and_handles_zero_baselines() {
    assert_eq!(
        MetricDelta::new(100.0, 125.0),
        MetricDelta {
            baseline: 100.0,
            measured: 125.0,
            delta: 25.0,
            overhead_percent: Some(25.0),
        }
    );
    assert_eq!(MetricDelta::new(0.0, 0.0).overhead_percent, Some(0.0));
    assert_eq!(MetricDelta::new(0.0, 1.0).overhead_percent, None);
}

#[test]
fn report_generates_comparisons_in_mode_order() {
    let report = sample_report();
    let comparisons = report.comparisons();

    assert_eq!(comparisons.len(), 3);
    assert_eq!(comparisons[0].mode, PerfMode::KernelOnly);
    assert_eq!(comparisons[1].mode, PerfMode::KernelTls);
    assert_eq!(comparisons[2].mode, PerfMode::Full);
    assert_eq!(comparisons[1].duration_ms.overhead_percent, Some(25.0));
    assert_eq!(comparisons[2].rss_bytes.overhead_percent, Some(22.0));
}

#[test]
fn budget_checks_pass_and_fail_expected_thresholds() {
    let report = sample_report().with_budget(
        PerfBudget::empty()
            .with_max_duration_overhead_percent(30.0)
            .with_max_rss_overhead_percent(25.0)
            .with_max_cpu_overhead_percent(35.0)
            .with_max_drops_total(1)
            .with_max_alerts_total(2),
    );

    let checks = report.budget_checks();

    assert_eq!(report.budget_status(), Some(BudgetStatus::Fail));
    assert!(checks.iter().any(|check| {
        check.mode == PerfMode::Full
            && check.metric == BudgetMetric::DurationOverheadPercent
            && !check.passed
    }));
    assert!(checks.iter().any(|check| {
        check.mode == PerfMode::KernelOnly
            && check.metric == BudgetMetric::DurationOverheadPercent
            && check.passed
    }));
    assert!(checks.iter().any(|check| {
        check.mode == PerfMode::Full && check.metric == BudgetMetric::DropsTotal && !check.passed
    }));
}

#[test]
fn json_report_includes_computed_sections() {
    let report = sample_report().with_budget(
        PerfBudget::empty()
            .with_max_duration_overhead_percent(40.0)
            .with_max_drops_total(2),
    );

    let json = report.to_json_pretty();

    assert!(matches!(json, Ok(ref value) if value.contains("\"comparisons\"")));
    assert!(matches!(json, Ok(ref value) if value.contains("\"budget_status\": \"pass\"")));
    assert!(matches!(json, Ok(ref value) if value.contains("\"kernel+tls\"")));
}

#[test]
fn markdown_report_renders_measurements_comparisons_and_budget() {
    let report = sample_report().with_budget(
        PerfBudget::empty()
            .with_max_duration_overhead_percent(40.0)
            .with_max_rss_overhead_percent(25.0),
    );

    let markdown = report.to_markdown();

    assert!(markdown.contains("# Veriskein Performance Report"));
    assert!(markdown.contains("| kernel+tls | 125.00 | 1030 | 1 | 2 | 1160000 | 12.50 |"));
    assert!(markdown.contains("| full | 35.00% | 22.00% | 40.00% | +50.00 | +2.00 | +3.00 |"));
    assert!(markdown.contains("Status: pass"));
}
