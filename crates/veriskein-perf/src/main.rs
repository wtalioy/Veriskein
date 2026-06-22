use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::process::Output;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use veriskein_perf::{BudgetStatus, PerfBudget, PerfMeasurement, PerfMode, PerfReport};

#[derive(Debug, Parser)]
#[command(name = "veriskein-perf")]
#[command(about = "Render Veriskein performance reports")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Report(ReportArgs),
    Measure(MeasureArgs),
}

#[derive(Debug, Parser)]
struct ReportArgs {
    #[arg(long, value_name = "JSON")]
    input: Option<PathBuf>,
    #[arg(long, value_name = "DIR", default_value = "artifacts/perf")]
    output_dir: PathBuf,
    #[arg(long)]
    sample: bool,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    max_duration_overhead_percent: Option<f64>,
    #[arg(long)]
    max_rss_overhead_percent: Option<f64>,
    #[arg(long)]
    max_cpu_overhead_percent: Option<f64>,
    #[arg(long)]
    max_drops_total: Option<u64>,
    #[arg(long)]
    max_alerts_total: Option<u64>,
}

#[derive(Debug, Parser)]
struct MeasureArgs {
    #[arg(long, value_name = "CMD")]
    baseline_cmd: String,
    #[arg(long, value_name = "CMD")]
    kernel_only_cmd: String,
    #[arg(long, value_name = "CMD")]
    kernel_tls_cmd: String,
    #[arg(long, value_name = "CMD")]
    full_cmd: String,
    #[arg(long, value_name = "DIR", default_value = "artifacts/perf")]
    output_dir: PathBuf,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    max_duration_overhead_percent: Option<f64>,
    #[arg(long)]
    max_rss_overhead_percent: Option<f64>,
    #[arg(long)]
    max_cpu_overhead_percent: Option<f64>,
    #[arg(long)]
    max_drops_total: Option<u64>,
    #[arg(long)]
    max_alerts_total: Option<u64>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Report(args) => render_report(args),
        Command::Measure(args) => measure(args),
    }
}

fn render_report(args: ReportArgs) -> Result<()> {
    let mut report = match (args.input.as_ref(), args.sample) {
        (Some(path), false) => read_report(path)?,
        (None, true) => sample_report(),
        (Some(_), true) => bail!("use either --input or --sample, not both"),
        (None, false) => bail!("provide --input JSON or --sample"),
    };

    if let Some(title) = args.title.as_ref() {
        report = report.with_title(title);
    }
    if let Some(budget) = report_budget_from_args(&args) {
        report = report.with_budget(budget);
    }

    write_report(&report, &args.output_dir)
}

fn measure(args: MeasureArgs) -> Result<()> {
    let require_reported = measure_requires_reported_counters(&args);
    let mut report = PerfReport::new([
        (
            PerfMode::Baseline,
            run_measurement(PerfMode::Baseline, &args.baseline_cmd, require_reported)?,
        ),
        (
            PerfMode::KernelOnly,
            run_measurement(
                PerfMode::KernelOnly,
                &args.kernel_only_cmd,
                require_reported,
            )?,
        ),
        (
            PerfMode::KernelTls,
            run_measurement(PerfMode::KernelTls, &args.kernel_tls_cmd, require_reported)?,
        ),
        (
            PerfMode::Full,
            run_measurement(PerfMode::Full, &args.full_cmd, require_reported)?,
        ),
    ]);

    if let Some(title) = args.title.as_ref() {
        report = report.with_title(title);
    }
    if let Some(budget) = measure_budget_from_args(&args) {
        report = report.with_budget(budget);
    }

    write_report(&report, &args.output_dir)
}

fn write_report(report: &PerfReport, output_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(output_dir).with_context(|| format!("create {}", output_dir.display()))?;
    let json_path = output_dir.join("report.json");
    let markdown_path = output_dir.join("report.md");
    fs::write(&json_path, report.to_json_pretty()?.as_bytes())
        .with_context(|| format!("write {}", json_path.display()))?;
    fs::write(&markdown_path, report.to_markdown().as_bytes())
        .with_context(|| format!("write {}", markdown_path.display()))?;

    println!("{}", json_path.display());
    println!("{}", markdown_path.display());
    if report.budget_status() == Some(BudgetStatus::Fail) {
        bail!("performance budget failed");
    }
    Ok(())
}

fn run_measurement(
    mode: PerfMode,
    command: &str,
    require_reported: bool,
) -> Result<PerfMeasurement> {
    let start = Instant::now();
    let output = ProcessCommand::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| format!("run {mode} workload"))?;
    if !output.status.success() {
        bail!("{mode} workload exited with {}", output.status);
    }
    let wall_duration_ms = start.elapsed().as_secs_f64() * 1_000.0;
    if let Some(mut measurement) = parse_measurement_stdout(&output)? {
        if measurement.duration_ms <= 0.0 {
            measurement.duration_ms = wall_duration_ms;
        }
        return Ok(measurement);
    }
    if require_reported {
        bail!(
            "{mode} workload must emit PerfMeasurement JSON when non-duration budgets are configured"
        );
    }
    Ok(PerfMeasurement::new(wall_duration_ms, 0, 0, 0, 0))
}

fn parse_measurement_stdout(output: &Output) -> Result<Option<PerfMeasurement>> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(line) = stdout.lines().rev().find(|line| !line.trim().is_empty()) else {
        return Ok(None);
    };
    serde_json::from_str::<PerfMeasurement>(line.trim())
        .map(Some)
        .with_context(|| "parse workload PerfMeasurement JSON from stdout")
}

fn read_report(path: &PathBuf) -> Result<PerfReport> {
    let input = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str::<PerfReport>(&input)
        .or_else(|_| {
            serde_json::from_str::<BTreeMap<PerfMode, PerfMeasurement>>(&input).map(PerfReport::new)
        })
        .with_context(|| {
            format!(
                "parse {} as PerfReport or mode-to-measurement map",
                path.display()
            )
        })
}

fn report_budget_from_args(args: &ReportArgs) -> Option<PerfBudget> {
    let mut budget = PerfBudget::empty();
    let mut configured = false;

    if let Some(limit) = args.max_duration_overhead_percent {
        budget = budget.with_max_duration_overhead_percent(limit);
        configured = true;
    }
    if let Some(limit) = args.max_rss_overhead_percent {
        budget = budget.with_max_rss_overhead_percent(limit);
        configured = true;
    }
    if let Some(limit) = args.max_cpu_overhead_percent {
        budget = budget.with_max_cpu_overhead_percent(limit);
        configured = true;
    }
    if let Some(limit) = args.max_drops_total {
        budget = budget.with_max_drops_total(limit);
        configured = true;
    }
    if let Some(limit) = args.max_alerts_total {
        budget = budget.with_max_alerts_total(limit);
        configured = true;
    }

    configured.then_some(budget)
}

fn measure_budget_from_args(args: &MeasureArgs) -> Option<PerfBudget> {
    let mut budget = PerfBudget::empty();
    let mut configured = false;

    if let Some(limit) = args.max_duration_overhead_percent {
        budget = budget.with_max_duration_overhead_percent(limit);
        configured = true;
    }
    if let Some(limit) = args.max_rss_overhead_percent {
        budget = budget.with_max_rss_overhead_percent(limit);
        configured = true;
    }
    if let Some(limit) = args.max_cpu_overhead_percent {
        budget = budget.with_max_cpu_overhead_percent(limit);
        configured = true;
    }
    if let Some(limit) = args.max_drops_total {
        budget = budget.with_max_drops_total(limit);
        configured = true;
    }
    if let Some(limit) = args.max_alerts_total {
        budget = budget.with_max_alerts_total(limit);
        configured = true;
    }

    configured.then_some(budget)
}

fn measure_requires_reported_counters(args: &MeasureArgs) -> bool {
    args.max_rss_overhead_percent.is_some()
        || args.max_cpu_overhead_percent.is_some()
        || args.max_drops_total.is_some()
        || args.max_alerts_total.is_some()
}

fn sample_report() -> PerfReport {
    PerfReport::new(BTreeMap::from([
        (
            PerfMode::Baseline,
            PerfMeasurement::new(100.0, 10_000, 0, 0, 64 * 1024 * 1024).with_cpu_percent(10.0),
        ),
        (
            PerfMode::KernelOnly,
            PerfMeasurement::new(108.0, 10_000, 0, 0, 70 * 1024 * 1024).with_cpu_percent(10.8),
        ),
        (
            PerfMode::KernelTls,
            PerfMeasurement::new(119.0, 10_000, 0, 1, 78 * 1024 * 1024).with_cpu_percent(12.1),
        ),
        (
            PerfMode::Full,
            PerfMeasurement::new(132.0, 10_000, 0, 3, 86 * 1024 * 1024).with_cpu_percent(13.7),
        ),
    ]))
}
