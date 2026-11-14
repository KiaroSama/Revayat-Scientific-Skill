//! Backward-compatible migration inventory CLI; execution acceptance remains explicit.
use super::*;
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    registry: Option<PathBuf>,
    #[arg(long)]
    report_only: bool,
    #[arg(long, requires_all = ["execution", "tested_sha", "tier"])]
    ledger: Option<PathBuf>,
    #[arg(long, default_value = "public", value_parser = ["public", "upstream", "security", "verifier"])]
    census: String,
    #[arg(long, requires = "ledger")]
    execution: Option<PathBuf>,
    #[arg(long, requires = "ledger")]
    tested_sha: Option<String>,
    #[arg(long, requires = "ledger")]
    tier: Option<String>,
}

pub fn cli(arguments: &[String]) -> Result<i32> {
    let args = Args::try_parse_from(
        std::iter::once("migration-check".to_owned()).chain(arguments.iter().cloned()),
    )?;
    let root = args.root.canonicalize()?;
    let baseline: Baseline = read_evidence(&root.join("tests/migration-baseline.json"))?;
    let map: MigrationMap = read_evidence(&root.join("tests/rust-migration-map.json"))?;
    let registry = if let Some(path) = args.registry {
        read_evidence(&path)?
    } else {
        registered_tests(&root)?
    };
    let public = audit(&baseline, &map, &registry, std::env::consts::OS)?;
    let upstream_baseline: Baseline = read_evidence(&root.join("tests/upstream-baseline.json"))?;
    let upstream_map: MigrationMap =
        read_evidence(&root.join("tests/upstream-rust-migration-map.json"))?;
    let security_baseline: Baseline = read_evidence(&root.join("tests/security-baseline.json"))?;
    let security_map: MigrationMap =
        read_evidence(&root.join("tests/security-rust-migration-map.json"))?;
    let verifier_baseline: Baseline = read_evidence(&root.join("tests/verifier-baseline.json"))?;
    let verifier_map: MigrationMap =
        read_evidence(&root.join("tests/verifier-rust-migration-map.json"))?;
    audit_censuses(&[
        (&baseline, &map),
        (&upstream_baseline, &upstream_map),
        (&security_baseline, &security_map),
        (&verifier_baseline, &verifier_map),
    ])?;
    let upstream = audit(
        &upstream_baseline,
        &upstream_map,
        &registry,
        std::env::consts::OS,
    )?;
    let security = audit(
        &security_baseline,
        &security_map,
        &registry,
        std::env::consts::OS,
    )?;
    let verifier = audit(
        &verifier_baseline,
        &verifier_map,
        &registry,
        std::env::consts::OS,
    )?;
    let executed_obligations = if let Some(path) = args.ledger {
        let ledger = read_evidence(&path)?;
        let evidence = read_evidence(
            args.execution
                .as_deref()
                .context("execution evidence is required")?,
        )?;
        let (selected_baseline, selected_map) = match args.census.as_str() {
            "upstream" => (&upstream_baseline, &upstream_map),
            "security" => (&security_baseline, &security_map),
            "verifier" => (&verifier_baseline, &verifier_map),
            _ => (&baseline, &map),
        };
        let registration = audit(
            selected_baseline,
            selected_map,
            &registry,
            std::env::consts::OS,
        )?;
        ensure!(
            registration.pending.is_empty() && registration.unavailable.is_empty(),
            "execution counterparts are not registered"
        );
        Some(audit_behavior(
            selected_baseline,
            selected_map,
            &ledger,
            &evidence,
            args.tested_sha
                .as_deref()
                .context("tested SHA is required")?,
            std::env::consts::OS,
            args.tier.as_deref().context("execution tier is required")?,
        )?)
    } else {
        None
    };
    #[derive(Serialize)]
    struct CombinedReport {
        #[serde(flatten)]
        public: Report,
        upstream: Report,
        security: Report,
        verifier: Report,
        evidence_level: &'static str,
        execution_unverified: bool,
        executed_obligations: Option<usize>,
        execution_census: Option<String>,
        final_parity_verified: bool,
    }
    let report = CombinedReport {
        public,
        upstream,
        security,
        verifier,
        evidence_level: if executed_obligations.is_some() {
            "scoped_execution"
        } else {
            "registration_only"
        },
        execution_unverified: executed_obligations.is_none(),
        execution_census: executed_obligations.map(|_| args.census),
        executed_obligations,
        final_parity_verified: false,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    let pending = report.public.pending.len()
        + report.upstream.pending.len()
        + report.security.pending.len()
        + report.verifier.pending.len();
    let unavailable = report.public.unavailable.len()
        + report.upstream.unavailable.len()
        + report.security.unavailable.len()
        + report.verifier.unavailable.len();
    ensure!(
        args.report_only || (pending == 0 && unavailable == 0),
        "Rust migration incomplete: {pending} unmapped, {unavailable} unavailable native tests"
    );
    Ok(0)
}
