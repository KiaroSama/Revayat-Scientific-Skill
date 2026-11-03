//! Auditable one-to-one migration inventory. Counting new tests alone cannot
//! prove that an old scenario survived: require an explicit unique mapping to
//! tests actually registered by the Rust test executables.
use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Deserialize)]
pub struct LegacyTest {
    pub id: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct Baseline {
    pub schema: u8,
    pub baseline_commit: String,
    pub public_test_count: usize,
    pub tests: Vec<LegacyTest>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub legacy_id: String,
    /// Integration test target plus fully qualified libtest function name.
    pub rust_test: String,
    /// Explain the behavior retained or interpreter-specific mechanism replaced.
    pub rationale: String,
    #[serde(default)]
    pub platforms: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationMap {
    pub schema: u8,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub baseline_commit: String,
    pub legacy_tests: usize,
    pub mapped_tests: usize,
    pub registered_rust_tests: usize,
    pub pending: Vec<String>,
    pub unavailable: Vec<String>,
}

/// Independent script inventories must not inflate preservation counts by
/// reusing a public test, another script's case, or a different historical base.
pub fn audit_censuses(censuses: &[(&Baseline, &MigrationMap)]) -> Result<()> {
    let (first, _) = censuses.first().context("migration census is empty")?;
    let mut legacy = BTreeSet::new();
    let mut registered = BTreeSet::new();
    for (baseline, map) in censuses {
        ensure!(
            baseline.baseline_commit == first.baseline_commit,
            "migration inventories refer to different baseline commits"
        );
        for test in &baseline.tests {
            ensure!(
                legacy.insert(test.id.as_str()),
                "legacy scenario counted in multiple inventories: {}",
                test.id
            );
        }
        for mapping in &map.mappings {
            ensure!(
                registered.insert(mapping.rust_test.as_str()),
                "independent inventories reuse a Rust test registration: {}",
                mapping.rust_test
            );
        }
    }
    Ok(())
}

pub fn audit(
    baseline: &Baseline,
    map: &MigrationMap,
    registered: &BTreeSet<String>,
    platform: &str,
) -> Result<Report> {
    ensure!(
        baseline.schema == 1 && map.schema == 1,
        "unsupported migration schema"
    );
    ensure!(
        baseline.baseline_commit.len() == 40
            && baseline
                .baseline_commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit()),
        "baseline requires exact commit identity"
    );
    let ids: BTreeSet<&str> = baseline.tests.iter().map(|t| t.id.as_str()).collect();
    ensure!(
        ids.len() == baseline.tests.len() && ids.len() == baseline.public_test_count,
        "baseline test inventory changed or contains duplicates"
    );
    let mut by_legacy = BTreeMap::new();
    let mut by_rust = BTreeSet::new();
    let mut unavailable = Vec::new();
    for mapping in &map.mappings {
        ensure!(
            ids.contains(mapping.legacy_id.as_str()),
            "unknown legacy test in migration mapping: {}",
            mapping.legacy_id
        );
        ensure!(
            by_legacy
                .insert(mapping.legacy_id.as_str(), mapping)
                .is_none(),
            "duplicate legacy mapping: {}",
            mapping.legacy_id
        );
        ensure!(
            by_rust.insert(mapping.rust_test.as_str()),
            "multiple legacy scenarios mapped to one Rust test: {}",
            mapping.rust_test
        );
        ensure!(
            !mapping.rationale.trim().is_empty(),
            "migration rationale missing for {}",
            mapping.legacy_id
        );
        ensure!(
            mapping
                .platforms
                .iter()
                .all(|p| ["linux", "macos", "windows"].contains(&p.as_str())),
            "invalid migration platform"
        );
        if (mapping.platforms.is_empty() || mapping.platforms.iter().any(|p| p == platform))
            && !registered.contains(&mapping.rust_test)
        {
            unavailable.push(mapping.rust_test.clone());
        }
    }
    let pending = ids
        .into_iter()
        .filter(|id| !by_legacy.contains_key(id))
        .map(str::to_owned)
        .collect();
    Ok(Report {
        baseline_commit: baseline.baseline_commit.clone(),
        legacy_tests: baseline.public_test_count,
        mapped_tests: by_legacy.len(),
        registered_rust_tests: registered.len(),
        pending,
        unavailable,
    })
}

/// Query actual libtest executables produced by Cargo rather than searching
/// source strings which might be comments, uncompiled code or placeholders.
pub fn registered_tests(root: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("cargo")
        .args([
            "test",
            "--workspace",
            "--locked",
            "--no-run",
            "--message-format=json",
        ])
        .current_dir(root)
        .output()
        .context("cannot compile Rust test registry")?;
    ensure!(
        output.status.success(),
        "Rust test compilation failed while discovering migration coverage"
    );
    ensure!(
        output.stdout.len() <= 32 * 1024 * 1024,
        "Cargo test registry exceeded diagnostic budget"
    );
    let mut binaries = BTreeMap::new();
    for line in output
        .stdout
        .split(|c| *c == b'\n')
        .filter(|l| !l.is_empty())
    {
        let value: serde_json::Value = serde_json::from_slice(line)?;
        if value["reason"] == "compiler-artifact"
            && value["profile"]["test"] == true
            && let (Some(path), Some(name)) = (
                value["executable"].as_str(),
                value["target"]["name"].as_str(),
            )
        {
            binaries.insert(PathBuf::from(path), name.to_owned());
        }
    }
    ensure!(!binaries.is_empty(), "Cargo registered no test executables");
    let mut registry = BTreeSet::new();
    for (binary, name) in binaries {
        let listed = Command::new(&binary)
            .args(["--list", "--format", "terse"])
            .current_dir(root)
            .output()?;
        ensure!(
            listed.status.success(),
            "Rust test executable failed to list its cases"
        );
        ensure!(
            listed.stdout.len() <= 8 * 1024 * 1024,
            "Rust test registry exceeded listing budget"
        );
        for line in std::str::from_utf8(&listed.stdout)?.lines() {
            if let Some(case) = line.strip_suffix(": test") {
                registry.insert(format!("{name}::{case}"));
            }
        }
    }
    ensure!(
        !registry.is_empty(),
        "zero-test execution does not establish migration coverage"
    );
    Ok(registry)
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    registry: Option<PathBuf>,
    #[arg(long)]
    report_only: bool,
}
pub fn cli(args: &[String]) -> Result<i32> {
    let args = Args::try_parse_from(
        std::iter::once("migration-check".to_owned()).chain(args.iter().cloned()),
    )?;
    let root = args.root.canonicalize()?;
    let baseline: Baseline =
        serde_json::from_slice(&fs::read(root.join("tests/migration-baseline.json"))?)?;
    let map: MigrationMap =
        serde_json::from_slice(&fs::read(root.join("tests/rust-migration-map.json"))?)?;
    let registry = if let Some(path) = args.registry {
        serde_json::from_slice(&fs::read(path)?)?
    } else {
        registered_tests(&root)?
    };
    let report = audit(&baseline, &map, &registry, std::env::consts::OS)?;
    let upstream_baseline: Baseline =
        serde_json::from_slice(&fs::read(root.join("tests/upstream-baseline.json"))?)?;
    let upstream_map: MigrationMap = serde_json::from_slice(&fs::read(
        root.join("tests/upstream-rust-migration-map.json"),
    )?)?;
    let security_baseline: Baseline =
        serde_json::from_slice(&fs::read(root.join("tests/security-baseline.json"))?)?;
    let security_map: MigrationMap = serde_json::from_slice(&fs::read(
        root.join("tests/security-rust-migration-map.json"),
    )?)?;
    audit_censuses(&[
        (&baseline, &map),
        (&upstream_baseline, &upstream_map),
        (&security_baseline, &security_map),
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
    #[derive(Serialize)]
    struct CombinedReport {
        #[serde(flatten)]
        public: Report,
        upstream: Report,
        security: Report,
    }
    let report = CombinedReport {
        public: report,
        upstream,
        security,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    let pending =
        report.public.pending.len() + report.upstream.pending.len() + report.security.pending.len();
    let unavailable = report.public.unavailable.len()
        + report.upstream.unavailable.len()
        + report.security.unavailable.len();
    if !args.report_only && (pending != 0 || unavailable != 0) {
        bail!(
            "Rust migration incomplete: {} unmapped, {} unavailable native tests",
            pending,
            unavailable
        );
    }
    Ok(0)
}
