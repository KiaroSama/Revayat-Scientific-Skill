//! Deterministic complete notices from the locked, all-platform Cargo graph.
//! No registry license identifier is treated as a substitute for license text.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use revayat_scientific::runtime::{self, CommandSpec, OperationLog};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "license_notices/dedup.rs"]
mod dedup;

const NOTICE_LIMIT: u64 = 16 * 1024 * 1024;
const BUNDLE_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Verify the committed bundle without rewriting it.
    #[arg(long)]
    check: bool,
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
    resolve: Resolve,
}
#[derive(Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Node {
    id: String,
}
#[derive(Deserialize)]
struct Package {
    id: String,
    name: String,
    version: String,
    license: Option<String>,
    license_file: Option<PathBuf>,
    manifest_path: PathBuf,
}
#[derive(Default, Deserialize)]
struct Supplements {
    schema: u8,
    packages: Vec<Supplement>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Supplement {
    name: String,
    version: String,
    /// Public upstream repository/commit/file identity actually inspected.
    provenance: String,
    notices: Vec<SupplementNotice>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupplementNotice {
    name: String,
    sha256: String,
    text: String,
}
struct Notice {
    name: String,
    sha256: String,
    text: String,
    provenance: String,
}
struct Entry {
    name: String,
    version: String,
    license: String,
    notices: Vec<Notice>,
}

#[derive(Deserialize)]
struct StandardLibraryNotice {
    toolchain: String,
    file: String,
    sha256: String,
}

fn verify_standard_library(root: &Path) -> Result<()> {
    let references = root.join("skills/revayat-scientific/references");
    let provenance: StandardLibraryNotice = serde_json::from_slice(&bounded(
        &references.join("rust-standard-library-notices.json"),
        NOTICE_LIMIT,
    )?)?;
    ensure!(
        provenance.toolchain == env!("CARGO_PKG_RUST_VERSION"),
        "standard-library notice toolchain differs from the pinned Rust version"
    );
    ensure!(
        provenance.file == "rust-standard-library-notices.html",
        "unexpected standard-library notice filename"
    );
    let version = tool_output(root, "rustc", &["--version"], 15, 4096)?;
    ensure!(
        std::str::from_utf8(&version)?.split_whitespace().nth(1)
            == Some(provenance.toolchain.as_str()),
        "active compiler differs from the standard-library notice pin"
    );
    let sysroot = tool_output(root, "rustc", &["--print", "sysroot"], 15, 16384)?;
    let sysroot = PathBuf::from(std::str::from_utf8(&sysroot)?.trim_end_matches(['\r', '\n']));
    ensure!(sysroot.is_absolute(), "compiler sysroot is not absolute");
    let official = bounded(
        &sysroot.join("share/doc/rust/COPYRIGHT-library.html"),
        NOTICE_LIMIT,
    )?;
    let distributed = bounded(&references.join(&provenance.file), NOTICE_LIMIT)?;
    ensure!(
        digest(&distributed) == provenance.sha256,
        "distributed standard-library notices differ from their recorded SHA-256"
    );
    ensure!(
        distributed == official,
        "standard-library notices differ from the exact installed official compiler component"
    );
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "notice input is not a plain file"
    );
    ensure!(metadata.len() <= limit, "notice input exceeds byte limit");
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "notice input grew beyond byte limit"
    );
    Ok(bytes)
}

fn legal_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    [
        "LICENSE",
        "LICENCE",
        "COPYING",
        "NOTICE",
        "COPYRIGHT",
        "UNLICENSE",
        "AUTHORS",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn collect(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut pending = vec![root.to_owned()];
    let mut output = BTreeSet::new();
    let mut seen = 0usize;
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(directory)? {
            let item = item?;
            seen += 1;
            ensure!(seen <= 250_000, "crate source inventory exceeds bound");
            let name = item.file_name();
            let name = name.to_str().context("non-Unicode crate source name")?;
            let kind = item.file_type()?;
            // Registry source trees are not followed outside their package.
            ensure!(
                !kind.is_symlink(),
                "symbolic link in crate source inventory"
            );
            if kind.is_dir() && ![".git", "target"].contains(&name) {
                pending.push(item.path());
            } else if kind.is_file() && legal_name(name) {
                output.insert(item.path());
            }
        }
    }
    Ok(output)
}

fn clean_label(value: &str) -> Result<&str> {
    ensure!(
        !value.is_empty() && !value.contains(['\r', '\n', '\0', '`', '|']),
        "invalid notice metadata label"
    );
    Ok(value)
}

fn reviewed_expression(value: &str) -> Result<()> {
    // New terms introduced by a changed lockfile require an explicit review.
    // Historical Cargo slash notation is retained rather than rewritten.
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" .-()/".contains(&byte)),
        "unreviewed license expression syntax"
    );
    for identifier in value
        .split(|character: char| {
            !character.is_ascii_alphanumeric() && !['-', '.'].contains(&character)
        })
        .filter(|part| !part.is_empty())
    {
        ensure!(
            [
                "0BSD",
                "Apache-2.0",
                "MIT",
                "Unlicense",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "MPL-2.0",
                "ISC",
                "Unicode-3.0",
                "Zlib",
                "BSL-1.0",
                "LGPL-2.1-or-later",
                "LLVM-exception",
                "OR",
                "AND",
                "WITH"
            ]
            .contains(&identifier),
            "unreviewed license identifier: {identifier}"
        );
    }
    Ok(())
}

fn source_notice(root: &Path, path: &Path, budget: &mut dedup::MaterialBudget) -> Result<Notice> {
    let canonical = path.canonicalize()?;
    ensure!(
        canonical.starts_with(root),
        "notice path escapes its source package"
    );
    let relative = path
        .strip_prefix(root)?
        .to_str()
        .context("non-Unicode notice path")?
        .replace('\\', "/");
    clean_label(&relative)?;
    budget.reserve(&[relative.len(), 64, 256])?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= NOTICE_LIMIT,
        "invalid or oversized source notice"
    );
    let bytes = budget.read(fs::File::open(path)?, NOTICE_LIMIT)?;
    let sha256 = digest(&bytes);
    let text =
        String::from_utf8(bytes).with_context(|| format!("notice is not UTF-8: {relative}"))?;
    ensure!(!text.trim().is_empty(), "empty source notice {relative}");
    Ok(Notice {
        name: relative,
        sha256,
        text,
        provenance: "Published Cargo source archive".to_owned(),
    })
}

fn fence(text: &str) -> String {
    let longest = text
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    "`".repeat(3.max(longest + 1))
}

fn embedded(root: &Path, relative: &str, name: &str) -> Result<Notice> {
    let bytes = bounded(&root.join(relative), NOTICE_LIMIT)?;
    Ok(Notice {
        name: name.to_owned(),
        sha256: digest(&bytes),
        text: String::from_utf8(bytes)?,
        provenance: format!("Repository file `{relative}`"),
    })
}

fn generate(
    root: &Path,
    metadata: Metadata,
    supplements: Supplements,
    lock_hash: &str,
) -> Result<(String, usize, usize)> {
    ensure!(
        supplements.schema == 1,
        "unsupported license supplement schema"
    );
    let workspace: BTreeSet<_> = metadata.workspace_members.into_iter().collect();
    let resolved: BTreeSet<_> = metadata
        .resolve
        .nodes
        .into_iter()
        .map(|node| node.id)
        .collect();
    let mut supplemental = BTreeMap::new();
    for supplement in supplements.packages {
        let key = (supplement.name.clone(), supplement.version.clone());
        ensure!(
            supplemental.insert(key, supplement).is_none(),
            "duplicate license supplement"
        );
    }
    let mut entries = BTreeMap::new();
    let mut budget = dedup::MaterialBudget::default();
    let mut missing = Vec::new();
    for package in metadata.packages {
        if workspace.contains(&package.id) || !resolved.contains(&package.id) {
            continue;
        }
        clean_label(&package.name)?;
        clean_label(&package.version)?;
        let license = package
            .license
            .context("resolved third-party crate has no declared license expression")?;
        clean_label(&license)?;
        reviewed_expression(&license)?;
        budget.reserve(&[
            package.name.len(),
            package.version.len(),
            license.len(),
            512,
        ])?;
        let source = package
            .manifest_path
            .parent()
            .context("crate manifest has no source directory")?
            .canonicalize()?;
        let mut paths = collect(&source)?;
        if let Some(declared) = package.license_file {
            let declared = if declared.is_absolute() {
                declared
            } else {
                source.join(declared)
            };
            ensure!(
                declared.canonicalize()?.starts_with(&source),
                "declared license escapes crate source"
            );
            paths.insert(declared);
        }
        let mut notices = Vec::new();
        for path in &paths {
            notices.push(source_notice(&source, path, &mut budget)?);
        }
        if let Some(supplement) =
            supplemental.remove(&(package.name.clone(), package.version.clone()))
        {
            clean_label(&supplement.provenance)?;
            ensure!(!supplement.notices.is_empty(), "empty license supplement");
            for notice in supplement.notices {
                clean_label(&notice.name)?;
                ensure!(
                    notice.sha256 == digest(notice.text.as_bytes()),
                    "license supplement hash differs"
                );
                ensure!(
                    !notice.text.trim().is_empty(),
                    "empty supplemental license text"
                );
                budget.reserve(&[
                    notice.name.len(),
                    notice.sha256.len(),
                    notice.text.len(),
                    supplement.provenance.len(),
                    256,
                ])?;
                notices.push(Notice {
                    name: notice.name,
                    sha256: notice.sha256,
                    text: notice.text,
                    provenance: supplement.provenance.clone(),
                });
            }
        }
        if notices.is_empty() {
            missing.push(format!("{} {}", package.name, package.version));
        }
        let key = (package.name.clone(), package.version.clone());
        let entry = Entry {
            name: package.name,
            version: package.version,
            license,
            notices,
        };
        ensure!(
            entries.insert(key, entry).is_none(),
            "same crate name/version appears from multiple source identities"
        );
    }
    ensure!(
        supplemental.is_empty(),
        "license supplement contains a package absent from the resolved graph"
    );
    ensure!(
        missing.is_empty(),
        "published crates lack complete notice files; provide reviewed upstream supplements: {}",
        missing.join(", ")
    );
    ensure!(
        bounded(
            &root.join("crates/revayat-scientific/assets/LICENSE.docx-defaults"),
            NOTICE_LIMIT
        )? == bounded(
            &root.join("skills/revayat-scientific/assets/LICENSE.docx-defaults"),
            NOTICE_LIMIT
        )?,
        "embedded and distributed OOXML notices differ"
    );
    let mut output = String::from(
        "# Complete third-party license notices\n\nGenerated by the native Rust `license-notices` tool from `cargo metadata --locked --format-version 1 --all-features` and the exact published crate sources. This inventory includes runtime, build, test/development and platform-specific dependencies across the complete resolved workspace graph; it is intentionally broader than any one platform binary. License expressions are preserved as declared, including historical slash notation. No license option is silently selected.\n\n",
    );
    output.push_str(&format!("Cargo.lock SHA-256: `{lock_hash}`\n\n"));
    output.push_str("Project licensing and history remain governed by the repository GPL-3.0-or-later LICENSE and the skill NOTICE. This inventory does not replace either. Optional external applications and document inputs are not redistributed here and retain their own terms.\n\nRegenerate after every lockfile update:\n\n```text\ncargo build --locked --workspace --bins\ncargo run --locked --bin license-notices -- --root .\ncargo run --locked --bin license-notices -- --root . --check\n```\n\nThe generator fails on missing license text, unknown expressions, mismatched supplement hashes, source escapes, stale supplements or a lockfile changed during generation. Logical retained occurrence material is admitted incrementally before retention against a 256 MiB budget; shared body material and rendered output each have a 64 MiB budget. These are material bounds, not allocator RSS limits. Refusal leaves the previous complete bundle unchanged; no legal file is silently omitted. Supplemental upstream notices are explicitly attributed; they are never represented as files included in a published crate archive. SHA-256 values cover exact source notice bytes; Markdown fence separator newlines are not part of those hashes. Each package/filename/provenance retains its own occurrence and references one exact shared body by SHA-256. Distinct attribution, line endings and final-newline bytes are never normalized. Unix tool invocations require the adjacent revayat-process-owner built by the --bins command; bounded execution has no unowned fallback. Private UTF-8 operation logs use logs/license-notices_YYYY-MM-DD_HH-mm-ss_UTC.log with collision suffixes, INFO/ERROR phase and exit state, no child output or private paths. Retain operational logs locally and attach only reviewed redacted copies to support requests.\n\n## Dependency inventory\n\n| Package | Exact declared license expression | Full notice files |\n| --- | --- | ---: |\n");
    let mut notice_count = 0;
    for entry in entries.values() {
        dedup::push(
            &mut output,
            &format!(
                "| {} {} | `{}` | {} |\n",
                entry.name,
                entry.version,
                entry.license,
                entry.notices.len()
            ),
        )?;
        notice_count += entry.notices.len();
    }
    let mut bodies = dedup::Bodies::default();
    output.push_str("\n## Project and embedded asset notices\n\n");
    for (relative, name) in [
        ("LICENSE", "Project GNU GPL version 3 or later license text"),
        (
            "skills/revayat-scientific/references/upstream-license.txt",
            "Retained adapted upstream skill material — MIT",
        ),
        (
            "crates/revayat-scientific/assets/LICENSE.docx-defaults",
            "Embedded OOXML defaults — MIT, Steve Canny",
        ),
        (
            "crates/revayat-scientific/assets/fonts/OFL.txt",
            "Bundled Vazirmatn Regular and Bold — SIL OFL 1.1",
        ),
    ] {
        bodies.occurrence(&mut output, &embedded(root, relative, name)?)?;
    }
    for entry in entries.values() {
        dedup::push(
            &mut output,
            &format!(
                "## {} {}\n\nDeclared license expression: `{}`\n\n",
                entry.name, entry.version, entry.license
            ),
        )?;
        for notice in &entry.notices {
            bodies.occurrence(&mut output, notice)?;
        }
        ensure!(
            output.len() <= BUNDLE_LIMIT,
            "complete notice bundle exceeds 64 MiB"
        );
    }
    bodies.append(&mut output)?;
    Ok((output, entries.len(), notice_count))
}

fn tool_output(
    root: &Path,
    program: &str,
    args: &[&str],
    seconds: u64,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut spec = CommandSpec::new(program).args(args.iter().copied());
    spec.cwd = Some(root.to_owned());
    spec.timeout = Duration::from_secs(seconds);
    spec.max_output = limit;
    let output =
        runtime::run(&spec).with_context(|| format!("bounded {program} invocation failed"))?;
    ensure!(
        output.success(),
        "{program} failed; no notice bundle written (exit {})",
        output.code
    );
    Ok(output.stdout)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = args.root.canonicalize()?;
    let mut log = OperationLog::create("license-notices", &root.join("logs"), None)?;
    let result = generate_bundle(&root, args.check, &mut log);
    log.write(
        if result.is_ok() { "INFO" } else { "ERROR" },
        if result.is_ok() {
            "completed exit=0"
        } else {
            "failed exit=1"
        },
    );
    result
}

fn generate_bundle(root: &Path, check: bool, log: &mut OperationLog) -> Result<()> {
    log.info("phase=compiler-and-standard-library");
    verify_standard_library(root)?;
    log.info("phase=locked-metadata");
    let lock = bounded(&root.join("Cargo.lock"), NOTICE_LIMIT)?;
    let lock_hash = digest(&lock);
    let bytes = tool_output(
        root,
        "cargo",
        &[
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--all-features",
        ],
        180,
        NOTICE_LIMIT as usize,
    )?;
    let metadata = serde_json::from_slice(&bytes)?;
    let supplements_path =
        root.join("skills/revayat-scientific/references/license-supplements.json");
    let supplements = if supplements_path.exists() {
        serde_json::from_slice(&bounded(&supplements_path, NOTICE_LIMIT)?)?
    } else {
        Supplements {
            schema: 1,
            ..Default::default()
        }
    };
    log.info("phase=collect-and-deduplicate");
    let (output, packages, notices) = generate(root, metadata, supplements, &lock_hash)?;
    log.info(&format!(
        "packages={packages} notice_occurrences={notices} bytes={}",
        output.len()
    ));
    ensure!(
        bounded(&root.join("Cargo.lock"), NOTICE_LIMIT)? == lock,
        "Cargo.lock changed during generation; rerun"
    );
    let target = root.join("skills/revayat-scientific/references/third-party-licenses.txt");
    log.info(if check {
        "phase=verify-bundle"
    } else {
        "phase=publish-bundle"
    });
    if check {
        ensure!(
            bounded(&target, BUNDLE_LIMIT as u64)? == output.as_bytes(),
            "committed license bundle is stale"
        );
    } else {
        let mut stage = tempfile::NamedTempFile::new_in(
            target.parent().context("license target has no parent")?,
        )?;
        stage.write_all(output.as_bytes())?;
        stage.flush()?;
        stage.as_file().sync_all()?;
        stage
            .persist(&target)
            .context("publish complete license bundle")?;
    }
    println!(
        "{} complete notices for {packages} locked third-party packages ({} bytes)",
        notices,
        output.len()
    );
    Ok(())
}
