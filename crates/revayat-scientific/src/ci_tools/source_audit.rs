//! Explicit tracked-file classification and comparable Rust-source size receipts.
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, path::Path};

pub fn classify_source(filename: &str, bytes: &[u8]) -> Result<&'static str> {
    ensure!(
        !bytes.starts_with(b"#!") || bytes.starts_with(b"#!["),
        "script shebang is not Rust project code"
    );
    let path = Path::new(filename);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid source filename")?;
    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let category = match extension {
        "rs" => "rust",
        "md" | "txt" => "documentation",
        "toml" | "lock" | "json" | "yaml" | "yml" | "docx-defaults" | "dockerignore" => "configuration",
        "tex" if name == "Dockerfile.tex" => {
            super::validate_docker_invocations(std::str::from_utf8(bytes)?)?;
            "configuration"
        }
        "html" | "tex" => "document",
        "tsv" | "zip" | "ttf" | "docx" | "png" | "icc" | "jp2" => "data",
        _ if [
            "LICENSE",
            "NOTICE",
            ".gitignore",
            ".gitattributes",
            ".dockerignore",
            ".cbmignore",
            ".graphifyignore",
        ]
        .contains(&name) => "configuration",
        _ => anyhow::bail!("unclassified tracked file: {filename}"),
    };
    if category == "rust" {
        let text = std::str::from_utf8(bytes).context("Rust source is not UTF-8")?;
        ensure!(
            text.lines().count() <= 799,
            "Rust source exceeds 799 lines: {filename}"
        );
    }
    Ok(category)
}

const BASELINE: &str = "c9ff76549ae23817e9827274aa45aee80bc11afc";

fn audit(root: &Path, mut git: impl FnMut(&[&str]) -> Result<String>) -> Result<serde_json::Value> {
    let listing = git(&["ls-files", "-z"])?;
    ensure!(!listing.is_empty(), "tracked source listing failed");
    let mut counts = BTreeMap::new();
    let mut current = 0;
    for filename in listing.split('\0').filter(|s| !s.is_empty()) {
        let path = root.join(filename);
        ensure!(
            !crate::identity::is_link(&path)?,
            "linked tracked file refused"
        );
        let bytes = std::fs::read(path)?;
        let category = classify_source(filename, &bytes)?;
        *counts.entry(category).or_insert(0usize) += 1;
        if category == "rust" {
            current += std::str::from_utf8(&bytes)?.lines().count();
        }
    }
    let listing = git(&["ls-tree", "-r", "--name-only", BASELINE])?;
    let mut previous = 0;
    for filename in listing.lines().filter(|s| s.ends_with(".rs")) {
        previous += git(&["show", &format!("{BASELINE}:{filename}")])?.lines().count();
    }
    ensure!(previous > 0, "baseline Rust source listing failed");
    // LOC remains comparable evidence, not proof that dead or duplicate logic was removed.
    Ok(serde_json::json!({
        "schema":1,"baseline_commit":BASELINE,"categories":counts,
        "rust_source_lines_before":previous,"rust_source_lines_after":current,
        "rust_source_line_delta":current as i64 - previous as i64,
        "measurement":"all tracked Rust source/test lines; excludes notices/docs/generated runtime output"
    }))
}

pub(super) fn run() -> Result<()> {
    let root = crate::distribution::repository_root()?;
    let report = audit(&root, |args| {
        if args == ["ls-files", "-z"] {
            let output = crate::distribution_paths::git_result(&root, args)?;
            ensure!(output.success(), "tracked source listing failed");
            Ok(String::from_utf8(output.stdout)?)
        } else {
            super::git(&root, args)
        }
    })?;
    println!("{report}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_git(args: &[&str], filename: &str, baseline: &str) -> Result<String> {
        match args {
            ["ls-files", "-z"] => Ok(format!("{filename}\0README.md\0")),
            ["ls-tree", "-r", "--name-only", BASELINE] => Ok("before.rs\nREADME.md\n".into()),
            ["show", revision] if *revision == format!("{BASELINE}:before.rs") => Ok(baseline.into()),
            _ => anyhow::bail!("unexpected fixture Git query"),
        }
    }

    #[test]
    fn audit_reports_growth_equality_and_reduction_without_a_total_quota() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("README.md"), "not Rust LOC\n")?;
        for (current, after, delta) in [
            ("fn candidate() {}\n", 1, -1),
            ("fn candidate() {}\r\n// retained\r\n", 2, 0),
            ("fn candidate() {}\n// retained\n\n", 3, 1),
        ] {
            std::fs::write(root.path().join("source.rs"), current)?;
            let report = audit(root.path(), |args| {
                fixture_git(args, "source.rs", "fn original() {}\n// baseline\n")
            })?;
            assert_eq!(report, serde_json::json!({
                "schema":1,"baseline_commit":BASELINE,
                "categories":{"rust":1,"documentation":1},
                "rust_source_lines_before":2,"rust_source_lines_after":after,
                "rust_source_line_delta":delta,
                "measurement":"all tracked Rust source/test lines; excludes notices/docs/generated runtime output"
            }));
        }
        Ok(())
    }

    #[test]
    fn audit_keeps_classification_utf8_shebang_and_per_file_limits() -> Result<()> {
        let root = tempfile::tempdir()?;
        for (filename, bytes, expected) in [
            ("helper.py", b"print(1)".to_vec(), "unclassified tracked file"),
            ("source.rs", vec![255], "Rust source is not UTF-8"),
            ("source.rs", b"#!/bin/sh\n".to_vec(), "script shebang"),
            ("source.rs", "\n".repeat(800).into_bytes(), "exceeds 799 lines"),
        ] {
            std::fs::write(root.path().join(filename), bytes)?;
            let error = audit(root.path(), |args| fixture_git(args, filename, "fn old() {}\n"))
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
        std::fs::write(root.path().join("source.rs"), "\n".repeat(799))?;
        std::fs::write(root.path().join("README.md"), "retained documentation")?;
        assert!(audit(root.path(), |args| fixture_git(args, "source.rs", "fn old() {}\n")).is_ok());
        Ok(())
    }

    #[test]
    fn audit_propagates_git_failures_and_refuses_empty_inventories() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("source.rs"), "fn current() {}\n")?;
        std::fs::write(root.path().join("README.md"), "retained documentation")?;
        for failing in ["ls-files", "ls-tree", "show"] {
            let error = audit(root.path(), |args| {
                anyhow::ensure!(args[0] != failing, "fixture Git failure at {failing}");
                fixture_git(args, "source.rs", "fn old() {}\n")
            }).unwrap_err();
            assert!(error.to_string().contains("fixture Git failure"), "{error:#}");
        }
        for empty in ["ls-files", "ls-tree", "show"] {
            let error = audit(root.path(), |args| {
                if args[0] == empty { Ok(String::new()) }
                else { fixture_git(args, "source.rs", "fn old() {}\n") }
            }).unwrap_err();
            assert!(error.to_string().contains("source listing failed"), "{error:#}");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn audit_refuses_linked_tracked_source() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("original.rs"), "fn original() {}\n")?;
        std::os::unix::fs::symlink(root.path().join("original.rs"), root.path().join("source.rs"))?;
        let error = audit(root.path(), |args| fixture_git(args, "source.rs", "fn old() {}\n"))
            .unwrap_err();
        assert!(error.to_string().contains("linked tracked file refused"));
        Ok(())
    }
}
