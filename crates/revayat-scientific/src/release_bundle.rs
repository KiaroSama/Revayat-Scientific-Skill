//! Six-target archives, detached owner signatures and verified GitHub publication.
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    fs,
    path::{Path, PathBuf},
};
#[path = "release_bundle/publish.rs"]
mod publish;
#[path = "release_bundle/signing.rs"]
mod signing;

pub const REQUIRED_TARGETS: [&str; 6] = [
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
];
const PUBLIC_KEY: &str = "release-signing-public-key.asc";
const FINGERPRINT: &str = "AD46D65BE80708C2F6C93607C94F9CF383377BB8";

#[derive(Parser)]
struct Options {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Stage {
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, default_value = "release-stage")]
        output_dir: PathBuf,
    },
    Sign {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, default_value = "release-assets")]
        dir: PathBuf,
        #[arg(long, default_value = "signing/release-signing-public-key.asc")]
        public_key: PathBuf,
    },
    Publish {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, default_value = "release-assets")]
        dir: PathBuf,
    },
}

fn environment(name: &str) -> Result<String> {
    let value = std::env::var(name)
        .with_context(|| format!("required release environment variable {name} is missing"))?;
    let valid = !value.is_empty() && !value.chars().any(char::is_control);
    ensure!(valid, "invalid release environment variable");
    Ok(value)
}
fn checked_tag(tag: Option<String>) -> Result<String> {
    let tag = tag.map_or_else(|| environment("RELEASE_TAG"), Ok)?;
    let matches = tag == format!("v{}", env!("CARGO_PKG_VERSION"));
    ensure!(
        matches,
        "release tag must match the compiled package version"
    );
    Ok(tag)
}
fn archive_names(tag: &str) -> Vec<String> {
    let tag = tag.to_owned();
    let mut names = REQUIRED_TARGETS
        .iter()
        .map(|target| {
            let target = target.to_string();
            format!("revayat-scientific-{tag}-{target}.zip")
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}
fn checksum_manifest(dir: &Path, tag: &str) -> Result<String> {
    let names = archive_names(tag);
    let mut actual = fs::read_dir(dir)?
        .map(|entry| {
            let entry = entry?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("release filename is not UTF-8"))
        })
        .collect::<Result<Vec<String>>>()?;
    actual.retain(|name| name.to_ascii_lowercase().ends_with(".zip"));
    actual.sort();
    ensure!(
        actual == names,
        "release directory must contain exactly the six required ZIP archives"
    );
    let mut manifest = String::new();
    for name in names {
        let path = dir.join(&name);
        ensure!(
            !crate::identity::is_link(&path)?,
            "release archive must be a plain file"
        );
        let fingerprint =
            crate::identity::file_identity(&path, Some(crate::distribution::MAX_PAYLOAD_BYTES))?;
        manifest.push_str(&fingerprint.sha256);
        manifest.push_str("  ");
        manifest.push_str(&name);
        manifest.push('\n');
    }
    Ok(manifest)
}
fn stage(target: Option<String>, tag: String, output_dir: &Path) -> Result<()> {
    let tag = tag.as_str();
    let target = target.map_or_else(|| environment("RELEASE_TARGET"), Ok)?;
    let supported = REQUIRED_TARGETS.contains(&target.as_str());
    ensure!(supported, "unsupported release target");
    let root = crate::distribution::repository_root()?;
    let name = if target.contains("windows") {
        "revayat-scientific.exe"
    } else {
        "revayat-scientific"
    };
    let binary = root.join("target").join(&target).join("release").join(name);
    crate::distribution::package_for_target(
        &root.join("skills/revayat-scientific"),
        &root,
        &output_dir.join(format!("revayat-scientific-{tag}-{target}.zip")),
        &binary,
        &target,
    )
}

pub fn cli(args: &[String]) -> Result<i32> {
    let options = Options::try_parse_from(
        std::iter::once("release-bundle".to_owned()).chain(args.iter().cloned()),
    )?;
    match options.command {
        Command::Stage {
            target,
            tag,
            output_dir,
        } => stage(target, checked_tag(tag)?, &output_dir)?,
        Command::Sign {
            tag,
            dir,
            public_key,
        } => signing::sign(&dir, &checked_tag(tag)?, &public_key)?,
        Command::Publish { tag, dir } => publish::publish(&dir, &checked_tag(tag)?)?,
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_targets_are_exactly_six_native_x64_and_arm64_builds() {
        let actual = REQUIRED_TARGETS;
        assert_eq!(
            actual,
            [
                "x86_64-pc-windows-msvc",
                "aarch64-pc-windows-msvc",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin"
            ]
        );
        assert!(
            actual
                .iter()
                .all(|target| target.starts_with("x86_64-") || target.starts_with("aarch64-"))
        );
        assert!(!actual.iter().any(|target| target.starts_with("i686")
            || target.starts_with("i586")
            || target.starts_with("armv7")));
    }
    #[test]
    fn checksums_are_sorted_exact_and_refuse_missing_extra_or_tampered_archives() {
        let temp = tempfile::tempdir().unwrap();
        let names = archive_names("v2.0.0");
        for name in names.iter().rev() {
            fs::write(temp.path().join(name), b"abc").unwrap();
        }
        let actual = checksum_manifest(temp.path(), "v2.0.0").unwrap();
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let expected = names
            .iter()
            .map(|name| {
                let name = name.as_str();
                format!("{digest}  {name}\n")
            })
            .collect::<String>();
        assert_eq!(actual, expected);
        fs::write(temp.path().join("unexpected.zip"), b"abc").unwrap();
        assert!(checksum_manifest(temp.path(), "v2.0.0").is_err());
        fs::remove_file(temp.path().join("unexpected.zip")).unwrap();
        fs::write(temp.path().join(&names[0]), b"abd").unwrap();
        assert_ne!(checksum_manifest(temp.path(), "v2.0.0").unwrap(), expected);
        fs::remove_file(temp.path().join(&names[0])).unwrap();
        assert!(checksum_manifest(temp.path(), "v2.0.0").is_err());
    }
    #[test]
    fn committed_release_public_key_is_an_armored_pgp_block() {
        let key = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../signing")
            .join(PUBLIC_KEY);
        assert!(key.is_file());
        let contents = fs::read_to_string(key).unwrap();
        assert_eq!(
            contents.lines().next(),
            Some("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        );
        assert!(
            contents
                .trim_end()
                .ends_with("-----END PGP PUBLIC KEY BLOCK-----")
        );
    }
}
