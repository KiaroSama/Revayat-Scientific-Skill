//! Bind release operations to the checked-out commit and any existing local tag.
use super::*;
use crate::runtime::{self, CommandOutput, CommandSpec};
use std::time::Duration;

pub(super) fn normalized_sha(value: &str) -> Result<String> {
    ensure!(
        value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "release revision must be one full Git commit SHA"
    );
    Ok(value.to_ascii_lowercase())
}

fn output_sha(output: &CommandOutput) -> Result<String> {
    ensure!(output.success(), "release source revision lookup failed");
    normalized_sha(std::str::from_utf8(&output.stdout)?.trim())
}

fn verify_checkout_with(
    tag: &str,
    expected: Option<&str>,
    mut git: impl FnMut(&[&str]) -> Result<CommandOutput>,
) -> Result<()> {
    let head = output_sha(&git(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        "HEAD^{commit}",
    ])?)?;
    if let Some(expected) = expected {
        ensure!(
            head == normalized_sha(expected)?,
            "release checkout differs from the workflow source revision"
        );
    }
    let reference = format!("refs/tags/{tag}");
    let exists = git(&["show-ref", "--verify", "--quiet", &reference])?;
    if exists.code == 1 {
        // A new version may create its tag when the verified release is published.
        return Ok(());
    }
    ensure!(exists.success(), "release tag lookup failed");
    let tagged = output_sha(&git(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{reference}^{{commit}}"),
    ])?)?;
    ensure!(
        head == tagged,
        "release tag differs from the source checkout"
    );
    Ok(())
}

pub(super) fn verify_checkout(root: &Path, tag: &str) -> Result<()> {
    let expected = if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        || std::env::var_os("GITHUB_SHA").is_some()
    {
        Some(environment("GITHUB_SHA")?)
    } else {
        None
    };
    verify_checkout_with(tag, expected.as_deref(), |args| {
        let mut spec = CommandSpec::new("git")
            .args(std::iter::once("--no-replace-objects").chain(args.iter().copied()));
        spec.cwd = Some(root.to_owned());
        spec.timeout = Duration::from_secs(10);
        spec.max_output = 4096;
        spec.env_remove
            .extend(["GH_TOKEN", "RELEASE_GPG_PRIVATE_KEY"].map(Into::into));
        runtime::run(&spec).map_err(|_| anyhow::anyhow!("release source inspection failed"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn output(code: i32, text: &str) -> CommandOutput {
        CommandOutput {
            code,
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn source_sha_is_exact_full_hex_and_normalizes_only_hex_case() {
        assert_eq!(normalized_sha(&SHA.to_ascii_uppercase()).unwrap(), SHA);
        for value in [
            "",
            "main",
            "../secret",
            &"g".repeat(40),
            &format!("{SHA}\n"),
        ] {
            assert!(normalized_sha(value).is_err());
        }
    }

    #[test]
    fn local_tag_is_peeled_to_a_commit_and_missing_tag_can_be_created() {
        for present in [false, true] {
            let mut calls = Vec::new();
            verify_checkout_with("v2.1.0", Some(SHA), |args| {
                calls.push(args.join(" "));
                Ok(if args[0] == "show-ref" {
                    output(i32::from(!present), "")
                } else {
                    output(0, &format!("{SHA}\n"))
                })
            })
            .unwrap();
            assert_eq!(calls.len(), if present { 3 } else { 2 });
            if present {
                assert_eq!(
                    calls[2],
                    "rev-parse --verify --end-of-options refs/tags/v2.1.0^{commit}"
                );
            }
        }
    }

    #[test]
    fn local_mismatch_and_git_failure_refuse_release_preparation() {
        let foreign = "b".repeat(40);
        assert!(verify_checkout_with("v2.1.0", Some(&foreign), |_| Ok(output(0, SHA))).is_err());
        for code in [0, 128] {
            assert!(
                verify_checkout_with("v2.1.0", Some(SHA), |args| {
                    Ok(match args[0] {
                        "show-ref" => output(code, ""),
                        _ if args[3].starts_with("HEAD") => output(0, SHA),
                        _ => output(0, &foreign),
                    })
                })
                .is_err()
            );
        }
    }
}
