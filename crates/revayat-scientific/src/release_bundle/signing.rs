//! Isolated GnuPG keyrings; secret input and tool diagnostics never leave this boundary.
use super::*;
use crate::runtime::{self, CommandSpec};
use std::time::Duration;

struct Keyring(tempfile::TempDir);
impl Keyring {
    fn new() -> Result<Self> {
        Ok(Self(
            tempfile::Builder::new()
                .prefix(".revayat-release-keyring-")
                .tempdir()?,
        ))
    }
    fn command(&self, program: &str) -> CommandSpec {
        let mut spec = CommandSpec::new(program);
        spec.cwd = Some(self.0.path().to_owned());
        spec.env
            .insert("GNUPGHOME".into(), self.0.path().as_os_str().to_owned());
        spec.env_remove
            .extend(["RELEASE_GPG_PRIVATE_KEY", "GH_TOKEN"].map(Into::into));
        spec.timeout = Duration::from_secs(60);
        spec.max_output = 1024 * 1024;
        spec
    }
    fn gpg(&self, args: &[&str], input: Option<&[u8]>) -> Result<runtime::CommandOutput> {
        let spec = self
            .command("gpg")
            .args(["--batch", "--yes", "--no-tty"])
            .args(args.iter().copied());
        let output = if let Some(input) = input {
            runtime::run_with_input(&spec, input)
        } else {
            runtime::run(&spec)
        };
        // Never propagate retained command output, imported identities or private key parse diagnostics.
        output.map_err(|_| anyhow::anyhow!("bounded release GPG operation failed"))
    }
    fn import(&self, bytes: &[u8]) -> Result<()> {
        let succeeded = self.gpg(&["--import"], Some(bytes))?.success();
        ensure!(succeeded, "release GPG key import failed");
        Ok(())
    }
    fn require_public_fingerprint(&self) -> Result<()> {
        let result = self.gpg(&["--with-colons", "--fingerprint", "--list-keys"], None)?;
        let text = std::str::from_utf8(&result.stdout)
            .context("invalid release public fingerprint output")?;
        let fingerprints = text
            .lines()
            .filter(|line| line.starts_with("fpr:"))
            .filter_map(|line| line.split(':').nth(9))
            .collect::<Vec<_>>();
        let primary_keys = text.lines().filter(|line| line.starts_with("pub:")).count();
        let valid =
            result.success() && primary_keys == 1 && fingerprints.first() == Some(&FINGERPRINT);
        ensure!(
            valid,
            "release public key fingerprint differs from approved signer"
        );
        Ok(())
    }
    fn sign(&self, file: &Path) -> Result<()> {
        let signature = signature_path(file);
        let file = file.to_str().context("release path is not UTF-8")?;
        let signature = signature
            .to_str()
            .context("release signature path is not UTF-8")?;
        let succeeded = self
            .gpg(
                &[
                    "--local-user",
                    FINGERPRINT,
                    "--armor",
                    "--detach-sign",
                    "--output",
                    signature,
                    file,
                ],
                None,
            )?
            .success();
        ensure!(succeeded, "release detached signing failed");
        Ok(())
    }
    fn verify(&self, signature: &Path, file: &Path) -> Result<bool> {
        let signature = signature
            .to_str()
            .context("release signature path is not UTF-8")?;
        let file = file.to_str().context("release path is not UTF-8")?;
        Ok(self.gpg(&["--verify", signature, file], None)?.success())
    }
}
impl Drop for Keyring {
    fn drop(&mut self) {
        // Stop only agents belonging to this disposable GNUPGHOME before deleting its files.
        let spec = self.command("gpgconf").args(["--kill", "all"]);
        let _ = runtime::run(&spec);
    }
}
fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".asc");
    name.into()
}
fn signed_files(dir: &Path, tag: &str) -> Vec<PathBuf> {
    let mut files = archive_names(tag)
        .into_iter()
        .map(|name| dir.join(name))
        .collect::<Vec<_>>();
    files.push(dir.join("SHA256SUMS"));
    files
}

pub(super) fn sign(dir: &Path, tag: &str, public_key: &Path) -> Result<()> {
    let manifest = checksum_manifest(dir, tag)?;
    let dir = dir.canonicalize()?;
    let public_key = public_key.canonicalize()?;
    let public = crate::resource::bounded_read(&public_key, 1024 * 1024)?;
    fs::write(dir.join("SHA256SUMS"), manifest.as_bytes())?;
    {
        let keyring = Keyring::new()?;
        let secret = std::env::var("RELEASE_GPG_PRIVATE_KEY")
            .map_err(|_| anyhow::anyhow!("RELEASE_GPG_PRIVATE_KEY is required for signing"))?;
        let present = !secret.is_empty();
        ensure!(present, "release signing key is empty");
        keyring.import(secret.as_bytes())?;
        keyring.require_public_fingerprint()?;
        for file in signed_files(&dir, tag) {
            keyring.sign(&file)?;
        }
    }
    fs::copy(public_key, dir.join(PUBLIC_KEY))?;
    verify(&dir, tag, &public)?;
    Ok(())
}

pub(super) fn verify(dir: &Path, tag: &str, public: &[u8]) -> Result<()> {
    let expected = checksum_manifest(dir, tag)?;
    let manifest = crate::resource::bounded_read(&dir.join("SHA256SUMS"), 65536)?;
    ensure!(
        manifest == expected.as_bytes(),
        "release checksums differ from archive bytes"
    );
    let dir = dir.canonicalize()?;
    let keyring = Keyring::new()?;
    keyring.import(public)?;
    keyring.require_public_fingerprint()?;
    for file in signed_files(&dir, tag) {
        let verified = keyring.verify(&signature_path(&file), &file)?;
        ensure!(verified, "release detached signature verification failed");
    }
    let mut tampered = manifest;
    let byte = tampered.first_mut().context("release manifest is empty")?;
    *byte ^= 1;
    let path = keyring.0.path().join("tampered-SHA256SUMS");
    fs::write(&path, tampered)?;
    let rejected = !keyring.verify(&dir.join("SHA256SUMS.asc"), &path)?;
    ensure!(rejected, "release signature accepted a tampered manifest");
    Ok(())
}
