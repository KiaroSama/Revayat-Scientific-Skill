//! Closed, immutable resource snapshots for an external static HTML renderer.
//! URL-bearing syntax is rewritten by typed parsers, never by prose replacement.
//! Srcset, duplicate HTML attributes, unclassified SVG references, XML stylesheets
//! style markup/CDATA/entities and dynamic CSS attribute URLs require review.
//! Explicit asset encoding declarations must agree with UTF-8 admission.
use super::{MAX_RESOURCE_BYTES, MAX_TOTAL_BYTES, ORIGIN, ResourcePolicy, io_guard, sha256};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use url::Url;

#[path = "resource_container_syntax.rs"]
mod syntax;

struct Stager<'a> {
    policy: &'a mut ResourcePolicy,
    targets: BTreeMap<String, String>,
    files: BTreeMap<PathBuf, Vec<u8>>,
    bytes: usize,
}
impl Stager<'_> {
    fn insert(&mut self, name: PathBuf, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            bytes.len() <= MAX_RESOURCE_BYTES,
            "container snapshot resource exceeds 64 MiB"
        );
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .context("container snapshot byte budget overflow")?;
        ensure!(
            self.bytes <= MAX_TOTAL_BYTES && self.files.len() < 2048,
            "container snapshot resource budget exceeded"
        );
        ensure!(
            self.files.insert(name, bytes).is_none(),
            "container snapshot path collision"
        );
        Ok(())
    }
    fn reference(&mut self, reference: &str, base: &Url, depth: usize) -> Result<String> {
        ensure!(
            depth <= 32,
            "container resource dependency depth exceeds 32"
        );
        if reference.trim().is_empty() || reference.trim_start().starts_with('#') {
            return Ok(reference.to_owned());
        }
        super::validate_authority(reference)?;
        let mut parsed = base
            .join(reference)
            .context("container resource requires a static URL")?;
        let fragment = parsed.fragment().map(str::to_owned);
        parsed.set_fragment(None);
        let key = parsed.as_str().to_owned();
        let target = if let Some(target) = self.targets.get(&key) {
            target.clone()
        } else {
            let (bytes, mime) = self.policy.fetch(&key)?;
            let extension = match mime.as_str() {
                "text/css" => "css",
                "image/svg+xml" => "svg",
                "image/png" => "png",
                "image/jpeg" => "jpg",
                "image/gif" => "gif",
                "image/webp" => "webp",
                "font/ttf" => "ttf",
                "font/otf" => "otf",
                "font/woff" => "woff",
                "font/woff2" => "woff2",
                "image/x-icon" => "ico",
                "application/pdf" => "pdf",
                _ => bail!("container resource MIME requires reviewed static artwork"),
            };
            // The URL participates in the identity: identical CSS reached via
            // different aliases can have different relative dependency bases.
            let name = format!(".revayat-assets/{}.{}", sha256(key.as_bytes()), extension);
            let target = format!("file:///input/{name}");
            self.targets.insert(key.clone(), target.clone());
            let rewritten = match mime.as_str() {
                "text/css" => syntax::css(std::str::from_utf8(&bytes)?, &mut |url| {
                    self.reference(url, &parsed, depth + 1)
                })?
                .into_bytes(),
                "image/svg+xml" => syntax::svg(std::str::from_utf8(&bytes)?, &mut |url| {
                    self.reference(url, &parsed, depth + 1)
                })?
                .into_bytes(),
                _ => bytes,
            };
            self.insert(name.into(), rewritten)?;
            target
        };
        Ok(match fragment {
            Some(fragment) => format!("{target}#{fragment}"),
            None => target,
        })
    }
}

pub(super) fn stage(policy: &mut ResourcePolicy, destination: &Path) -> Result<()> {
    ensure!(
        !policy.denied,
        "container resource policy already denied access"
    );
    ensure!(
        !crate::identity::is_link(destination)?,
        "linked container snapshot destination refused"
    );
    if destination.exists() {
        ensure!(
            destination.is_dir() && fs::read_dir(destination)?.next().is_none(),
            "container snapshot destination must be an empty directory"
        );
    }
    let mut base = Url::parse(ORIGIN)?;
    base.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("invalid container resource origin"))?
        .push(
            policy
                .source
                .file_name()
                .and_then(|s| s.to_str())
                .context("HTML source filename must be UTF-8")?,
        );
    let (source, _) = policy.fetch(base.as_str())?;
    let mut stager = Stager {
        policy,
        targets: BTreeMap::new(),
        files: BTreeMap::new(),
        bytes: 0,
    };
    let main = syntax::html(std::str::from_utf8(&source)?, &mut |url| {
        stager.reference(url, &base, 0)
    })?;
    stager.insert(".revayat-main.html".into(), main.into_bytes())?;
    // Reopen through the same descriptor boundary before committing a snapshot.
    // Publication performs its own final digest check after the external render.
    for (path, digest) in &stager.policy.resources {
        let actual = io_guard::read(path, &stager.policy.root, MAX_RESOURCE_BYTES, |_, _| Ok(()))?;
        ensure!(
            sha256(&actual) == *digest,
            "resource changed before container staging"
        );
    }
    if !destination.exists() {
        fs::create_dir(destination)?;
    }
    if stager.files.len() > 1 {
        fs::create_dir(destination.join(".revayat-assets"))?;
    }
    for (name, bytes) in stager.files {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    Ok(())
}
