//! Local-only immutable-source resource policy shared by all HTML renderers.
use crate::html::ParsedHtml;
#[path = "resource_io.rs"]
mod io_guard;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
pub use io_guard::ReadBoundary;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;
pub const ORIGIN: &str = "https://revayat.invalid";
pub const MAX_RESOURCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const ALLOWED: &str = "css png jpg jpeg gif webp svg ttf otf woff woff2 ico pdf";
#[derive(Debug)]
pub struct ResourcePolicy {
    pub source: PathBuf,
    pub root: PathBuf,
    pub source_bytes: Vec<u8>,
    pub source_text: String,
    pub resources: BTreeMap<PathBuf, String>,
    pub denied: bool,
    pub total: usize,
    pub requests: usize,
    embedded: BTreeMap<String, usize>,
    preflight_seen: BTreeSet<PathBuf>,
    preflight_bytes: usize,
}
impl ResourcePolicy {
    pub fn new(source: &Path) -> Result<Self> {
        let source = source.canonicalize()?;
        let root = source
            .parent()
            .context("source has no parent")?
            .to_path_buf();
        let source_bytes = io_guard::read(&source, &root, MAX_RESOURCE_BYTES, |_, _| Ok(()))?;
        let source_text = String::from_utf8(source_bytes.clone())?;
        let model = ParsedHtml::parse(&source_text)?;
        for n in &model.nodes {
            if n.attr("rel")
                .split_ascii_whitespace()
                .any(|s| s.eq_ignore_ascii_case("attachment"))
            {
                bail!("PDF attachment requires explicit authorization; omitted by this renderer");
            }
            if crate::html::member("script iframe object embed base", &n.tag)
                || (n.tag == "meta" && n.attr("http-equiv").eq_ignore_ascii_case("refresh"))
            {
                bail!("active HTML content is not supported for scientific rendering");
            }
        }
        let resources = BTreeMap::from([(source.clone(), sha256(&source_bytes))]);
        let mut policy = Self {
            source,
            root,
            source_bytes,
            source_text,
            resources,
            denied: false,
            total: 0,
            requests: 0,
            embedded: BTreeMap::new(),
            preflight_seen: BTreeSet::new(),
            preflight_bytes: 0,
        };
        let mut base = Url::parse(ORIGIN)?;
        base.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid document resource origin"))?
            .push(
                policy
                    .source
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("HTML source filename must be UTF-8")?,
            );
        policy.preflight_urls(crate::resource_preflight::html_urls(&model)?, &base, 0)?;
        ensure!(
            policy.requests < 2048
                && policy
                    .total
                    .checked_add(policy.source_bytes.len())
                    .is_some_and(|n| n <= MAX_TOTAL_BYTES),
            "embedded render resource budget exceeded before browser launch"
        );
        Ok(policy)
    }
    pub fn fetch(&mut self, url: &str) -> Result<(Vec<u8>, String)> {
        self.fetch_observed(url, |_, _| Ok(()))
    }
    /// Deterministic hooks surround the actual descriptor I/O used in production.
    pub fn fetch_observed(
        &mut self,
        url: &str,
        mut boundary: impl FnMut(ReadBoundary, &Path) -> Result<()>,
    ) -> Result<(Vec<u8>, String)> {
        let result = self.fetch_inner(url, &mut boundary);
        if result.is_err() {
            self.denied = true;
        }
        result
    }
    fn fetch_inner(
        &mut self,
        url: &str,
        boundary: &mut impl FnMut(ReadBoundary, &Path) -> Result<()>,
    ) -> Result<(Vec<u8>, String)> {
        validate_authority(url)?;
        let parsed = Url::parse(url)?;
        let canonical = parsed.as_str().to_owned();
        let reserved = if parsed.scheme() == "data" {
            self.embedded.get_mut(&canonical).is_some_and(|remaining| {
                if *remaining == 0 {
                    false
                } else {
                    *remaining -= 1;
                    true
                }
            })
        } else {
            false
        };
        if !reserved {
            self.requests += 1;
            ensure!(self.requests <= 2048, "render resource count exceeds 2048");
        }
        let (data, mime) = if parsed.scheme() == "data" {
            decode_embedded(&canonical)?
        } else {
            let path = self.resolve_url(&parsed)?;
            let resolved = path;
            if !resolved.starts_with(&self.root)
                || !resolved.is_file()
                || (resolved != self.source
                    && !crate::html::member(
                        ALLOWED,
                        &resolved
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase(),
                    ))
            {
                bail!("resource is outside the approved document asset boundary");
            }
            let data = if resolved == self.source {
                self.source_bytes.clone()
            } else {
                io_guard::read(&resolved, &self.root, MAX_RESOURCE_BYTES, boundary)?
            };
            let digest = sha256(&data);
            if self
                .resources
                .get(&resolved)
                .is_some_and(|previous| previous != &digest)
            {
                bail!("resource changed during rendering");
            }
            self.resources.insert(resolved.clone(), digest);
            self.scan_file(&resolved, &parsed, &data, 0)?;
            let mime = mime_for(&resolved).into();
            (data, mime)
        };
        if !reserved {
            self.total = self
                .total
                .checked_add(data.len())
                .context("render resource byte limit exceeded")?;
        }
        if data.len() > MAX_RESOURCE_BYTES || self.total > MAX_TOTAL_BYTES {
            bail!("render resource byte limit exceeded");
        }
        if !reserved && parsed.scheme() == "data" && mime == "image/svg+xml" {
            self.preflight_urls(crate::resource_preflight::svg_urls(&data)?, &parsed, 0)?;
        }
        Ok((data, mime))
    }
    fn resolve_url(&self, parsed: &Url) -> Result<PathBuf> {
        let path = if parsed.scheme() == "https"
            && parsed.host_str() == Some("revayat.invalid")
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.port().is_none()
        {
            let decoded = String::from_utf8(percent_decode(parsed.path())?)?;
            self.root.join(decoded.trim_start_matches('/'))
        } else if parsed.scheme() == "file" && parsed.host_str().is_none_or(|h| h == "localhost") {
            parsed
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid local file URL"))?
        } else {
            bail!("network and unapproved URL schemes are denied");
        };
        let resolved = path.canonicalize()?;
        ensure!(
            resolved.starts_with(&self.root)
                && resolved.is_file()
                && (resolved == self.source
                    || crate::html::member(
                        ALLOWED,
                        &resolved
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase()
                    )),
            "resource is outside the approved document asset boundary"
        );
        ensure!(
            fs::metadata(&resolved)?.len() <= MAX_RESOURCE_BYTES as u64,
            "render resource exceeds 64 MiB"
        );
        Ok(resolved)
    }
    fn preflight_urls(&mut self, urls: Vec<String>, base: &Url, depth: usize) -> Result<()> {
        ensure!(depth <= 32, "render resource dependency depth exceeds 32");
        for reference in urls {
            if reference.trim().is_empty() || reference.trim_start().starts_with('#') {
                continue;
            }
            validate_authority(&reference)?;
            let parsed = base
                .join(&reference)
                .context("resource requires a static resolvable URL")?;
            if parsed.scheme() == "data" {
                let canonical = parsed.as_str().to_owned();
                let (data, mime) = decode_embedded(&canonical)?;
                self.requests += 1;
                self.total = self
                    .total
                    .checked_add(data.len())
                    .context("embedded render resource byte limit exceeded")?;
                ensure!(
                    self.requests <= 2048 && self.total <= MAX_TOTAL_BYTES,
                    "embedded render resource budget exceeded before browser launch"
                );
                *self.embedded.entry(canonical).or_default() += 1;
                if mime == "image/svg+xml" {
                    self.preflight_urls(
                        crate::resource_preflight::svg_urls(&data)?,
                        &parsed,
                        depth + 1,
                    )?;
                }
            } else {
                let path = self.resolve_url(&parsed)?;
                if !matches!(mime_for(&path), "text/css" | "image/svg+xml")
                    || self.preflight_seen.contains(&path)
                {
                    continue;
                }
                let bytes = io_guard::read(&path, &self.root, MAX_RESOURCE_BYTES, |_, _| Ok(()))?;
                self.scan_file(&path, &parsed, &bytes, depth)?;
            }
        }
        Ok(())
    }
    fn scan_file(&mut self, path: &Path, parsed: &Url, bytes: &[u8], depth: usize) -> Result<()> {
        let mime = mime_for(path);
        if !matches!(mime, "text/css" | "image/svg+xml")
            || !self.preflight_seen.insert(path.to_owned())
        {
            return Ok(());
        }
        ensure!(
            self.preflight_seen.len() <= 2048,
            "render dependency count exceeds 2048"
        );
        self.preflight_bytes = self
            .preflight_bytes
            .checked_add(bytes.len())
            .context("resource preflight byte budget exceeded")?;
        ensure!(
            self.preflight_bytes <= MAX_TOTAL_BYTES,
            "resource preflight byte budget exceeded"
        );
        self.resources.insert(path.to_owned(), sha256(bytes));
        let urls = if mime == "text/css" {
            crate::resource_preflight::css_urls(std::str::from_utf8(bytes)?)?
        } else {
            crate::resource_preflight::svg_urls(bytes)?
        };
        self.preflight_urls(urls, parsed, depth + 1)
    }
}
fn validate_authority(reference: &str) -> Result<()> {
    let compact: String = reference
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let reference = compact.trim_matches(|c: char| c.is_ascii() && c <= ' ');
    if let Some((scheme, rest)) = reference.split_once("://")
        && scheme.eq_ignore_ascii_case("https")
    {
        ensure!(
            rest.split(['/', '?', '#']).next() == Some("revayat.invalid"),
            "network and unapproved URL authorities are denied"
        );
    }
    Ok(())
}
fn decode_embedded(url: &str) -> Result<(Vec<u8>, String)> {
    let body = url.get(5..).context("invalid embedded resource URL")?;
    let (header, encoded) = body.split_once(',').context("invalid embedded resource")?;
    let mime = header.split(';').next().unwrap_or("").to_ascii_lowercase();
    ensure!(
        crate::html::member(
            "image/png image/jpeg image/gif image/webp image/svg+xml",
            &mime
        ),
        "unsupported embedded resource type"
    );
    ensure!(
        encoded.len() <= MAX_RESOURCE_BYTES * 2,
        "embedded resource is too large"
    );
    let data = if header.to_ascii_lowercase().ends_with(";base64") {
        base64::engine::general_purpose::STANDARD.decode(encoded)?
    } else {
        percent_decode_bytes(encoded)?
    };
    ensure!(
        data.len() <= MAX_RESOURCE_BYTES,
        "embedded render resource exceeds 64 MiB"
    );
    Ok((data, mime))
}
pub fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit as u64 {
        bail!(
            "required input is not a bounded regular file: {}",
            path.display()
        );
    }
    let mut data = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    if data.len() > limit {
        bail!("input exceeds its byte limit: {}", path.display());
    }
    Ok(data)
}
pub fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
pub fn percent_decode(value: &str) -> Result<Vec<u8>> {
    let out = percent_decode_bytes(value)?;
    if out.contains(&0) {
        bail!("NUL in asset URL");
    }
    Ok(out)
}
fn percent_decode_bytes(value: &str) -> Result<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                bail!("invalid percent-encoded URL");
            }
            let a = (bytes[i + 1] as char)
                .to_digit(16)
                .context("invalid percent-encoded URL")?;
            let b = (bytes[i + 2] as char)
                .to_digit(16)
                .context("invalid percent-encoded URL")?;
            out.push((a * 16 + b) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}
fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}
#[cfg(test)]
#[path = "resource_tests.rs"]
mod tests;
