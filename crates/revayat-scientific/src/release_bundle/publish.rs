//! Network publication begins only after local archive and owner signature verification.
use super::*;
use reqwest::{
    Method, StatusCode,
    blocking::{Client, Response},
    header::{HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use std::{io::Read, time::Duration};

fn decode(response: Response) -> Result<Value> {
    let successful = response.status().is_success();
    ensure!(successful, "GitHub release request failed");
    let mut bytes = Vec::new();
    response.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "GitHub release response exceeds byte limit"
    );
    serde_json::from_slice(&bytes).context("GitHub release response is invalid JSON")
}
trait ReleaseApi {
    fn get(&mut self, path: &str) -> Result<Option<Value>>;
    fn json(&mut self, method: Method, path: &str, body: &Value) -> Result<Value>;
    fn delete(&mut self, path: &str) -> Result<()>;
    fn upload(&mut self, id: u64, name: &str, bytes: Vec<u8>) -> Result<Value>;
}

struct GitHubRelease {
    client: Client,
    repository: String,
}
impl GitHubRelease {
    fn url(&self, path: &str) -> String {
        format!("https://api.github.com/repos/{}/{path}", self.repository)
    }
}
impl ReleaseApi for GitHubRelease {
    fn get(&mut self, path: &str) -> Result<Option<Value>> {
        let response = self
            .client
            .get(self.url(path))
            .send()
            .context("GitHub release lookup failed")?;
        if response.status() == StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            decode(response).map(Some)
        }
    }
    fn json(&mut self, method: Method, path: &str, body: &Value) -> Result<Value> {
        decode(
            self.client
                .request(method, self.url(path))
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(body)?)
                .send()
                .context("GitHub release request could not complete")?,
        )
    }
    fn delete(&mut self, path: &str) -> Result<()> {
        let deleted = self
            .client
            .delete(self.url(path))
            .send()?
            .status()
            .is_success();
        ensure!(deleted, "GitHub release asset replacement failed");
        Ok(())
    }
    fn upload(&mut self, id: u64, name: &str, bytes: Vec<u8>) -> Result<Value> {
        decode(
            self.client
                .post(format!(
                    "https://uploads.github.com/repos/{}/releases/{id}/assets",
                    self.repository
                ))
                .query(&[("name", name)])
                .header("Content-Type", "application/octet-stream")
                .body(bytes)
                .send()?,
        )
    }
}
fn release_body() -> String {
    format!(
        "Native Rust bundles for Windows and Linux, each in x64 and arm64 (four targets).\n\nVerify the self-managed project release signing key fingerprint `{FINGERPRINT}`, then run:\n```text\ngpg --import release-signing-public-key.asc\ngpg --verify SHA256SUMS.asc SHA256SUMS\nsha256sum --check SHA256SUMS\n```\n\nEach archive has a detached .zip.asc signature. GitHub build provenance attestations accompany the four ZIP archives."
    )
}
fn asset_names(tag: &str) -> Vec<String> {
    let mut names = archive_names(tag);
    names.extend(archive_names(tag).into_iter().map(|name| name + ".asc"));
    names.extend(["SHA256SUMS", "SHA256SUMS.asc", PUBLIC_KEY].map(str::to_owned));
    names
}

pub(super) fn publish(dir: &Path, tag: &str) -> Result<()> {
    let dir = dir.canonicalize()?;
    let public = crate::resource::bounded_read(&dir.join(PUBLIC_KEY), 1024 * 1024)?;
    signing::verify(&dir, tag, &public)?;
    let uploads = asset_names(tag)
        .into_iter()
        .map(|name| {
            let path = dir.join(&name);
            let fingerprint = crate::identity::file_identity(
                &path,
                Some(crate::distribution::MAX_PAYLOAD_BYTES),
            )?;
            Ok((name, fingerprint))
        })
        .collect::<Result<Vec<_>>>()?;
    let repo = environment("GITHUB_REPOSITORY")?;
    let parts = repo.split('/').collect::<Vec<_>>();
    let valid_repo = parts.len() == 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        });
    ensure!(valid_repo, "invalid release repository");
    let sha = source::normalized_sha(&environment("GITHUB_SHA")?)?;
    let token = std::env::var("GH_TOKEN")
        .map_err(|_| anyhow::anyhow!("GH_TOKEN is required for publication"))?;
    let valid_token = !token.is_empty() && !token.chars().any(char::is_whitespace);
    ensure!(valid_token, "invalid GitHub release token");
    let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| anyhow::anyhow!("invalid GitHub release token"))?;
    auth.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", auth);
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static("2022-11-28"),
    );
    headers.insert(
        "Accept",
        HeaderValue::from_static("application/vnd.github+json"),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("revayat-scientific-release")
        .default_headers(headers)
        .build()?;
    publish_verified(
        &mut GitHubRelease {
            client,
            repository: repo,
        },
        &dir,
        tag,
        &sha,
        uploads,
    )
}

fn publish_verified(
    api: &mut impl ReleaseApi,
    dir: &Path,
    tag: &str,
    sha: &str,
    uploads: Vec<(String, crate::identity::Fingerprint)>,
) -> Result<()> {
    let sha = source::normalized_sha(sha)?;
    let tag_existed = require_remote_tag(api, tag, &sha)?;
    let release = if let Some(release) = api.get(&format!("releases/tags/{tag}"))? {
        release
    } else {
        api.json(
            Method::POST,
            "releases",
            &json!({"tag_name":tag, "target_commitish":sha,
            "name":format!("Revayat Scientific {tag}"), "draft":true, "prerelease":false, "body":release_body()}),
        )?
    };
    let id = release["id"]
        .as_u64()
        .context("GitHub release ID missing")?;
    ensure!(
        id > 0 && release["tag_name"] == tag,
        "GitHub release identity differs from the requested tag"
    );
    let release_path = format!("releases/{id}");
    // List every asset, including later pages, before replacing only the same owned names.
    let mut old_assets = Vec::new();
    let mut complete = false;
    for page in 1..=100 {
        let page_value = api
            .get(&format!("{release_path}/assets?per_page=100&page={page}"))?
            .context("GitHub release asset listing is missing")?;
        let rows = page_value
            .as_array()
            .context("GitHub release asset listing is invalid")?;
        old_assets.extend(rows.iter().cloned());
        if rows.len() < 100 {
            complete = true;
            break;
        }
    }
    ensure!(complete, "GitHub release asset listing exceeds page limit");
    // Stage a rerun as draft too, so incomplete replacements never advertise a finished release.
    api.json(
        Method::PATCH,
        &release_path,
        &json!({"draft":true,"target_commitish":sha}),
    )?;
    for (name, fingerprint) in uploads {
        for asset in old_assets
            .iter()
            .filter(|asset| asset["name"].as_str() == Some(name.as_str()))
        {
            let asset_id = asset["id"]
                .as_u64()
                .context("GitHub release asset ID missing")?;
            api.delete(&format!("releases/assets/{asset_id}"))?;
        }
        let bytes = crate::resource::bounded_read(
            &dir.join(&name),
            crate::distribution::MAX_PAYLOAD_BYTES as usize,
        )?;
        use sha2::{Digest, Sha256};
        let unchanged = bytes.len() as u64 == fingerprint.size
            && format!("{:x}", Sha256::digest(&bytes)) == fingerprint.sha256;
        ensure!(unchanged, "verified release asset changed before upload");
        let uploaded = api.upload(id, &name, bytes)?;
        let matches =
            uploaded["name"].as_str() == Some(name.as_str()) && uploaded["state"] == "uploaded";
        ensure!(matches, "GitHub release upload was not finalized");
    }
    let tag_present = require_remote_tag(api, tag, &sha)?;
    ensure!(
        !tag_existed || tag_present,
        "release tag disappeared during publication"
    );
    api.json(
        Method::PATCH,
        &release_path,
        &json!({"draft":false,"target_commitish":sha}),
    )?;
    Ok(())
}

/// Existing tags must peel to the built commit; a missing tag may be created at it.
fn require_remote_tag(api: &mut impl ReleaseApi, tag: &str, expected: &str) -> Result<bool> {
    let Some(reference) = api.get(&format!("git/ref/tags/{tag}"))? else {
        return Ok(false);
    };
    ensure!(
        reference["ref"] == format!("refs/tags/{tag}"),
        "GitHub tag reference differs from the requested release"
    );
    let mut object = reference["object"].clone();
    let mut visited = std::collections::BTreeSet::new();
    for depth in 0..=16 {
        let sha = source::normalized_sha(
            object["sha"]
                .as_str()
                .context("GitHub tag object SHA missing")?,
        )?;
        match object["type"].as_str() {
            Some("commit") => {
                ensure!(
                    sha == expected,
                    "release tag differs from the built source revision"
                );
                return Ok(true);
            }
            Some("tag") => {
                ensure!(
                    depth < 16 && visited.insert(sha.clone()),
                    "GitHub tag chain is cyclic or too deep"
                );
                let annotated = api
                    .get(&format!("git/tags/{sha}"))?
                    .context("GitHub annotated tag object is missing")?;
                ensure!(
                    source::normalized_sha(
                        annotated["sha"]
                            .as_str()
                            .context("GitHub annotated tag SHA missing")?
                    )? == sha,
                    "GitHub annotated tag identity differs"
                );
                object = annotated["object"].clone();
            }
            _ => anyhow::bail!("release tag does not resolve to a commit"),
        }
    }
    anyhow::bail!("GitHub tag chain is too deep")
}

#[cfg(test)]
#[path = "publish_tests.rs"]
mod tests;
