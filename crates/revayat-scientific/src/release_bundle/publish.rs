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
fn json_request(client: &Client, method: Method, url: &str, body: &Value) -> Result<Value> {
    let request = client
        .request(method, url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(body)?);
    decode(
        request
            .send()
            .context("GitHub release request could not complete")?,
    )
}
fn release_body() -> String {
    format!(
        "Native Rust bundles for Windows, Linux and macOS, each in x64 and arm64 (six targets).\n\nVerify the self-managed project release signing key fingerprint `{FINGERPRINT}`, then run:\n```text\ngpg --import release-signing-public-key.asc\ngpg --verify SHA256SUMS.asc SHA256SUMS\nsha256sum --check SHA256SUMS\n```\n\nEach archive has a detached .zip.asc signature. GitHub build provenance attestations accompany the six ZIP archives."
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
    let sha = environment("GITHUB_SHA")?;
    let valid_sha = sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit());
    ensure!(valid_sha, "invalid release commit SHA");
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
    let base = format!("https://api.github.com/repos/{repo}/releases");
    let response = client
        .get(format!("{base}/tags/{tag}"))
        .send()
        .context("GitHub release lookup failed")?;
    let release = if response.status() == StatusCode::NOT_FOUND {
        json_request(
            &client,
            Method::POST,
            &base,
            &json!({"tag_name":tag, "target_commitish":sha,
            "name":format!("Revayat Scientific {tag}"), "draft":true, "prerelease":false, "body":release_body()}),
        )?
    } else {
        decode(response)?
    };
    let id = release["id"]
        .as_u64()
        .context("GitHub release ID missing")?;
    let release_url = format!("{base}/{id}");
    // List every asset, including later pages, before replacing only the same owned names.
    let mut old_assets = Vec::new();
    let mut complete = false;
    for page in 1..=100 {
        let page_value = decode(
            client
                .get(format!("{release_url}/assets?per_page=100&page={page}"))
                .send()?,
        )?;
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
    json_request(&client, Method::PATCH, &release_url, &json!({"draft":true}))?;
    for (name, fingerprint) in uploads {
        for asset in old_assets
            .iter()
            .filter(|asset| asset["name"].as_str() == Some(name.as_str()))
        {
            let asset_id = asset["id"]
                .as_u64()
                .context("GitHub release asset ID missing")?;
            let deleted = client
                .delete(format!("{base}/assets/{asset_id}"))
                .send()?
                .status()
                .is_success();
            ensure!(deleted, "GitHub release asset replacement failed");
        }
        let bytes = crate::resource::bounded_read(
            &dir.join(&name),
            crate::distribution::MAX_PAYLOAD_BYTES as usize,
        )?;
        use sha2::{Digest, Sha256};
        let unchanged = bytes.len() as u64 == fingerprint.size
            && format!("{:x}", Sha256::digest(&bytes)) == fingerprint.sha256;
        ensure!(unchanged, "verified release asset changed before upload");
        let uploaded = decode(
            client
                .post(format!(
                    "https://uploads.github.com/repos/{repo}/releases/{id}/assets"
                ))
                .query(&[("name", &name)])
                .header("Content-Type", "application/octet-stream")
                .body(bytes)
                .send()?,
        )?;
        let matches =
            uploaded["name"].as_str() == Some(name.as_str()) && uploaded["state"] == "uploaded";
        ensure!(matches, "GitHub release upload was not finalized");
    }
    json_request(
        &client,
        Method::PATCH,
        &release_url,
        &json!({"draft":false}),
    )?;
    Ok(())
}
