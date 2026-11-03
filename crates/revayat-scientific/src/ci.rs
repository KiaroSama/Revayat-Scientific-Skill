//! Native CI status reporting. Every result comes from a verified Actions job;
//! missing, cancelled, skipped and failed jobs never become aggregate success.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Read,
    time::Duration,
};

pub const REQUIRED_JOBS: &[&str] = &[
    "security / linux-security",
    "security / windows-security",
    "codeql / analyse",
    "dependency-review / review",
    "portable (ubuntu-latest)",
    "portable (macos-latest)",
    "portable (windows-latest)",
    "scientific",
    "quality",
];
pub const SUMMARY: &str = "ci/manual-summary";
pub const HTTP_TIMEOUT_SECONDS: u64 = 15;
pub fn status_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECONDS))
        .build()?)
}
pub fn decode_response(response: reqwest::blocking::Response) -> Result<Value> {
    ensure!(
        response.status().is_success(),
        "GitHub status API returned HTTP {}",
        response.status().as_u16()
    );
    let mut raw = Vec::new();
    response
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| anyhow::anyhow!("GitHub status API read failed"))?;
    ensure!(
        raw.len() <= 8 * 1024 * 1024,
        "GitHub status API response exceeded 8 MiB"
    );
    let value: Value =
        serde_json::from_slice(&raw).context("GitHub status API response is not UTF-8 JSON")?;
    ensure!(value.is_object(), "GitHub response must be an object");
    Ok(value)
}
pub trait GitHubApi {
    fn get(&mut self, path: &str) -> Result<Value>;
    fn post(&mut self, path: &str, body: &Value) -> Result<Value>;
}
pub struct GitHub {
    client: reqwest::blocking::Client,
    token: String,
}
impl GitHub {
    pub fn new(token: String) -> Result<Self> {
        ensure!(
            !token.is_empty() && !token.chars().any(char::is_whitespace),
            "nonempty GitHub token required"
        );
        Ok(Self {
            client: status_client()?,
            token,
        })
    }
    fn request(&self, path: &str, body: Option<&Value>) -> Result<Value> {
        ensure!(
            path.starts_with("repos/")
                && path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./?=&,()-".contains(&b)),
            "invalid GitHub API path"
        );
        let url = format!("https://api.github.com/{path}");
        let method = if body.is_some() {
            reqwest::Method::POST
        } else {
            reqwest::Method::GET
        };
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("Content-Type", "application/json; charset=utf-8")
            .header("X-GitHub-Api-Version", "2026-03-10")
            .header("User-Agent", "revayat-ci-status");
        if let Some(body) = body {
            request = request.body(serde_json::to_vec(body)?);
        }
        let response = request
            .send()
            .map_err(|_| anyhow::anyhow!("GitHub status API request failed"))?;
        decode_response(response)
    }
}
impl GitHubApi for GitHub {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.request(path, None)
    }
    fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        self.request(path, Some(body))
    }
}
pub fn pages(api: &mut impl GitHubApi, path: &str, field: &str) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    let mut total = None;
    for page in 1..=10 {
        let value = api.get(&format!(
            "{path}{}per_page=100&page={page}",
            if path.contains('?') { '&' } else { '?' }
        ))?;
        let count = value["total_count"]
            .as_u64()
            .context("invalid GitHub result count")?;
        let batch = value[field]
            .as_array()
            .context("GitHub result is not an array")?;
        ensure!(
            count <= 1000
                && batch.len() <= 100
                && batch.iter().all(Value::is_object)
                && total.is_none_or(|n| n == count),
            "inconsistent or excessive GitHub result count"
        );
        total = Some(count);
        result.extend(batch.iter().cloned());
        if result.len() as u64 == count {
            return Ok(result);
        }
        ensure!(
            !batch.is_empty() && (result.len() as u64) < count,
            "incomplete GitHub result pagination"
        );
    }
    bail!("GitHub result pagination exceeded ten pages")
}
pub fn context_for(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name.len() <= 137
            && name.bytes().all(|c| (32..=126).contains(&c))
            && name.trim() == name
            && !name.eq_ignore_ascii_case("manual-summary"),
        "invalid or reserved CI validation job name"
    );
    Ok(format!("ci/{name}"))
}
#[derive(Clone, Debug)]
pub struct ReportingIdentity<'a> {
    pub repository: &'a str,
    pub sha: &'a str,
    pub run_id: u64,
    pub attempt: u64,
}
fn validate_run(api: &mut impl GitHubApi, id: &ReportingIdentity<'_>) -> Result<()> {
    ensure!(
        regex::Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+\z")?.is_match(id.repository)
            && id.sha.len() == 40
            && id
                .sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && id.run_id > 0
            && id.attempt > 0,
        "invalid CI reporting identity"
    );
    let value = api.get(&format!(
        "repos/{}/actions/runs/{}",
        id.repository, id.run_id
    ))?;
    ensure!(
        value["id"].as_u64() == Some(id.run_id)
            && value["head_sha"] == id.sha
            && value["run_attempt"].as_u64() == Some(id.attempt)
            && ["workflow_dispatch", "push", "pull_request"]
                .iter()
                .any(|e| value["event"] == *e)
            && value["path"] == ".github/workflows/ci.yml"
            && value["repository"]["full_name"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(id.repository)),
        "CI run repository, revision, workflow or attempt changed"
    );
    Ok(())
}
pub fn job_results(jobs: &[Value], id: &ReportingIdentity<'_>) -> Result<BTreeMap<String, Value>> {
    let mut latest: HashMap<String, &Value> = HashMap::new();
    let mut ids = HashSet::new();
    let mut generations = HashSet::new();
    for job in jobs {
        let name = job["name"].as_str().context("job name missing")?;
        let context = context_for(name)?;
        let identifier = job["id"].as_u64().context("job id invalid")?;
        let attempt = job["run_attempt"].as_u64().context("job attempt invalid")?;
        ensure!(
            identifier > 0
                && ids.insert(identifier)
                && job["run_id"].as_u64() == Some(id.run_id)
                && job["head_sha"] == id.sha
                && attempt > 0
                && attempt <= id.attempt
                && generations.insert((context.to_lowercase(), attempt))
                && job["html_url"]
                    == format!(
                        "https://github.com/{}/actions/runs/{}/job/{identifier}",
                        id.repository, id.run_id
                    ),
            "CI job identity, context, revision, attempt or link is invalid"
        );
        let key = context.to_lowercase();
        if latest
            .get(&key)
            .is_none_or(|old| old["run_attempt"].as_u64().unwrap_or(0) < attempt)
        {
            latest.insert(key, job);
        }
    }
    let mut results = BTreeMap::new();
    for job in latest.values() {
        let name = job["name"].as_str().unwrap();
        if ["status-pending", "status-final"].contains(&name) {
            continue;
        }
        let conclusion = job["conclusion"].as_str().unwrap_or("unknown");
        let (state, label) = if job["status"] != "completed" {
            ("pending", "not completed")
        } else {
            match conclusion {
                "success" => ("success", "success"),
                "failure" | "timed_out" | "action_required" => ("failure", conclusion),
                "cancelled" | "skipped" | "neutral" | "stale" => ("error", conclusion),
                _ => ("error", "unknown"),
            }
        };
        results.insert(context_for(name)?,json!({"state":state,"target_url":job["html_url"],"description":format!("Run {}, attempt {}: {label}",id.run_id,job["run_attempt"])}));
    }
    Ok(results)
}
fn send(api: &mut impl GitHubApi, path: &str, context: &str, body: Value) -> Result<()> {
    let mut body = body;
    body.as_object_mut()
        .unwrap()
        .insert("context".into(), json!(context));
    api.post(path, &body)?;
    println!(
        "CI status: {context} = {}",
        body["state"].as_str().unwrap_or("error")
    );
    Ok(())
}
pub fn publish(
    api: &mut impl GitHubApi,
    id: &ReportingIdentity<'_>,
    phase: &str,
) -> Result<String> {
    ensure!(
        ["pending", "final"].contains(&phase),
        "invalid CI reporting phase"
    );
    validate_run(api, id)?;
    let url = format!(
        "https://github.com/{}/actions/runs/{}",
        id.repository, id.run_id
    );
    let path = format!("repos/{}/statuses/{}", id.repository, id.sha);
    let attempt = (|| -> Result<String> {
        send(
            api,
            &path,
            SUMMARY,
            json!({"state":"pending","target_url":url,"description":format!("Run {}, attempt {}: publishing job outcomes",id.run_id,id.attempt)}),
        )?;
        let previous = pages(
            api,
            &format!("repos/{}/commits/{}/status", id.repository, id.sha),
            "statuses",
        )?;
        let mut contexts: BTreeMap<String, String> = REQUIRED_JOBS
            .iter()
            .map(|name| {
                let c = context_for(name).unwrap();
                (c.to_lowercase(), c)
            })
            .collect();
        for old in previous {
            let c = old["context"].as_str().unwrap_or("");
            if c.to_lowercase().starts_with("ci/") && !c.eq_ignore_ascii_case(SUMMARY) {
                contexts
                    .entry(c.to_lowercase())
                    .or_insert(context_for(&c[3..])?);
            }
        }
        let mut reporting_failed = false;
        let mut results = if phase == "pending" {
            contexts.values().map(|c|(c.clone(),json!({"state":"pending","target_url":url,"description":format!("Run {}, attempt {}: awaiting CI results",id.run_id,id.attempt)}))).collect()
        } else {
            let jobs = pages(
                api,
                &format!(
                    "repos/{}/actions/runs/{}/jobs?filter=all",
                    id.repository, id.run_id
                ),
                "jobs",
            )?;
            let mut result = job_results(&jobs, id)?;
            let pending = jobs
                .iter()
                .filter(|j| j["name"] == "status-pending")
                .max_by_key(|j| j["run_attempt"].as_u64().unwrap_or(0));
            reporting_failed =
                pending.is_some_and(|j| j["status"] != "completed" || j["conclusion"] != "success");
            let seen: HashSet<_> = result.keys().map(|c| c.to_lowercase()).collect();
            for (key, c) in &contexts {
                if !seen.contains(key) {
                    result.insert(c.clone(),json!({"state":"error","target_url":url,"description":format!("Run {}: job missing from latest results",id.run_id)}));
                }
            }
            result
        };
        validate_run(api, id)?;
        let mut counts: HashMap<String, usize> = HashMap::new();
        for (c, body) in &mut results {
            *counts
                .entry(body["state"].as_str().unwrap().to_owned())
                .or_default() += 1;
            send(api, &path, c, body.clone())?;
        }
        let count = |name: &str| counts.get(name).copied().unwrap_or(0);
        let state = if reporting_failed {
            "error"
        } else {
            ["error", "failure", "pending"]
                .into_iter()
                .find(|s| count(s) > 0)
                .unwrap_or("success")
        };
        send(
            api,
            &path,
            SUMMARY,
            json!({"state":state,"target_url":url,"description":if reporting_failed{"Initial CI status publisher failed; inspect status-pending".into()}else{format!("{} passed, {} failed, {} unavailable, {} pending",count("success"),count("failure"),count("error"),count("pending"))}}),
        )?;
        Ok(state.to_owned())
    })();
    if attempt.is_err() && validate_run(api, id).is_ok() {
        let _ = send(
            api,
            &path,
            SUMMARY,
            json!({"state":"error","target_url":url,"description":"CI status publication failed; inspect reporting job"}),
        );
    }
    attempt
}
pub fn cli_status(args: &[String]) -> Result<i32> {
    ensure!(
        args.len() == 1 && ["pending", "final"].contains(&args[0].as_str()),
        "usage: ci-status pending|final"
    );
    let value = |key| std::env::var(key).unwrap_or_default();
    let repo = value("GITHUB_REPOSITORY");
    let sha = std::env::var("CI_HEAD_SHA").unwrap_or_else(|_| value("GITHUB_SHA"));
    let id = ReportingIdentity {
        repository: &repo,
        sha: &sha,
        run_id: value("GITHUB_RUN_ID").parse()?,
        attempt: value("GITHUB_RUN_ATTEMPT").parse()?,
    };
    let mut api = GitHub::new(value("GH_TOKEN"))?;
    let state = publish(&mut api, &id, &args[0])?;
    Ok(i32::from(args[0] == "final" && state != "success"))
}
