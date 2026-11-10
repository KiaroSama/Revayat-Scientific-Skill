use anyhow::{Result, bail};
use revayat_scientific::ci::{self, GitHubApi, REQUIRED_JOBS, ReportingIdentity, SUMMARY};
use serde_json::{Value, json};
fn id() -> ReportingIdentity<'static> {
    ReportingIdentity {
        repository: "example/project",
        sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        run_id: 123,
        attempt: 1,
    }
}
fn job(name: &str, index: u64, conclusion: &str, attempt: u64) -> Value {
    json!({"id":index,"name":name,"run_id":123,"run_attempt":attempt,"head_sha":id().sha,"status":"completed","conclusion":conclusion,"html_url":format!("https://github.com/example/project/actions/runs/123/job/{index}")})
}
struct Fixture {
    jobs: Vec<Value>,
    previous: Vec<Value>,
    run: Value,
    published: Vec<Value>,
    gets: Vec<String>,
    fail: Option<String>,
    bad_page: Option<Value>,
    supersede: bool,
}
impl Fixture {
    fn new() -> Self {
        Self {
            jobs: REQUIRED_JOBS
                .iter()
                .enumerate()
                .map(|(i, n)| job(n, i as u64 + 1, "success", 1))
                .collect(),
            previous: vec![],
            run: json!({"id":123,"head_sha":id().sha,"run_attempt":1,"event":"workflow_dispatch","path":".github/workflows/ci.yml","repository":{"full_name":"example/project"}}),
            published: vec![],
            gets: vec![],
            fail: None,
            bad_page: None,
            supersede: false,
        }
    }
    fn state(&self, context: &str) -> &Value {
        self.published
            .iter()
            .rev()
            .find(|v| v["context"] == context)
            .unwrap()
    }
}
impl GitHubApi for Fixture {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.gets.push(path.into());
        if path.contains("/jobs?") || path.contains("/status?") {
            if let Some(value) = &self.bad_page
                && path.contains("/jobs?")
            {
                return Ok(value.clone());
            }
            let field = if path.contains("/jobs?") {
                if self.supersede {
                    self.run["run_attempt"] = json!(2);
                }
                "jobs"
            } else {
                "statuses"
            };
            let rows = if field == "jobs" {
                &self.jobs
            } else {
                &self.previous
            };
            let page: usize = path.rsplit("page=").next().unwrap().parse()?;
            let batch: Vec<_> = rows
                .iter()
                .skip((page - 1) * 100)
                .take(100)
                .cloned()
                .collect();
            Ok(json!({"total_count":rows.len(),field:batch}))
        } else {
            Ok(self.run.clone())
        }
    }
    fn post(&mut self, _path: &str, body: &Value) -> Result<Value> {
        if self.fail.as_ref().is_some_and(|c| body["context"] == *c) {
            bail!("controlled boundary failure");
        }
        self.published.push(body.clone());
        Ok(body.clone())
    }
}
#[test]
fn test_required_census_matches_all_existing_matrix_and_reusable_jobs() {
    assert_eq!(REQUIRED_JOBS.len(), 9);
    for expected in [
        "security / linux-security",
        "security / windows-security",
        "codeql / analyse",
        "dependency-review / review",
        "portable (ubuntu-latest)",
        "portable (macos-latest)",
        "portable (windows-latest)",
        "scientific",
        "quality",
    ] {
        assert!(REQUIRED_JOBS.contains(&expected));
    }
}
#[test]
fn test_all_real_jobs_have_their_own_true_result_and_direct_link() -> Result<()> {
    let mut f = Fixture::new();
    f.jobs[0]["conclusion"] = json!("failure");
    f.jobs.push(job("additional validation", 40, "failure", 1));
    f.jobs.push(job("status-final", 41, "", 1));
    f.jobs.push(job("status-pending", 42, "success", 1));
    assert_eq!(ci::publish(&mut f, &id(), "final")?, "failure");
    assert_eq!(f.state("ci/security / linux-security")["state"], "failure");
    assert_eq!(f.state("ci/scientific")["state"], "success");
    assert_eq!(
        f.state("ci/additional validation")["target_url"],
        "https://github.com/example/project/actions/runs/123/job/40"
    );
    assert!(
        f.state(SUMMARY)["description"]
            .as_str()
            .unwrap()
            .contains("8 passed, 2 failed")
    );
    assert!(
        !f.published
            .iter()
            .any(|v| v["context"] == "ci/status-final")
    );
    Ok(())
}
#[test]
fn test_pending_resets_expected_and_old_contexts_without_claiming_results() -> Result<()> {
    let mut f = Fixture::new();
    f.previous = vec![
        json!({"context":"ci/retired"}),
        json!({"context":"external/check"}),
    ];
    assert_eq!(ci::publish(&mut f, &id(), "pending")?, "pending");
    assert_eq!(f.state("ci/retired")["state"], "pending");
    assert!(f.published.iter().all(|v| v["state"] == "pending"));
    assert!(!f.published.iter().any(|v| v["context"] == "external/check"));
    Ok(())
}
#[test]
fn test_preparation_is_opt_in_bounded_and_publishes_only_generated_inputs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let source = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let workflow: Value = serde_saphyr::from_str(&source).unwrap();
    let events = workflow["on"].as_object().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events["workflow_dispatch"]["inputs"]["prepare_artifacts"]["default"], false);
    let jobs = workflow["jobs"].as_object().unwrap();
    for (name, job) in jobs {
        let gate = match name.as_str() {
            "prepare-artifacts" => "${{ inputs.prepare_artifacts }}",
            "status-final" => "${{ always() && !inputs.prepare_artifacts }}",
            _ => "${{ !inputs.prepare_artifacts }}",
        };
        assert_eq!(job["if"], gate, "{name}");
    }
    let prepare = &jobs["prepare-artifacts"];
    assert_eq!(prepare["runs-on"], "ubuntu-latest");
    assert_eq!(prepare["timeout-minutes"], 40);
    let steps = prepare["steps"].as_array().unwrap();
    let commands: Vec<_> = steps.iter().filter_map(|step| step["run"].as_str()).collect();
    assert_eq!(commands, [
        "cargo update --workspace", "cargo update --workspace --locked", "cargo fetch --locked",
        "cargo build --locked -p revayat-scientific --bin license-notices --bin revayat-process-owner",
        "cargo run --locked --bin license-notices -- --root .",
        "cargo run --locked --bin license-notices -- --root . --check", "cargo update --workspace --locked",
    ]);
    for step in steps.iter().filter(|step| step["run"].is_string()) {
        assert!(step["timeout-minutes"].as_u64().is_some_and(|minutes| minutes <= 20));
    }
    assert!(steps.iter().any(|step| step["with"]["toolchain"] == "1.99.1" && step["with"]["components"] == "rust-docs" && step["with"]["cache"] == false));
    let artifacts: Vec<_> = steps.iter().filter(|step| step["uses"].as_str().is_some_and(|name| name.starts_with("actions/upload-artifact@"))).collect();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0]["with"]["path"], "Cargo.lock\nskills/revayat-scientific/references/third-party-licenses.txt\n");
    assert_eq!(artifacts[0]["with"]["if-no-files-found"], "error");
    assert!(artifacts[0].get("if").is_none());
}

#[test]
fn test_only_completed_skipped_preparation_is_excluded_from_full_validation() -> Result<()> {
    let mut normal = Fixture::new();
    normal.jobs.push(job("prepare-artifacts", 80, "skipped", 1));
    assert_eq!(ci::publish(&mut normal, &id(), "final")?, "success");
    assert!(
        !normal
            .published
            .iter()
            .any(|value| value["context"] == "ci/prepare-artifacts")
    );
    for conclusion in [
        "success",
        "failure",
        "cancelled",
        "timed_out",
        "neutral",
        "",
        "unknown",
    ] {
        let mut fixture = Fixture::new();
        fixture
            .jobs
            .push(job("prepare-artifacts", 80, conclusion, 1));
        assert!(ci::publish(&mut fixture, &id(), "final").is_err());
        assert!(
            !fixture
                .published
                .iter()
                .any(|value| value["state"] == "success")
        );
    }
    for status in ["queued", "in_progress", "waiting", "unknown"] {
        let mut fixture = Fixture::new();
        let mut preparation = job("prepare-artifacts", 80, "skipped", 1);
        preparation["status"] = json!(status);
        fixture.jobs.push(preparation);
        assert!(ci::publish(&mut fixture, &id(), "final").is_err());
    }
    let mut required = Fixture::new();
    required.jobs[0]["conclusion"] = json!("skipped");
    required
        .jobs
        .push(job("prepare-artifacts", 80, "skipped", 1));
    assert_eq!(ci::publish(&mut required, &id(), "final")?, "error");
    Ok(())
}

#[test]
fn test_every_non_success_conclusion_stays_non_green() -> Result<()> {
    for (conclusion, expected) in [
        ("failure", "failure"),
        ("timed_out", "failure"),
        ("action_required", "failure"),
        ("cancelled", "error"),
        ("skipped", "error"),
        ("neutral", "error"),
        ("stale", "error"),
        ("unexpected", "error"),
        ("", "error"),
    ] {
        let mut f = Fixture::new();
        f.jobs[0]["conclusion"] = json!(conclusion);
        assert_ne!(ci::publish(&mut f, &id(), "final")?, "success");
        assert_eq!(f.state("ci/security / linux-security")["state"], expected);
    }
    let mut f = Fixture::new();
    f.jobs[0]["status"] = json!("in_progress");
    assert_eq!(ci::publish(&mut f, &id(), "final")?, "pending");
    Ok(())
}
#[test]
fn test_missing_and_retired_jobs_are_explicit_errors() -> Result<()> {
    let mut f = Fixture::new();
    f.previous.push(json!({"context":"ci/retired"}));
    f.jobs.remove(0);
    assert_eq!(ci::publish(&mut f, &id(), "final")?, "error");
    assert_eq!(f.state("ci/retired")["state"], "error");
    assert_eq!(f.state("ci/security / linux-security")["state"], "error");
    Ok(())
}
#[test]
fn test_complete_pagination_and_partial_rerun_successes_are_retained() -> Result<()> {
    let mut f = Fixture::new();
    f.run["run_attempt"] = json!(2);
    for index in 0..105 {
        f.jobs.push(job(
            &format!("validation {index}"),
            index + 100,
            "success",
            2,
        ));
    }
    let mut identity = id();
    identity.attempt = 2;
    assert_eq!(ci::publish(&mut f, &identity, "final")?, "success");
    assert_eq!(f.state("ci/validation 104")["state"], "success");
    assert_eq!(f.gets.iter().filter(|p| p.contains("/jobs?")).count(), 2);
    assert!(
        f.gets
            .iter()
            .filter(|p| p.contains("/jobs?"))
            .all(|p| p.contains("filter=all"))
    );
    Ok(())
}
#[test]
fn test_rerun_replaces_only_jobs_with_a_newer_actual_result() -> Result<()> {
    let mut f = Fixture::new();
    f.run["run_attempt"] = json!(2);
    f.jobs[0]["conclusion"] = json!("failure");
    f.jobs.extend([
        job("security / linux-security", 60, "success", 2),
        job("quality", 61, "failure", 2),
    ]);
    let mut identity = id();
    identity.attempt = 2;
    assert_eq!(ci::publish(&mut f, &identity, "final")?, "failure");
    assert_eq!(f.state("ci/security / linux-security")["state"], "success");
    assert_eq!(f.state("ci/quality")["state"], "failure");
    assert!(
        f.state("ci/scientific")["description"]
            .as_str()
            .unwrap()
            .contains("attempt 1")
    );
    Ok(())
}
#[test]
fn test_only_latest_pending_publisher_outcome_affects_summary() -> Result<()> {
    let mut f = Fixture::new();
    f.run["run_attempt"] = json!(2);
    f.jobs.extend([
        job("status-pending", 60, "failure", 1),
        job("status-pending", 61, "success", 2),
    ]);
    let mut identity = id();
    identity.attempt = 2;
    assert_eq!(ci::publish(&mut f, &identity, "final")?, "success");
    f.jobs.last_mut().unwrap()["conclusion"] = json!("failure");
    assert_eq!(ci::publish(&mut f, &identity, "final")?, "error");
    Ok(())
}
#[test]
fn test_wrong_run_revision_attempt_event_repository_or_workflow_never_publishes() {
    for (key, value) in [
        ("id", json!(124)),
        (
            "head_sha",
            json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ),
        ("run_attempt", json!(2)),
        ("event", json!("workflow_run")),
        ("path", json!(".github/workflows/other.yml")),
        ("repository", json!({"full_name":"another/project"})),
    ] {
        let mut f = Fixture::new();
        f.run[key] = value;
        assert!(ci::publish(&mut f, &id(), "final").is_err());
        assert!(f.published.is_empty());
    }
}
#[test]
fn test_bad_job_identity_urls_and_context_collisions_fail_without_green() {
    for change in [
        json!({"run_id":999}),
        json!({"head_sha":"b"}),
        json!({"run_attempt":2}),
        json!({"html_url":"https://outside.invalid/job/1"}),
        json!({"name":"manual-summary"}),
        json!({"name":"unsafe\nlabel"}),
        json!({"id":0}),
    ] {
        let mut f = Fixture::new();
        for (key, value) in change.as_object().unwrap() {
            f.jobs[0][key] = value.clone();
        }
        assert!(ci::publish(&mut f, &id(), "final").is_err());
        assert!(!f.published.iter().any(|v| v["state"] == "success"));
    }
    let mut f = Fixture::new();
    f.jobs.push(job("SCIENTIFIC", 99, "success", 1));
    assert!(ci::publish(&mut f, &id(), "final").is_err());
}
#[test]
fn test_inconsistent_or_unbounded_pages_are_rejected() {
    for bad in [
        json!({"total_count":1001,"jobs":[]}),
        json!({"total_count":2,"jobs":[]}),
        json!({"total_count":1,"jobs":[job("one",1,"success",1),job("two",2,"success",1)]}),
    ] {
        let mut f = Fixture::new();
        f.bad_page = Some(bad);
        assert!(ci::publish(&mut f, &id(), "final").is_err());
        assert!(!f.published.iter().any(|v| v["state"] == "success"));
    }
}
#[test]
fn test_superseded_attempt_never_overwrites_new_results_with_failure() {
    let mut f = Fixture::new();
    f.supersede = true;
    assert!(ci::publish(&mut f, &id(), "final").is_err());
    assert_eq!(f.published.len(), 1);
    assert_eq!(f.published[0]["state"], "pending");
}
#[test]
fn test_partial_write_failure_leaves_aggregate_error_and_propagates() {
    let mut f = Fixture::new();
    f.fail = Some("ci/scientific".into());
    assert!(ci::publish(&mut f, &id(), "final").is_err());
    assert_eq!(f.state(SUMMARY)["state"], "error");
    assert_eq!(f.published[0]["state"], "pending");
}
fn http_fixture(
    code: &str,
    extra: &str,
    body: Vec<u8>,
) -> (String, std::thread::JoinHandle<Vec<u8>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let header = format!(
        "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    );
    let thread = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|b| b == b"\r\n\r\n") {
            let n = connection.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..n]);
            assert!(request.len() <= 8192);
        }
        connection.write_all(header.as_bytes()).unwrap();
        let _ = connection.write_all(&body);
        request
    });
    (url, thread)
}
#[test]
fn test_http_timeout_cap_utf8_and_secret_safe_errors() {
    assert!(ci::GitHub::new(String::new()).is_err());
    assert!(ci::GitHub::new("private token".into()).is_err());
    let mut api = ci::GitHub::new("private-test-token".into()).unwrap();
    let error = api
        .get("https://private-test-token.invalid")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("private-test-token"));
    assert!(error.contains("invalid GitHub API path"));
    assert_eq!(ci::HTTP_TIMEOUT_SECONDS, 15);
    for (code, body, expected) in [
        ("200 OK", b"{\"ok\":true}".to_vec(), None),
        ("200 OK", vec![255], Some("UTF-8 JSON")),
        (
            "200 OK",
            vec![b'x'; 8 * 1024 * 1024 + 1],
            Some("exceeded 8 MiB"),
        ),
        (
            "403 Forbidden",
            b"secret response private-test-token".to_vec(),
            Some("HTTP 403"),
        ),
    ] {
        let (url, server) = http_fixture(code, "", body);
        let response = ci::status_client().unwrap().get(url).send().unwrap();
        let result = ci::decode_response(response);
        server.join().unwrap();
        if let Some(expected) = expected {
            let error = result.unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("private-test-token"));
            assert!(!error.contains("secret response"));
        } else {
            assert_eq!(result.unwrap(), json!({"ok":true}));
        }
    }
}
#[test]
fn test_redirects_never_forward_credentials() {
    let mut api = ci::GitHub::new("private-test-token".into()).unwrap();
    for path in [
        "//outside.invalid",
        "repos/x/y\r\nAuthorization: secret",
        "repos/x/y#outside",
    ] {
        assert!(api.get(path).is_err());
    }
    let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let location = format!(
        "Location: http://{}/credential-leak\r\n",
        destination.local_addr().unwrap()
    );
    let (url, server) = http_fixture("302 Found", &location, Vec::new());
    let response = ci::status_client()
        .unwrap()
        .get(url)
        .bearer_auth("private-test-token")
        .send()
        .unwrap();
    assert_eq!(response.status().as_u16(), 302);
    assert!(ci::decode_response(response).is_err());
    let request = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer private-test-token")
    );
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn test_workflow_retains_manual_trigger_and_complete_final_dependency_set() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let source = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    assert!(source.contains("  workflow_dispatch:"));
    assert!(source.contains("  pull_request:"));
    assert!(source.contains("  push:"));
    let workflow: Value = serde_saphyr::from_str(&source).unwrap();
    assert!(workflow["on"].get("push").is_some());
    assert!(
        workflow["on"]["push"].is_null(),
        "all branch pushes must trigger CI without a branch filter"
    );
    assert!(source.contains("github.event.pull_request.head.repo.full_name || github.repository"));
    assert!(source.contains("github.head_ref || github.ref_name"));
    assert!(source.contains("git merge-base -- \"origin/$DEFAULT_BRANCH\" \"$HEAD_REF\""));
    let final_job = source.split("  status-final:\n").nth(1).unwrap();
    assert!(final_job.contains("always()"));
    for dependency in [
        "status-pending",
        "security",
        "codeql",
        "dependency-review",
        "portable",
        "scientific",
        "quality",
    ] {
        assert!(final_job.contains(dependency));
    }
    assert!(!final_job.contains("continue-on-error"));
    assert!(final_job.contains("ci-status final"));
}
