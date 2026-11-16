//! Local-only, immutable-image XeTeX sandbox with verified ownership cleanup.
use crate::{
    build::{BuildGuard, file_hash},
    identity::is_link,
    publication::{publish_files, validate_destination},
    runtime::{self, CommandSpec},
};
use anyhow::{Context, Result, ensure};
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "tex_execution.rs"]
mod execution;
#[path = "tex_finalize.rs"]
pub(crate) mod finalize;
pub use execution::{
    IsolatedRendererFailure, TexBoundary, compile_document, compile_document_observed,
    compile_document_with_lifecycle, compile_document_with_recovery, execute_prepared_job,
};
#[path = "tex_config.rs"]
mod config;
pub use config::{runtime_config, runtime_config_with};

pub const DEFAULT_IMAGE: &str = "revayat-scientific-tex:1";
pub const IMAGE_LABEL: &str = "org.revayat.tex.toolchain";
pub const RUN_LABEL: &str = "org.revayat.tex.run";
pub const INNER_TIMEOUT: u64 = 120;
pub const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_INPUT_FILES: usize = 512;
pub const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
pub const OUTPUT_CHUNK_BYTES: u64 = 1024 * 1024;
pub const OUTPUT_FILES: &[&str] = &["document.pdf", "console-pass-1.log", "console-pass-2.log"];
const OUTPUT_NAMES: &[&str] = &[
    "document.pdf",
    "console-pass-1.log",
    "console-pass-2.log",
    "sandbox-verified.json",
    "probe.txt",
    "public-one.txt",
    "public-two.txt",
];
pub const STAGED_MAIN: &str = ".revayat-main.tex";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub base: Vec<String>,
    pub kind: String,
    pub image: String,
}

pub fn validate_endpoint(endpoint: &str, kind: &str) -> Result<()> {
    let local_unix =
        endpoint.starts_with("unix:///") && !endpoint.contains(['\r', '\n', '\0', '?', '#']);
    let local_pipe =
        kind == "docker" && Regex::new(r"^npipe:////\./pipe/[A-Za-z0-9_.-]+$")?.is_match(endpoint);
    let local_podman=kind=="podman" && Regex::new(r"^ssh://(?:[A-Za-z0-9_.-]+@)?(?:127\.0\.0\.1|localhost|\[::1\])(?::[0-9]+)?/[^\r\n\x00?#]+$")?.is_match(endpoint);
    ensure!(
        local_unix || local_pipe || local_podman,
        "only a local container endpoint is allowed; remote jobs are forbidden"
    );
    Ok(())
}

pub fn call(arguments: &[String], timeout: u64) -> Result<(i32, String)> {
    call_with_environment(arguments, timeout, &[])
}
pub fn call_with_environment(
    arguments: &[String],
    timeout: u64,
    environment: &[(&str, &str)],
) -> Result<(i32, String)> {
    let mut spec = CommandSpec::new(arguments.first().context("empty runtime command")?);
    spec.args = arguments[1..].iter().map(OsString::from).collect();
    spec.timeout = Duration::from_secs(timeout);
    spec.max_output = 2 * 1024 * 1024;
    for name in [
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
    ] {
        spec.env.insert(name.into(), "".into());
    }
    spec.env.extend(
        environment
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into())),
    );
    let output = runtime::run(&spec)?;
    let text = String::from_utf8(output.stdout)
        .context("container runtime returned invalid structured output")?;
    Ok((output.code, text))
}
fn append(base: &[String], args: &[&str]) -> Vec<String> {
    base.iter()
        .cloned()
        .chain(args.iter().map(|s| s.to_string()))
        .collect()
}
fn hash_id(value: &str, prefix: bool) -> bool {
    let value = if prefix {
        value.strip_prefix("sha256:").unwrap_or(value)
    } else {
        value
    };
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Fail early on a daemon which explicitly cannot apply the requested resource
/// limits. A supported driver is necessary; the native enforcement probe must
/// still observe the real cgroup controls inside the production boundary.
pub fn validate_runtime_information(information: &Value, kind: &str) -> Result<()> {
    let os = if kind == "docker" {
        &information["OSType"]
    } else {
        &information["host"]["os"]
    };
    ensure!(
        os == "linux",
        "the container runtime must use Linux containers"
    );
    let driver = if kind == "docker" {
        information["CgroupDriver"].as_str()
    } else {
        information["host"]["cgroupManager"].as_str()
    }
    .unwrap_or("");
    ensure!(
        driver == "systemd" || driver == "cgroupfs",
        "container daemon has no supported cgroup driver; requested memory, PID and CPU limits cannot be trusted"
    );
    if kind == "podman" {
        ensure!(
            information["host"]["security"]["rootless"] != true
                || information["host"]["cgroupVersion"] != "v1",
            "rootless Podman cgroup v1 cannot enforce required delegated resource limits"
        );
        if let Some(controllers) = information["host"]["cgroupControllers"].as_array() {
            for controller in ["cpu", "memory", "pids"] {
                ensure!(
                    controllers.iter().any(|item| item == controller),
                    "Podman is missing required delegated {controller} controller"
                );
            }
        }
    }
    Ok(())
}

pub fn approved_files(source: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let source = source.canonicalize()?;
    ensure!(
        source
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("tex")),
        "isolated TeX requires .tex source"
    );
    let root = source.parent().context("source root unavailable")?;
    let model = crate::source::TexSource::load(&source)?;
    let mut approved = model
        .closure
        .sources
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for (_, reference) in model.image_references() {
        let asset = crate::build::resolve_asset(&source, &reference)?;
        ensure!(
            ["pdf", "png", "jpg", "jpeg"].iter().any(|e| asset
                .extension()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(e))),
            "container graphics must be PDF, PNG or JPEG"
        );
        approved.insert(asset);
    }
    let fonts = root.join("fonts");
    if fonts.try_exists()? {
        ensure!(
            !is_link(&fonts)? && fonts.is_dir(),
            "local font directory must not be linked"
        );
        for entry in fs::read_dir(fonts)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("ttf") || e.eq_ignore_ascii_case("otf"))
            {
                approved.insert(path);
            }
        }
    }
    let mut result = vec![];
    let mut size = 0u64;
    for path in approved {
        for ancestor in path.ancestors() {
            ensure!(
                !is_link(ancestor)?,
                "approved input paths must not contain links"
            );
            if ancestor == root {
                break;
            }
        }
        let resolved = path.canonicalize()?;
        ensure!(
            resolved.starts_with(root) && resolved.is_file(),
            "approved asset leaves approved job root"
        );
        let relative = resolved.strip_prefix(root)?.to_path_buf();
        ensure!(
            !relative.to_string_lossy().contains(['\0', '\r', '\n']),
            "invalid document path"
        );
        size = size
            .checked_add(fs::metadata(&resolved)?.len())
            .context("input size overflow")?;
        ensure!(
            size <= MAX_INPUT_BYTES && result.len() < MAX_INPUT_FILES,
            "approved TeX input set exceeds size limit"
        );
        result.push((resolved, relative));
    }
    Ok(result)
}

pub fn mount_argument(source: &Path, target: &str, readonly: bool) -> Result<String> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(vec![]);
    let mut values = vec![
        "type=bind".into(),
        format!("src={}", std::path::absolute(source)?.display()),
        format!("dst={target}"),
    ];
    if readonly {
        values.push("readonly".into());
    }
    writer.write_record(values)?;
    let bytes = writer.into_inner()?;
    Ok(String::from_utf8(bytes)?.trim_end_matches('\n').to_owned())
}
pub fn run_arguments(
    config: &RuntimeConfig,
    directory: &Path,
    source_name: &str,
    run_id: &str,
) -> Result<Vec<String>> {
    ensure!(
        crate::tex_supervisor::valid_token(run_id),
        "invalid run identity"
    );
    ensure!(
        !source_name.contains(['/', '\\', '\0', '\r', '\n']),
        "source must be a basename"
    );
    let mut command = append(
        &config.base,
        &[
            "run",
            "--rm",
            "--detach",
            "--pull=never",
            "--name",
            &format!("revayat-tex-{run_id}"),
            "--label",
            &format!("{RUN_LABEL}={run_id}"),
            "--cidfile",
            directory
                .join("container.cid")
                .to_str()
                .context("staging path UTF-8")?,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=64",
            "--memory=1g",
            "--memory-swap=1g",
            "--cpus=2",
            "--ulimit",
            "fsize=268435456:268435456",
            "--ulimit",
            "nofile=128:128",
            "--log-driver=none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=268435456",
            "--tmpfs",
            "/output:rw,noexec,nosuid,nodev,size=268435456",
            "--workdir=/input",
            "--mount",
            &mount_argument(&directory.join("input"), "/input", true)?,
            "--env",
            "HOME=/tmp/tex-home",
            "--env",
            "TEXMFVAR=/tmp/tex-var",
            "--env",
            "TEXMFCONFIG=/tmp/tex-config",
            "--env",
            "TEXMFOUTPUT=/output",
            "--entrypoint=/usr/bin/timeout",
        ],
    );
    #[cfg(target_os = "linux")]
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    #[cfg(not(target_os = "linux"))]
    let (uid, gid) = (65532u32, 65532u32);
    if config.kind == "podman" && cfg!(target_os = "linux") && uid != 0 {
        command.push("--userns=keep-id".into());
    }
    command.extend([
        "--user".into(),
        format!(
            "{}:{}",
            if uid == 0 { 65532 } else { uid },
            if gid == 0 { 65532 } else { gid }
        ),
        config.image.clone(),
        "--signal=TERM".into(),
        "--kill-after=5s".into(),
        format!("{}s", INNER_TIMEOUT + 30),
        "/usr/local/bin/revayat-tex-entry".into(),
        "--hold".into(),
    ]);
    Ok(command)
}

/// A CID receipt is not authority until the daemon confirms its name and label.
/// Use this before any exec/copy as well as during owned cleanup.
pub fn verified_container_with(
    config: &RuntimeConfig,
    directory: &Path,
    run_id: &str,
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
) -> Result<String> {
    ensure!(
        crate::tex_supervisor::valid_token(run_id),
        "invalid run identity"
    );
    let receipt = directory.join("container.cid");
    ensure!(
        !is_link(&receipt)? && fs::metadata(&receipt)?.len() <= 128,
        "invalid owned-container receipt"
    );
    let identifier = fs::read_to_string(receipt)?.trim().to_owned();
    ensure!(
        hash_id(&identifier, false),
        "invalid owned-container receipt"
    );
    let (code, text) = execute(&append(&config.base, &["inspect", &identifier]), 15)?;
    ensure!(code == 0, "container inspection failed");
    let records: Value = serde_json::from_str(&text)?;
    let records = records.as_array().context("invalid container inspection")?;
    ensure!(records.len() == 1, "ambiguous owned container inspection");
    let record = &records[0];
    ensure!(
        record["Config"]["Labels"][RUN_LABEL] == run_id
            && record["Name"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches('/')
                == format!("revayat-tex-{run_id}")
            && record["Id"].as_str().or_else(|| record["ID"].as_str()) == Some(identifier.as_str()),
        "refusing access without matching ownership"
    );
    Ok(identifier)
}

/// The detached holder keeps the quota-backed tmpfs alive. Only this synchronous
/// trusted exec runs the compiler; its return is the completion receipt, never a
/// marker writable by TeX.
pub fn entry_arguments(
    config: &RuntimeConfig,
    identifier: &str,
    args: &[&str],
) -> Result<Vec<String>> {
    ensure!(
        hash_id(identifier, false),
        "invalid owned-container identity"
    );
    let mut command = append(
        &config.base,
        &[
            "exec",
            identifier,
            "/usr/bin/timeout",
            "--signal=TERM",
            "--kill-after=5s",
        ],
    );
    command.push(format!("{INNER_TIMEOUT}s"));
    command.push("/usr/local/bin/revayat-tex-entry".into());
    command.extend(args.iter().map(|argument| (*argument).to_owned()));
    Ok(command)
}

fn execute_prepared_with(
    config: &RuntimeConfig,
    directory: &Path,
    run_id: &str,
    entry_args: &[&str],
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
) -> Result<(i32, String)> {
    let started = Instant::now();
    let limit = Duration::from_secs(INNER_TIMEOUT + 30);
    let mut bounded = |args: &[String], seconds: u64| -> Result<(i32, String)> {
        let remaining = limit.saturating_sub(started.elapsed()).as_secs();
        if remaining == 0 {
            return Err(runtime::DeadlineExceeded { idle: false, limit }.into());
        }
        execute(args, seconds.min(remaining))
    };
    let arguments = run_arguments(config, directory, STAGED_MAIN, run_id)?;
    let (code, _) = bounded(&arguments, INNER_TIMEOUT + 30)?;
    ensure!(
        code == 0,
        "isolated container launch failed (exit_code={code})"
    );
    let identifier = verified_container_with(config, directory, run_id, &mut bounded)?;
    let result = bounded(
        &entry_arguments(config, &identifier, entry_args)?,
        INNER_TIMEOUT + 10,
    )?;
    // GNU timeout's own expiry can precede the outer owned-process deadline.
    // Retain its operational category instead of treating an interrupted
    // readiness command as an optional engine which is simply absent.
    if matches!(result.0, 124 | 137) {
        return Err(runtime::DeadlineExceeded {
            idle: false,
            limit: Duration::from_secs(INNER_TIMEOUT),
        }
        .into());
    }
    if entry_args == ["--engine-info", "weasyprint"] {
        return Ok(result);
    }
    // The compiler exec has returned. No TeX-writable completion marker exists.
    copy_outputs_with(config, directory, run_id, OUTPUT_FILES, &mut bounded)?;
    if result.0 == 0 {
        let pdf = directory.join("output/document.pdf");
        ensure!(
            pdf.is_file() && !is_link(&pdf)? && fs::metadata(&pdf)?.len() > 0,
            "isolated renderer omitted its admitted PDF"
        );
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputFile {
    name: String,
    size: u64,
    sha256: String,
}

/// Extract only individually admitted regular artifacts after the renderer has
/// exited. No writable host filesystem is mounted in the untrusted boundary.
pub fn copy_outputs_with(
    config: &RuntimeConfig,
    directory: &Path,
    run_id: &str,
    names: &[&str],
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
) -> Result<()> {
    ensure!(
        names.len() <= MAX_INPUT_FILES,
        "output inventory exceeds bound"
    );
    ensure!(
        names.iter().all(|name| OUTPUT_NAMES.contains(name)),
        "invalid output artifact name"
    );
    let identifier = verified_container_with(config, directory, run_id, execute)?;
    let mut request = vec!["--output-manifest"];
    request.extend_from_slice(names);
    let (code, text) = execute(&entry_arguments(config, &identifier, &request)?, 15)?;
    ensure!(code == 0, "container output admission failed");
    let manifest: Vec<OutputFile> =
        serde_json::from_str(&text).context("invalid bounded output manifest")?;
    ensure!(manifest.len() <= names.len(), "unexpected output inventory");
    let mut seen = BTreeSet::new();
    let mut aggregate = 0u64;
    for file in &manifest {
        ensure!(
            names.contains(&file.name.as_str()) && seen.insert(&file.name),
            "unexpected or duplicate output artifact"
        );
        ensure!(
            hash_id(&file.sha256, false),
            "invalid output artifact digest"
        );
        aggregate = aggregate
            .checked_add(file.size)
            .context("output size overflow")?;
        ensure!(
            aggregate <= MAX_OUTPUT_BYTES,
            "container output exceeds aggregate delivery budget"
        );
    }
    let outgoing = directory.join("output");
    ensure!(
        outgoing.is_dir() && !is_link(&outgoing)?,
        "invalid output delivery directory"
    );
    for file in manifest {
        let destination = outgoing.join(&file.name);
        ensure!(
            !destination.try_exists()? && !is_link(&destination)?,
            "output delivery target already exists"
        );
        // Docker's archive/cp API cannot see a container's tmpfs mount. Read
        // bounded chunks from inside its live mount namespace instead; each
        // encoded result remains below the unchanged 2MiB diagnostic limit.
        use std::io::Write;
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        let mut offset = 0;
        while offset < file.size {
            let count = OUTPUT_CHUNK_BYTES.min(file.size - offset);
            let (offset_text, count_text) = (offset.to_string(), count.to_string());
            let request = entry_arguments(
                config,
                &identifier,
                &["--read-output", &file.name, &offset_text, &count_text],
            )?;
            let (code, text) = execute(&request, 30)?;
            ensure!(
                code == 0 && text.len() as u64 == count.div_ceil(3) * 4,
                "bounded container output read failed"
            );
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .context("invalid bounded output encoding")?;
            ensure!(
                bytes.len() as u64 == count,
                "container output chunk differs from admitted length"
            );
            writer.write_all(&bytes)?;
            offset += count;
        }
        writer.sync_all()?;
        drop(writer);
        let metadata = fs::symlink_metadata(&destination)?;
        ensure!(
            metadata.file_type().is_file()
                && !is_link(&destination)?
                && metadata.len() == file.size,
            "container output copy differs from admitted regular artifact"
        );
        ensure!(
            file_hash(&destination)? == file.sha256,
            "container output differs from admitted digest"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(metadata.nlink() == 1, "container output copy is linked");
        }
    }
    Ok(())
}

pub fn cleanup(
    config: &RuntimeConfig,
    directory: &Path,
    run_id: &str,
    require_receipt: bool,
) -> Result<()> {
    cleanup_with(
        config,
        directory,
        run_id,
        require_receipt,
        &mut |args, _| call(args, 15),
    )
}
pub fn cleanup_with(
    config: &RuntimeConfig,
    directory: &Path,
    run_id: &str,
    require_receipt: bool,
    execute: &mut impl FnMut(&[String], u64) -> Result<(i32, String)>,
) -> Result<()> {
    let listing = append(
        &config.base,
        &[
            "ps",
            "-a",
            "--filter",
            &format!("label={RUN_LABEL}={run_id}"),
            "--no-trunc",
            "--format",
            "{{.ID}}",
        ],
    );
    let (code, text) = execute(&listing, 15)?;
    ensure!(code == 0, "cannot verify owned container cleanup");
    let identifiers = text.split_whitespace().collect::<Vec<_>>();
    let cid = directory.join("container.cid");
    ensure!(!is_link(&cid)?, "container receipt is linked");
    let expected = if cid.try_exists()? {
        ensure!(
            fs::metadata(&cid)?.len() <= 128,
            "invalid owned-container receipt"
        );
        Some(fs::read_to_string(cid)?.trim().to_owned())
    } else {
        None
    };
    ensure!(
        !require_receipt || expected.is_some() || !identifiers.is_empty(),
        "container launch outcome unknown; ownership evidence retained"
    );
    if let Some(expected) = &expected {
        ensure!(hash_id(expected, false), "invalid owned-container receipt");
        if !identifiers.contains(&expected.as_str()) {
            let (code, all) = execute(
                &append(
                    &config.base,
                    &["ps", "-a", "--no-trunc", "--format", "{{.ID}}"],
                ),
                15,
            )?;
            ensure!(
                code == 0 && !all.split_whitespace().any(|id| id == expected),
                "CID container cannot be verified through ownership label"
            );
        }
    }
    for identifier in identifiers {
        ensure!(
            hash_id(identifier, false) && expected.as_ref().is_none_or(|id| id == identifier),
            "owned container identity mismatch"
        );
        let (code, text) = execute(&append(&config.base, &["inspect", identifier]), 15)?;
        ensure!(code == 0, "container inspection failed");
        let records: Value = serde_json::from_str(&text)?;
        let record = &records[0];
        ensure!(
            record["Config"]["Labels"][RUN_LABEL] == run_id
                && record["Name"]
                    .as_str()
                    .unwrap_or("")
                    .trim_start_matches('/')
                    == format!("revayat-tex-{run_id}")
                && record["Id"].as_str().or_else(|| record["ID"].as_str()) == Some(identifier),
            "refusing removal without matching ownership"
        );
        ensure!(
            execute(&append(&config.base, &["rm", "--force", identifier]), 15)?.0 == 0,
            "owned container removal failed"
        );
    }
    let (code, remaining) = execute(&listing, 15)?;
    ensure!(
        code == 0 && remaining.trim().is_empty(),
        "owned container cleanup could not be confirmed"
    );
    Ok(())
}

pub fn failure_class(outgoing: &Path) -> Result<&'static str> {
    let categories = [
        ("undefined control sequence", "undefined-control-sequence"),
        ("fontspec error", "font-unavailable"),
        ("not found", "missing-resource-or-package"),
        ("i can't find file", "missing-resource-or-package"),
        ("missing $ inserted", "math-syntax"),
        ("package xepersian error", "xepersian-package"),
        ("cannot write", "output-permission"),
        ("tex capacity exceeded", "tex-capacity"),
    ];
    for name in ["console-pass-2.log", "console-pass-1.log"] {
        let path = outgoing.join(name);
        if is_link(&path)? || !path.is_file() {
            continue;
        }
        let mut file = fs::File::open(path)?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(
            file.metadata()?.len().saturating_sub(128 * 1024),
        ))?;
        let mut bytes = vec![];
        file.take(128 * 1024).read_to_end(&mut bytes)?;
        let text = String::from_utf8_lossy(&bytes).to_lowercase();
        for (marker, category) in categories {
            if text.contains(marker) {
                return Ok(category);
            }
        }
    }
    Ok("unclassified")
}
/// Raw console tails are opt-in evidence for generated repository fixtures.
/// Ordinary manuscripts only expose the bounded error category above.
pub fn retain_fixture_console(
    source: &Path,
    outgoing: &Path,
    run_id: &str,
    evidence: Option<&Path>,
    fixture_mode: bool,
) -> Result<()> {
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.scratch");
    let Ok(scratch) = scratch.canonicalize() else {
        return Ok(());
    };
    if !fixture_mode || !source.canonicalize()?.starts_with(scratch) {
        return Ok(());
    }
    let Some(evidence) = evidence else {
        return Ok(());
    };
    ensure!(
        evidence.is_dir(),
        "scientific fixture evidence directory missing"
    );
    ensure!(
        crate::tex_supervisor::valid_token(run_id),
        "invalid fixture run identity"
    );
    for name in ["console-pass-1.log", "console-pass-2.log"] {
        let path = outgoing.join(name);
        if is_link(&path)? || !path.is_file() {
            continue;
        }
        let mut file = fs::File::open(&path)?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(
            file.metadata()?.len().saturating_sub(256 * 1024),
        ))?;
        let mut bytes = vec![];
        file.take(256 * 1024).read_to_end(&mut bytes)?;
        let destination = evidence.join(format!("fixture-tex-{run_id}-{name}"));
        validate_destination(&destination, std::slice::from_ref(&path))?;
        fs::write(destination, bytes)?;
    }
    Ok(())
}

pub fn cli(args: &[String]) -> Result<i32> {
    if args.first().map(String::as_str) == Some("--probe") {
        match runtime_config() {
            Ok(config) => {
                println!(
                    "{}",
                    json!({"available":true,"runtime":config.kind,"image":config.image})
                );
                return Ok(0);
            }
            Err(error) => {
                println!("{}", json!({"available":false,"reason":error.to_string()}));
                return Ok(2);
            }
        }
    }
    ensure!(args.len() == 2, "tex-container SOURCE OUTPUT or --probe");
    compile_document(Path::new(&args[0]), Path::new(&args[1]), None, None)?;
    Ok(0)
}
