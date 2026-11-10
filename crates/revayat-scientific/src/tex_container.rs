//! Local-only, immutable-image XeTeX sandbox with verified ownership cleanup.
use crate::{
    build::{BuildGuard, file_hash},
    identity::is_link,
    publication::{publish_files, validate_destination},
    runtime::{self, CommandSpec},
};
use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[path = "tex_execution.rs"]
mod execution;
#[path = "tex_finalize.rs"]
pub(crate) mod finalize;
pub use execution::{
    TexBoundary, compile_document, compile_document_observed, compile_document_with_lifecycle,
    compile_document_with_recovery,
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
            "--workdir=/input",
            "--mount",
            &mount_argument(&directory.join("input"), "/input", true)?,
            "--mount",
            &mount_argument(&directory.join("output"), "/output", false)?,
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
        format!("{INNER_TIMEOUT}s"),
        "/usr/local/bin/revayat-tex-entry".into(),
        format!("/input/{source_name}"),
    ]);
    Ok(command)
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
