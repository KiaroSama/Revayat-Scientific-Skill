//! Resolve a local runtime and immutable preinstalled image, with per-call queries.
use super::*;
pub fn runtime_config() -> Result<RuntimeConfig> {
    let executable = if let Ok(requested) = std::env::var("REVAYAT_CONTAINER_RUNTIME") {
        runtime::executable(&requested)?
    } else {
        runtime::executable("docker").or_else(|_| runtime::executable("podman"))?
    };
    let environment = [
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "REVAYAT_TEX_IMAGE",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect();
    runtime_config_with(&executable, &environment, |arguments| {
        let (code, text) = call(arguments, 15)?;
        ensure!(code == 0, "local container runtime query failed");
        Ok(serde_json::from_str(&text)?)
    })
}
pub fn runtime_config_with(
    executable: &Path,
    environment: &BTreeMap<String, String>,
    mut query: impl FnMut(&[String]) -> Result<Value>,
) -> Result<RuntimeConfig> {
    let kind = executable
        .file_stem()
        .context("runtime has no basename")?
        .to_string_lossy()
        .to_lowercase();
    ensure!(
        kind == "docker" || kind == "podman",
        "runtime must be Docker or Podman"
    );
    let executable = executable
        .to_str()
        .context("runtime path must be UTF-8")?
        .to_owned();
    let value = |key: &str| {
        environment
            .get(key)
            .filter(|v| !v.is_empty())
            .map(String::as_str)
    };
    let base = if kind == "docker" {
        let context = value("DOCKER_CONTEXT");
        let endpoint = if context.is_none() {
            value("DOCKER_HOST")
        } else {
            None
        };
        let endpoint = if let Some(endpoint) = endpoint {
            endpoint.to_owned()
        } else {
            let mut args = vec![executable.clone(), "context".into(), "inspect".into()];
            if let Some(context) = context {
                args.push(context.into());
            }
            query(&args)?[0]["Endpoints"]["docker"]["Host"]
                .as_str()
                .context("Docker context omitted endpoint")?
                .to_owned()
        };
        validate_endpoint(&endpoint, &kind)?;
        vec![executable, "--host".into(), endpoint]
    } else if cfg!(target_os = "linux")
        && value("CONTAINER_HOST").is_none()
        && value("CONTAINER_CONNECTION").is_none()
    {
        vec![executable, "--remote=false".into()]
    } else {
        let rows = query(&[
            executable.clone(),
            "system".into(),
            "connection".into(),
            "list".into(),
            "--format=json".into(),
        ])?;
        let selected = value("CONTAINER_CONNECTION").unwrap_or("");
        let requested = value("CONTAINER_HOST").unwrap_or("");
        let choices = rows
            .as_array()
            .context("invalid Podman connection list")?
            .iter()
            .filter(|row| {
                if !requested.is_empty() {
                    row["URI"] == requested
                } else if !selected.is_empty() {
                    row["Name"] == selected
                } else {
                    row["Default"] == true
                }
            })
            .collect::<Vec<_>>();
        ensure!(
            choices.len() == 1,
            "a single configured local Podman connection is required"
        );
        let connection = choices[0];
        let endpoint = connection["URI"]
            .as_str()
            .context("connection endpoint missing")?;
        validate_endpoint(endpoint, &kind)?;
        let mut args = vec![executable, "--url".into(), endpoint.into()];
        if let Some(identity) = connection["Identity"].as_str().filter(|s| !s.is_empty()) {
            args.extend(["--identity".into(), identity.into()]);
        }
        args
    };
    validate_runtime_information(&query(&append(&base, &["info", "--format=json"]))?, &kind)?;
    let image = value("REVAYAT_TEX_IMAGE").unwrap_or(DEFAULT_IMAGE);
    ensure!(
        !image.is_empty() && !image.starts_with('-') && !image.chars().any(char::is_whitespace),
        "invalid preinstalled TeX image reference"
    );
    let images = query(&append(&base, &["image", "inspect", image]))?;
    let images = images.as_array().context("invalid image inspection")?;
    ensure!(
        images.len() == 1 && images[0]["Config"]["Labels"][IMAGE_LABEL] == "1",
        "preinstalled TeX image does not declare supported toolchain"
    );
    let id = images[0]["Id"]
        .as_str()
        .or_else(|| images[0]["ID"].as_str())
        .context("image identity missing")?;
    ensure!(hash_id(id, true), "container image identity is invalid");
    Ok(RuntimeConfig {
        base,
        kind,
        image: id.into(),
    })
}
