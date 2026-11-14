//! Actual bounded Rust compiler preparation of the closed no-CRT fixture roles.
//! Compilation and byte qualification do not attest that an entry or debug event ran.
use super::{
    child,
    io::{self, HeldFile},
    prepared::{
        FixtureKind, PreparedFixture, PreparedSet, SealInput, Snapshot, self_build_request,
    },
    source,
};
use crate::{
    runtime::{self, CommandSpec},
    windows_security::{
        activation::{Failures, self_result::SelfRole},
        image::PeImage,
    },
};
use anyhow::{Result, ensure};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct RustTools {
    pub rustc: PathBuf,
    pub linker: PathBuf,
    pub kernel32: PathBuf,
    pub system_root: PathBuf,
}
struct Inputs {
    files: Vec<HeldFile>,
    snapshots: Vec<Snapshot>,
    common: usize,
}
impl Inputs {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            snapshots: Vec::new(),
            common: 0,
        }
    }
    fn retain(&mut self, mut file: HeldFile, maximum: usize) -> Result<()> {
        let captured = Snapshot::capture(&mut file, maximum);
        self.files.push(file);
        self.snapshots.push(captured?);
        Ok(())
    }
    fn open(&mut self, path: &Path, maximum: usize) -> Result<()> {
        self.retain(HeldFile::open(path, maximum)?, maximum)
    }
    fn create(&mut self, path: &Path, bytes: &[u8], maximum: usize) -> Result<()> {
        self.retain(io::create(path, bytes, maximum)?, maximum)
    }
    fn verify(&mut self) -> Result<()> {
        for file in &mut self.files {
            file.verify()?;
        }
        Ok(())
    }
    fn close(&mut self, primary: Option<anyhow::Error>) -> Result<()> {
        let mut errors = Vec::new();
        for file in self.files.iter_mut().rev() {
            if let Err(error) = file.close() {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            return primary.map_or(Ok(()), Err);
        }
        if let Some(primary) = primary {
            errors.insert(0, primary);
        }
        Err(Failures { errors }.into())
    }
}
impl Drop for Inputs {
    fn drop(&mut self) {
        let _ = self.close(None);
    }
}
impl RustTools {
    fn validate(&self) -> Result<()> {
        for (path, name) in [
            (&self.rustc, "rustc.exe"),
            (&self.linker, "link.exe"),
            (&self.kernel32, "kernel32.lib"),
        ] {
            child::canonical_input(path, name)?;
            io::plain(path, false)?;
        }
        ensure!(
            self.system_root.is_absolute() && self.system_root.is_dir(),
            "Rust fixture build requires trusted Windows root"
        );
        io::plain(&self.system_root, false)
    }
    fn command(&self, directory: &Path) -> CommandSpec {
        let mut command = CommandSpec::new(self.rustc.as_os_str());
        command.cwd = Some(directory.into());
        command.timeout = Duration::from_secs(60);
        command.idle_timeout = Some(Duration::from_secs(20));
        command.max_output = 1048576;
        command.env_remove = std::env::vars_os().map(|(name, _)| name).collect();
        let mut path = self.rustc.parent().unwrap().as_os_str().to_owned();
        path.push(";");
        path.push(self.linker.parent().unwrap());
        path.push(";");
        path.push(self.system_root.join("System32"));
        for (name, value) in [
            ("SystemRoot", self.system_root.as_os_str()),
            ("WINDIR", self.system_root.as_os_str()),
            ("TEMP", directory.as_os_str()),
            ("TMP", directory.as_os_str()),
            ("PATH", path.as_os_str()),
        ] {
            command.env.insert(name.into(), value.into());
        }
        command
    }
}
fn directory(path: &Path) -> Result<()> {
    io::missing(path)?;
    fs::create_dir(path)?;
    io::plain(path, false)
}
fn load_source(inputs: &mut Inputs, root: &Path, name: &str) -> Result<String> {
    let (file, text) = source::open_owned(root, name)?;
    inputs.retain(file, 65536)?;
    Ok(text)
}
struct Compile<'a> {
    directory: &'a Path,
    output: &'a Path,
    resource: Option<&'a Path>,
    module: bool,
    explicit: bool,
    imports: Option<&'a Path>,
}
fn compile(tools: &RustTools, inputs: &mut Inputs, job: Compile<'_>) -> Result<()> {
    io::missing(job.output)?;
    io::no_overrides(job.output)?;
    let mut command = tools.command(job.directory);
    command.args = [
        "--edition=2024",
        "--crate-type=bin",
        "--target=x86_64-pc-windows-msvc",
        "--crate-name=scientific_activation_fixture",
        "-Dwarnings",
        "-Cpanic=abort",
        "-Copt-level=0",
        "-Cdebuginfo=0",
        "-Ccodegen-units=1",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    command.args.push(OsString::from(format!(
        "-Clinker={}",
        tools.linker.display()
    )));
    for argument in [
        "/NODEFAULTLIB",
        "/MANIFEST:NO",
        "/SUBSYSTEM:CONSOLE",
        "/MACHINE:X64",
    ] {
        command.args.push(format!("-Clink-arg={argument}").into());
    }
    command.args.push(
        format!(
            "-Clink-arg=/ENTRY:{}",
            if job.module {
                "ModuleEntry"
            } else {
                "StartupEntry"
            }
        )
        .into(),
    );
    command.args.push(
        format!(
            "-Clink-arg=/ALLOWISOLATION:{}",
            if job.explicit { "NO" } else { "YES" }
        )
        .into(),
    );
    command
        .args
        .push(format!("-Lnative={}", tools.kernel32.parent().unwrap().display()).into());
    command
        .args
        .push(format!("-Clink-arg={}", tools.kernel32.display()).into());
    if let Some(resource) = job.resource {
        command
            .args
            .push(format!("-Clink-arg={}", resource.display()).into());
    }
    if job.module {
        let library = job.directory.join("startup-module.lib");
        io::missing(&library)?;
        io::missing(&job.directory.join("startup-module.exp"))?;
        for argument in [
            "/DLL".to_owned(),
            "/EXPORT:ObserveModuleActivation".into(),
            format!("/IMPLIB:{}", library.display()),
        ] {
            command.args.push(format!("-Clink-arg={argument}").into());
        }
    }
    if let Some(imports) = job.imports {
        command
            .args
            .push(format!("-Lnative={}", imports.display()).into());
    }
    command.args.extend([
        "-o".into(),
        job.output.as_os_str().into(),
        job.directory.join("main.rs").into_os_string(),
    ]);
    let mut output = runtime::run(&command)?;
    let success = output.code == 0 && output.stdout.is_empty() && output.stderr.is_empty();
    let code = output.code;
    output.stdout.fill(0);
    output.stderr.fill(0);
    ensure!(
        success,
        "fixed Rust fixture compiler failed exit={code} raw_output_withheld=True"
    );
    inputs.verify()?;
    inputs.open(job.output, 1048576)?;
    if job.module {
        inputs.open(&job.directory.join("startup-module.lib"), 131072)?;
    }
    Ok(())
}
fn rust_inputs(
    inputs: &mut Inputs,
    root: &Path,
    directory: &Path,
    role: &str,
    module: bool,
    config: &str,
) -> Result<()> {
    for name in ["abi.rs", "builtins.rs"] {
        let text = load_source(inputs, root, name)?;
        inputs.create(&directory.join(name), text.as_bytes(), 65536)?;
    }
    if !module {
        let text = load_source(inputs, root, "emit.rs")?;
        inputs.create(&directory.join("emit.rs"), text.as_bytes(), 65536)?;
        inputs.create(&directory.join("config.rs"), config.as_bytes(), 65536)?;
    }
    let entry = load_source(
        inputs,
        root,
        if module {
            "module_entry.rs"
        } else {
            "startup_entry.rs"
        },
    )?;
    inputs.create(&directory.join("main.rs"), entry.as_bytes(), 65536)?;
    inputs.create(&directory.join("role.rs"), role.as_bytes(), 65536)
}
fn resource(
    inputs: &mut Inputs,
    directory: &Path,
    language: u16,
    id: u16,
    payload: &[u8],
) -> Result<PathBuf> {
    let path = directory.join("activation.res");
    let mut bytes = source::resource_bytes(language, id, payload)?;
    let result = inputs.create(&path, &bytes, 131072);
    bytes.fill(0);
    result?;
    Ok(path)
}
struct RuntimeBytes {
    python: Vec<u8>,
    dll: Vec<u8>,
    python_path: PathBuf,
    dll_path: PathBuf,
}
impl Drop for RuntimeBytes {
    fn drop(&mut self) {
        self.python.fill(0);
        self.dll.fill(0);
    }
}
fn runtime_bytes(python: &Path, state: &Path, inputs: &mut Inputs) -> Result<RuntimeBytes> {
    self_build_request(Some(python), Some(state), 0)?;
    let dll = python.parent().unwrap().join("python311.dll");
    io::no_overrides(python)?;
    io::no_overrides(&dll)?;
    let mut bytes = RuntimeBytes {
        python: Vec::new(),
        dll: Vec::new(),
        python_path: python.into(),
        dll_path: dll.clone(),
    };
    let mut held_python = HeldFile::open(python, 16777216)?;
    bytes.python = held_python.bytes()?;
    inputs.retain(held_python, 16777216)?;
    let mut held_dll = HeldFile::open(&dll, 16777216)?;
    bytes.dll = held_dll.bytes()?;
    inputs.retain(held_dll, 16777216)?;
    // Reject the additional std fixture copied under Python filenames. These are
    // the actual pinned-runtime physical import roles, not a filename assertion.
    PeImage::parse(&bytes.python, 1)?.qualify_python_imports("python-exe")?;
    PeImage::parse(&bytes.dll, 1)?.qualify_python_imports("python311")?;
    Ok(bytes)
}
fn seal(
    inputs: &Inputs,
    kind: FixtureKind,
    runtime: &RuntimeBytes,
    image: &Path,
    module: Option<&Path>,
    start: usize,
) -> Result<PreparedFixture> {
    let source_path = if matches!(kind, FixtureKind::Child | FixtureKind::Default) {
        &runtime.python_path
    } else {
        &runtime.dll_path
    };
    let source_bytes = if matches!(kind, FixtureKind::Child | FixtureKind::Default) {
        &runtime.python
    } else {
        &runtime.dll
    };
    let manifest = PeImage::parse(source_bytes, 1)?.manifest(
        if matches!(kind, FixtureKind::Child | FixtureKind::Default) {
            1
        } else {
            2
        },
        false,
    )?;
    let mut snapshots = Vec::new();
    for snapshot in inputs.snapshots[..inputs.common]
        .iter()
        .chain(&inputs.snapshots[start..])
    {
        if !snapshots
            .iter()
            .any(|value: &Snapshot| value.path == snapshot.path)
        {
            snapshots.push(snapshot.clone());
        }
    }
    PreparedFixture::seal(
        SealInput {
            kind,
            python: &runtime.python_path,
            image,
            module,
            manifest_source: source_path,
            language: manifest.language,
            payload: manifest.bytes,
        },
        snapshots,
    )
}
/// Build all original fixture roles from actual external Python image manifests.
/// The caller must already own and verify that external runtime bundle. This
/// operation verifies the physical Python import roles and exact payload bytes;
/// it never substitutes the additional fixed-manifest Rust std fixture.
pub fn prepare(
    tools: &RustTools,
    python: &Path,
    state: &Path,
    sources: &Path,
) -> Result<PreparedSet> {
    tools.validate()?;
    let root = state.join("activation-rust-build");
    directory(&root)?;
    let mut inputs = Inputs::new();
    let result = (|| {
        for path in [&tools.rustc, &tools.linker, &tools.kernel32] {
            inputs.open(path, 67108864)?;
        }
        let runtime = runtime_bytes(python, state, &mut inputs)?;
        inputs.common = inputs.snapshots.len();
        let mut output = PreparedSet::default();
        for (kind, label) in [
            (FixtureKind::Child, "child"),
            (FixtureKind::DllRequest, "dll-request"),
            (FixtureKind::Default, "default"),
            (FixtureKind::SelfHost(SelfRole::Original), "self"),
            (FixtureKind::SelfHost(SelfRole::Manual), "manual"),
            (FixtureKind::SelfHost(SelfRole::ExplicitId2), "explicit-id2"),
        ] {
            let start = inputs.snapshots.len();
            let directory_path = root.join(label);
            directory(&directory_path)?;
            let source_bytes = if matches!(kind, FixtureKind::Child | FixtureKind::Default) {
                &runtime.python
            } else {
                &runtime.dll
            };
            let manifest = PeImage::parse(source_bytes, 1)?.manifest(
                if matches!(kind, FixtureKind::Child | FixtureKind::Default) {
                    1
                } else {
                    2
                },
                false,
            )?;
            let (role, config) = match kind {
                FixtureKind::Child => (
                    load_source(&mut inputs, sources, "child.rs")?,
                    source::header(python, manifest.language, false)?,
                ),
                FixtureKind::DllRequest => (
                    source::dll_source(&load_source(&mut inputs, sources, "child.rs")?)?,
                    source::header(&runtime.dll_path, manifest.language, true)?,
                ),
                FixtureKind::Default => (
                    load_source(&mut inputs, sources, "default_host.rs")?,
                    "pub const FIXED_ROLE_INPUT: bool = false;\n".into(),
                ),
                FixtureKind::SelfHost(role) => {
                    let request = self_build_request(
                        Some(python),
                        Some(state),
                        match role {
                            SelfRole::Original => 0,
                            SelfRole::Manual => 1,
                            SelfRole::ExplicitId2 => 2,
                        },
                    )?;
                    (
                        source::self_source(
                            &load_source(&mut inputs, sources, "self_host.rs")?,
                            request.role,
                        )?,
                        "pub const FIXED_ROLE_INPUT: bool = false;\n".into(),
                    )
                }
                _ => unreachable!(),
            };
            rust_inputs(&mut inputs, sources, &directory_path, &role, false, &config)?;
            let resource = kind
                .resource_id()
                .map(|id| {
                    resource(
                        &mut inputs,
                        &directory_path,
                        manifest.language,
                        id,
                        manifest.bytes,
                    )
                })
                .transpose()?;
            let image = python.parent().unwrap().join(kind.image_name());
            compile(
                tools,
                &mut inputs,
                Compile {
                    directory: &directory_path,
                    output: &image,
                    resource: resource.as_deref(),
                    module: false,
                    explicit: kind == FixtureKind::SelfHost(SelfRole::ExplicitId2),
                    imports: None,
                },
            )?;
            output.insert(seal(&inputs, kind, &runtime, &image, None, start)?)?;
        }
        prepare_module(tools, sources, &root, &runtime, &mut inputs, &mut output)?;
        inputs.verify()?;
        Ok(output)
    })();
    match result {
        Ok(output) => {
            inputs.close(None)?;
            Ok(output)
        }
        Err(primary) => {
            inputs.close(Some(primary))?;
            unreachable!("primary retained")
        }
    }
}
fn prepare_module(
    tools: &RustTools,
    sources: &Path,
    root: &Path,
    runtime: &RuntimeBytes,
    inputs: &mut Inputs,
    output: &mut PreparedSet,
) -> Result<()> {
    let manifest = PeImage::parse(&runtime.dll, 1)?.manifest(2, false)?;
    let mut first_host = Vec::new();
    for present in [false, true] {
        let start = inputs.snapshots.len();
        let label = if present {
            "module-id2"
        } else {
            "module-plain"
        };
        let folder = runtime.python_path.parent().unwrap().join(label);
        directory(&folder)?;
        let build_folder = root.join(label);
        directory(&build_folder)?;
        let role = load_source(inputs, sources, "module_dll.rs")?;
        rust_inputs(inputs, sources, &build_folder, &role, true, "")?;
        let resource = if present {
            Some(resource(
                inputs,
                &build_folder,
                manifest.language,
                2,
                manifest.bytes,
            )?)
        } else {
            None
        };
        let dll = folder.join("startup-module.dll");
        compile(
            tools,
            inputs,
            Compile {
                directory: &build_folder,
                output: &dll,
                resource: resource.as_deref(),
                module: true,
                explicit: false,
                imports: None,
            },
        )?;
        let host = folder.join("startup-module.exe");
        if present {
            inputs.create(&host, &first_host, 1048576)?;
        } else {
            let host_build = root.join("module-host");
            directory(&host_build)?;
            let role = load_source(inputs, sources, "module_host.rs")?;
            rust_inputs(
                inputs,
                sources,
                &host_build,
                &role,
                false,
                "pub const FIXED_ROLE_INPUT: bool = false;\n",
            )?;
            compile(
                tools,
                inputs,
                Compile {
                    directory: &host_build,
                    output: &host,
                    resource: None,
                    module: false,
                    explicit: false,
                    imports: Some(&build_folder),
                },
            )?;
            let mut held = HeldFile::open(&host, 1048576)?;
            first_host = held.bytes()?;
            held.close()?;
        }
        output.insert(seal(
            inputs,
            FixtureKind::Module { manifest: present },
            runtime,
            &host,
            Some(&dll),
            start,
        )?)?;
    }
    first_host.fill(0);
    Ok(())
}
