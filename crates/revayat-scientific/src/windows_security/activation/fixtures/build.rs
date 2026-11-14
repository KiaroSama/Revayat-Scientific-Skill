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

#[path = "build_plan.rs"]
mod plan;
pub use plan::check_order_validation;

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
    ranges: &[std::ops::Range<usize>],
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
    for snapshot in inputs.snapshots[..inputs.common].iter().chain(
        ranges
            .iter()
            .flat_map(|range| inputs.snapshots[range.clone()].iter()),
    ) {
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
        let context = BuildContext {
            tools,
            sources,
            root: &root,
            state,
            runtime: &runtime,
        };
        plan::execute(|step| match step {
            plan::Step::Single(kind, label) => {
                prepare_single(&context, &mut inputs, &mut output, kind, label)
            }
            plan::Step::Module => prepare_module(&context, &mut inputs, &mut output),
        })?;
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
struct BuildContext<'a> {
    tools: &'a RustTools,
    sources: &'a Path,
    root: &'a Path,
    state: &'a Path,
    runtime: &'a RuntimeBytes,
}
fn prepare_single(
    context: &BuildContext<'_>,
    inputs: &mut Inputs,
    output: &mut PreparedSet,
    kind: FixtureKind,
    label: &str,
) -> Result<()> {
    let BuildContext {
        tools,
        sources,
        root,
        state,
        runtime,
    } = context;
    let python = &runtime.python_path;
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
            load_source(inputs, sources, "child.rs")?,
            source::header(python, manifest.language, false)?,
        ),
        FixtureKind::DllRequest => (
            source::dll_source(&load_source(inputs, sources, "child.rs")?)?,
            source::header(&runtime.dll_path, manifest.language, true)?,
        ),
        FixtureKind::Default => (
            load_source(inputs, sources, "default_host.rs")?,
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
                source::self_source(&load_source(inputs, sources, "self_host.rs")?, request.role)?,
                "pub const FIXED_ROLE_INPUT: bool = false;\n".into(),
            )
        }
        _ => unreachable!(),
    };
    rust_inputs(inputs, sources, &directory_path, &role, false, &config)?;
    let resource = kind
        .resource_id()
        .map(|id| {
            resource(
                inputs,
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
        inputs,
        Compile {
            directory: &directory_path,
            output: &image,
            resource: resource.as_deref(),
            module: false,
            explicit: kind == FixtureKind::SelfHost(SelfRole::ExplicitId2),
            imports: None,
        },
    )?;
    let owned_inputs = start..inputs.snapshots.len();
    output.insert(seal(
        inputs,
        kind,
        runtime,
        &image,
        None,
        std::slice::from_ref(&owned_inputs),
    )?)?;
    Ok(())
}
fn prepare_module(
    context: &BuildContext<'_>,
    inputs: &mut Inputs,
    output: &mut PreparedSet,
) -> Result<()> {
    let BuildContext {
        tools,
        sources,
        root,
        runtime,
        ..
    } = context;
    let manifest = PeImage::parse(&runtime.dll, 1)?.manifest(2, false)?;
    let folders = ["module-plain", "module-id2"]
        .map(|label| runtime.python_path.parent().unwrap().join(label));
    let build_folders = ["module-plain", "module-id2"].map(|label| root.join(label));
    let mut dll_inputs = Vec::with_capacity(2);
    // Original ModuleActivationFixture: both DLLs are linked before either host is produced.
    for (index, present) in [false, true].into_iter().enumerate() {
        let start = inputs.snapshots.len();
        directory(&folders[index])?;
        directory(&build_folders[index])?;
        let role = load_source(inputs, sources, "module_dll.rs")?;
        rust_inputs(inputs, sources, &build_folders[index], &role, true, "")?;
        let resource = if present {
            Some(resource(
                inputs,
                &build_folders[index],
                manifest.language,
                2,
                manifest.bytes,
            )?)
        } else {
            None
        };
        compile(
            tools,
            inputs,
            Compile {
                directory: &build_folders[index],
                output: &folders[index].join("startup-module.dll"),
                resource: resource.as_deref(),
                module: true,
                explicit: false,
                imports: None,
            },
        )?;
        dll_inputs.push(start..inputs.snapshots.len());
    }
    let host_start = inputs.snapshots.len();
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
    let first_host = folders[0].join("startup-module.exe");
    compile(
        tools,
        inputs,
        Compile {
            directory: &host_build,
            output: &first_host,
            resource: None,
            module: false,
            explicit: false,
            imports: Some(&build_folders[0]),
        },
    )?;
    let host_inputs = host_start..inputs.snapshots.len();
    let copy_start = inputs.snapshots.len();
    // Read through the descriptor already owned by Inputs. The common finalizer
    // retains and closes it even if reading/copying fails; no unowned close path.
    let mut bytes = inputs
        .files
        .iter_mut()
        .find(|file| file.path() == first_host)
        .ok_or_else(|| anyhow::anyhow!("compiled module host is not retained"))?
        .bytes()?;
    let copied = inputs.create(&folders[1].join("startup-module.exe"), &bytes, 1048576);
    bytes.fill(0);
    copied?;
    let copy_inputs = copy_start..inputs.snapshots.len();
    for (index, present) in [false, true].into_iter().enumerate() {
        let mut selected = vec![dll_inputs[index].clone(), host_inputs.clone()];
        if present {
            selected.push(copy_inputs.clone());
        }
        output.insert(seal(
            inputs,
            FixtureKind::Module { manifest: present },
            runtime,
            &folders[index].join("startup-module.exe"),
            Some(&folders[index].join("startup-module.dll")),
            &selected,
        )?)?;
    }
    Ok(())
}
