//! Same-run prepared fixture identities. Sealing/holding bytes never attests an executed entry.
use super::{
    child,
    io::{self, HeldFile},
    lease::{self, CloseOrder, Lease},
};
use crate::windows_security::{activation::self_result::SelfRole, image::PeImage};
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureKind {
    Child,
    DllRequest,
    Default,
    SelfHost(SelfRole),
    Module { manifest: bool },
}
impl FixtureKind {
    pub fn image_name(self) -> String {
        match self {
            Self::Child => "startup-activation.exe".into(),
            Self::DllRequest => "startup-dll-resource.exe".into(),
            Self::Default => "startup-default-activation.exe".into(),
            Self::SelfHost(role) => role.image_name(),
            Self::Module { .. } => "startup-module.exe".into(),
        }
    }
    pub fn resource_id(self) -> Option<u16> {
        match self {
            Self::Child | Self::DllRequest | Self::Module { manifest: false } => None,
            Self::Default => Some(1),
            Self::SelfHost(SelfRole::Manual) => Some(101),
            _ => Some(2),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub path: PathBuf,
    pub length: u64,
    pub digest: String,
    pub maximum: usize,
}
impl Snapshot {
    pub fn capture(held: &mut HeldFile, maximum: usize) -> Result<Self> {
        let mut bytes = held.bytes()?;
        let snapshot = Self {
            path: held.path().into(),
            length: bytes.len() as u64,
            digest: io::digest(&bytes),
            maximum,
        };
        bytes.fill(0);
        Ok(snapshot)
    }
}
pub struct PreparedFixture {
    kind: FixtureKind,
    python: PathBuf,
    image: PathBuf,
    module: Option<PathBuf>,
    manifest_source: PathBuf,
    language: u16,
    payload_length: u64,
    payload_digest: String,
    inputs: Vec<Snapshot>,
}
pub(crate) struct SealInput<'a> {
    pub kind: FixtureKind,
    pub python: &'a Path,
    pub image: &'a Path,
    pub module: Option<&'a Path>,
    pub manifest_source: &'a Path,
    pub language: u16,
    pub payload: &'a [u8],
}
impl PreparedFixture {
    /// Only the trusted in-crate builder seals a candidate, after actual compiler
    /// completion. Every supplied snapshot and role qualifier is independently
    /// rechecked through a fresh retained lease before the candidate can escape.
    pub(crate) fn seal(input: SealInput<'_>, inputs: Vec<Snapshot>) -> Result<Self> {
        let SealInput {
            kind,
            python,
            image,
            module,
            manifest_source,
            language,
            payload,
        } = input;
        ensure!(
            !inputs.is_empty()
                && inputs.len() <= 32
                && inputs.iter().any(|value| value.path == image)
                && inputs.iter().any(|value| value.path == manifest_source)
                && module.is_some() == matches!(kind, FixtureKind::Module { .. }),
            "fixture seal lacks bounded role/source/image identities"
        );
        child::canonical_input(python, "python.exe")?;
        ensure!(
            image.file_name().and_then(|v| v.to_str()) == Some(kind.image_name().as_str()),
            "fixture output filename differs from role"
        );
        let directory = python.parent().unwrap();
        let expected_directory = match kind {
            FixtureKind::Module { manifest } => directory.join(if manifest {
                "module-id2"
            } else {
                "module-plain"
            }),
            _ => directory.into(),
        };
        ensure!(
            image.parent() == Some(expected_directory.as_path()),
            "fixture image is outside fixed prepared runtime role"
        );
        if let Some(module) = module {
            ensure!(
                module == expected_directory.join("startup-module.dll")
                    && inputs.iter().any(|value| value.path == module),
                "fixture module pair identity is absent"
            );
        }
        let candidate = Self {
            kind,
            python: python.into(),
            image: image.into(),
            module: module.map(Path::to_path_buf),
            manifest_source: manifest_source.into(),
            language,
            payload_length: payload.len() as u64,
            payload_digest: io::digest(payload),
            inputs,
        };
        candidate.hold(Some(python))?.close()?;
        Ok(candidate)
    }
    pub fn kind(&self) -> FixtureKind {
        self.kind
    }
    pub fn image(&self) -> &Path {
        &self.image
    }
    pub fn module(&self) -> Option<&Path> {
        self.module.as_deref()
    }
    pub fn language(&self) -> u16 {
        self.language
    }
    pub fn hold(&self, python: Option<&Path>) -> Result<Lease<HeldFile>> {
        ensure!(
            python == Some(self.python.as_path()),
            "fixture identity was not prepared for this runtime"
        );
        for path in [&self.python, &self.manifest_source, &self.image] {
            io::plain(path, false)?;
            io::no_overrides(path)?;
        }
        if let Some(module) = &self.module {
            io::no_overrides(module)?;
        }
        let opens = self
            .inputs
            .iter()
            .map(|snapshot| {
                Box::new(move || HeldFile::open(&snapshot.path, snapshot.maximum))
                    as Box<dyn FnOnce() -> Result<HeldFile> + '_>
            })
            .collect();
        lease::acquire(
            opens,
            if self.kind == FixtureKind::Child {
                CloseOrder::Forward
            } else {
                CloseOrder::Reverse
            },
            |held| {
                let mut buffers = Vec::new();
                let result = (|| {
                    for (file, expected) in held.iter_mut().zip(&self.inputs) {
                        let bytes = file.bytes()?;
                        buffers.push(bytes);
                        io::require_identity(
                            buffers.last().unwrap(),
                            expected.length,
                            &expected.digest,
                        )?;
                    }
                    let selected = |path: &Path| {
                        self.inputs
                            .iter()
                            .position(|value| value.path == path)
                            .ok_or_else(|| anyhow::anyhow!("fixture retained identity absent"))
                    };
                    let source = &buffers[selected(&self.manifest_source)?];
                    let source_image = PeImage::parse(source, 1)?;
                    let manifest = source_image.manifest(
                        if matches!(self.kind, FixtureKind::Child | FixtureKind::Default) {
                            1
                        } else {
                            2
                        },
                        false,
                    )?;
                    ensure!(
                        manifest.language == self.language,
                        "fixture source manifest language changed"
                    );
                    io::require_identity(
                        manifest.bytes,
                        self.payload_length,
                        &self.payload_digest,
                    )?;
                    let image = PeImage::parse(&buffers[selected(&self.image)?], 1)?;
                    match self.kind {
                        FixtureKind::Child | FixtureKind::DllRequest => {
                            image.qualify_child_activation()?
                        }
                        FixtureKind::Default => {
                            image.qualify_default_activation(self.language, manifest.bytes)?
                        }
                        FixtureKind::SelfHost(role) => {
                            image.qualify_self_activation(role, self.language, manifest.bytes)?
                        }
                        FixtureKind::Module { manifest: present } => {
                            image.qualify_module_activation(
                                false,
                                false,
                                self.language,
                                manifest.bytes,
                            )?;
                            PeImage::parse(&buffers[selected(self.module.as_ref().unwrap())?], 1)?
                                .qualify_module_activation(
                                    true,
                                    present,
                                    self.language,
                                    manifest.bytes,
                                )?;
                        }
                    }
                    Ok(())
                })();
                for bytes in &mut buffers {
                    bytes.fill(0);
                }
                result
            },
        )
    }
}
#[derive(Default)]
pub struct PreparedSet {
    images: Vec<PreparedFixture>,
}
impl PreparedSet {
    pub(crate) fn insert(&mut self, image: PreparedFixture) -> Result<()> {
        ensure!(
            !self.images.iter().any(|value| value.kind == image.kind),
            "fixture role was already prepared"
        );
        self.images.push(image);
        Ok(())
    }
    pub fn get(&self, kind: FixtureKind, python: Option<&Path>) -> Result<&PreparedFixture> {
        self.images
            .iter()
            .find(|value| value.kind == kind && python == Some(value.python.as_path()))
            .ok_or_else(|| {
                anyhow::anyhow!("fixture identity was not prepared for this role/runtime")
            })
    }
    pub fn self_prepared(&self, python: Option<&Path>, role: i32) -> Result<&PreparedFixture> {
        self.get(FixtureKind::SelfHost(SelfRole::try_from(role)?), python)
    }
    pub fn hold_self(&self, python: Option<&Path>, role: i32) -> Result<Lease<HeldFile>> {
        self.self_prepared(python, role)?.hold(python)
    }
}
pub struct SelfBuildRequest {
    pub role: SelfRole,
    pub python: PathBuf,
    pub state: PathBuf,
}
pub fn self_build_request(
    python: Option<&Path>,
    state: Option<&Path>,
    role: i32,
) -> Result<SelfBuildRequest> {
    let role = SelfRole::try_from(role)?;
    let python = python.ok_or_else(|| anyhow::anyhow!("fixed self build runtime is absent"))?;
    let state = state.ok_or_else(|| anyhow::anyhow!("fixed self build state is absent"))?;
    child::canonical_input(python, "python.exe")?;
    ensure!(
        state.is_absolute() && python.parent() == Some(state.join("python").as_path()),
        "self build input is outside fixed prepared runtime"
    );
    Ok(SelfBuildRequest {
        role,
        python: python.into(),
        state: state.into(),
    })
}
