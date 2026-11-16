//! Fixed resource-ID2 file operation and independently attempted finalization, never child proof.
use super::{CallRole, Failures, FixedPathCall};
use anyhow::{Result, ensure};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestIdentity {
    pub language: u16,
    pub length: usize,
    pub image_length: usize,
    pub digest: String,
    pub image_digest: String,
}
pub fn require_same(first: &ManifestIdentity, later: &ManifestIdentity) -> Result<()> {
    ensure!(
        first == later,
        "fixed DLL activation evidence is inconclusive"
    );
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub created: bool,
    pub error: u32,
    pub released: bool,
}
pub fn metadata(manifest: &ManifestIdentity, value: Outcome) -> Result<String> {
    ensure!(
        (1..=65536).contains(&manifest.length)
            && if value.created {
                value.error == 0 && value.released
            } else {
                value.error != 0 && !value.released
            },
        "fixed DLL activation evidence is inconclusive"
    );
    let boolean = |value| if value { "True" } else { "False" };
    let line = format!(
        "WINDOWS_DLL_ACTIVATION context=host resource_type=24 resource_id=2 resource_language={} manifest_bytes={} created={} win32_error={} release_returned={} cache_reset_claimed=False cause_claimed=False child_equivalence_claimed=False",
        manifest.language,
        manifest.length,
        boolean(value.created),
        value.error,
        boolean(value.released)
    );
    ensure!(
        line.len() <= 512,
        "fixed DLL activation metadata exceeds bound"
    );
    Ok(line)
}
pub trait DllIo {
    type Held;
    fn acquire(&mut self) -> Result<Self::Held>;
    fn qualify(&mut self, held: &mut Self::Held) -> Result<()>;
    fn create(&mut self) -> Result<(usize, u32)>;
    fn release(&mut self, handle: usize) -> Result<()>;
    fn readback(&mut self, held: &mut Self::Held) -> Result<()>;
    fn close(&mut self, held: Self::Held) -> Result<()>;
    fn deadline(&mut self) -> Result<()>;
    fn emit(&mut self, value: Outcome) -> Result<()>;
}
/// Counterpart of ExecuteFixedDll: release first, qualified readback only after a clean operation
/// and release, then independent lease close; output follows every successful finalization step.
pub fn execute(io: &mut impl DllIo) -> Result<Outcome> {
    let mut held = None;
    let mut handle = usize::MAX;
    let mut value = Outcome {
        created: false,
        error: 0,
        released: false,
    };
    let operation = (|| {
        io.deadline()?;
        held = Some(io.acquire()?);
        io.qualify(held.as_mut().unwrap())?;
        io.deadline()?;
        (handle, value.error) = io.create()?;
        ensure!(handle != 0, "fixed DLL activation evidence is inconclusive");
        value.created = handle != usize::MAX;
        ensure!(
            if value.created {
                value.error == 0
            } else {
                value.error != 0
            },
            "fixed DLL activation evidence is inconclusive"
        );
        io.deadline()
    })();
    let mut failures = Vec::new();
    if handle != 0 && handle != usize::MAX {
        match io.release(handle) {
            Ok(()) => value.released = true,
            Err(error) => failures.push(error),
        }
    }
    if operation.is_ok() && failures.is_empty() {
        let readback = (|| {
            io.deadline()?;
            io.readback(held.as_mut().unwrap())?;
            io.deadline()
        })();
        if let Err(error) = readback {
            failures.push(error);
        }
    }
    if let Some(held) = held
        && let Err(error) = io.close(held)
    {
        failures.push(error);
    }
    if let Err(primary) = operation {
        failures.insert(0, primary);
    }
    ensure!(failures.is_empty(), Failures { errors: failures });
    io.deadline()?;
    io.emit(value)?;
    io.deadline()?;
    Ok(value)
}
/// Match RegistryLoaderEvidence.Sanitize: retain aggregate structure and private raw cause owners.
pub fn sanitize(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<Failures>() {
        Ok(group) => Failures {
            errors: group.errors.into_iter().map(sanitize).collect(),
        }
        .into(),
        Err(error) => crate::windows_security::sxs::safe(error, "fixed-dll"),
    }
}
pub fn safe_execute(io: &mut impl DllIo) -> Result<Outcome> {
    execute(io).map_err(sanitize)
}
#[derive(Default)]
struct CheckIo {
    mode: Option<u8>,
    handle: usize,
    error: u32,
    order: Vec<&'static str>,
    releases: usize,
    closes: usize,
    reports: usize,
    deadlines: usize,
}
impl DllIo for CheckIo {
    type Held = ();
    fn acquire(&mut self) -> Result<()> {
        self.order.push("acquire");
        if self.mode == Some(0) {
            anyhow::bail!("private-dll-path-sentinel");
        }
        Ok(())
    }
    fn qualify(&mut self, _: &mut ()) -> Result<()> {
        self.order.push("qualify");
        if self.mode == Some(1) {
            anyhow::bail!("private-dll-path-sentinel");
        }
        Ok(())
    }
    fn create(&mut self) -> Result<(usize, u32)> {
        self.order.push("create");
        if self.mode == Some(2) {
            anyhow::bail!("private-dll-path-sentinel");
        }
        Ok((self.handle, self.error))
    }
    fn release(&mut self, handle: usize) -> Result<()> {
        ensure!(handle == self.handle, "DLL release handle changed");
        self.order.push("release");
        self.releases += 1;
        if matches!(self.mode, Some(3 | 7)) {
            anyhow::bail!("private-dll-cleanup-sentinel");
        }
        Ok(())
    }
    fn readback(&mut self, _: &mut ()) -> Result<()> {
        self.order.push("readback");
        if self.mode == Some(4) {
            anyhow::bail!("private-dll-path-sentinel");
        }
        Ok(())
    }
    fn close(&mut self, _: ()) -> Result<()> {
        self.order.push("close");
        self.closes += 1;
        if matches!(self.mode, Some(5 | 7)) {
            anyhow::bail!("private-dll-cleanup-sentinel");
        }
        Ok(())
    }
    fn deadline(&mut self) -> Result<()> {
        self.deadlines += 1;
        if self.mode == Some(7) && self.deadlines == 3 {
            anyhow::bail!("private-dll-path-sentinel");
        }
        Ok(())
    }
    fn emit(&mut self, value: Outcome) -> Result<()> {
        self.order.push("emit");
        self.reports += 1;
        ensure!(
            value.created == (self.handle != usize::MAX)
                && value.error == self.error
                && value.released == value.created,
            "DLL observed outcome changed"
        );
        if self.mode == Some(6) {
            anyhow::bail!("private-dll-path-sentinel");
        }
        Ok(())
    }
}
/// Source counterpart of StartupActivationAccess.CheckFixedDllValidation, not a cache-reset proof.
pub fn check_fixed_dll_validation() -> Result<()> {
    let call = FixedPathCall::new(
        CallRole::HostDll,
        "C:\\owned space\\python\\DLLs\\_ctypes.pyd",
        0,
    )?;
    let value = call.context();
    ensure!(
        std::mem::size_of::<usize>() == 8
            && std::mem::size_of::<super::ActCtx>() == 56
            && value.size == 56
            && value.flags == 8
            && value.source == call.source_units().as_ptr() as usize
            && value.resource == 2
            && value.architecture == 0
            && value.language == 0
            && value.directory == 0
            && value.application == 0
            && value.module == 0,
        "fixed DLL ACTCTX differs"
    );
    for handle in [0, usize::MAX, 7] {
        for error in [0, 5, u32::MAX] {
            let mut io = CheckIo {
                handle,
                error,
                ..CheckIo::default()
            };
            let result = execute(&mut io);
            let valid = handle != 0 && handle != usize::MAX;
            let qualified = handle != 0 && if valid { error == 0 } else { error != 0 };
            ensure!(
                result.is_ok() == qualified
                    && io.releases == usize::from(valid)
                    && io.closes == 1
                    && io.reports == usize::from(qualified),
                "DLL handle/error ownership matrix differs"
            );
        }
    }
    for mode in 0..8 {
        let mut io = CheckIo {
            mode: Some(mode),
            handle: 7,
            error: 0,
            ..CheckIo::default()
        };
        let error = safe_execute(&mut io).unwrap_err();
        ensure!(
            !format!("{error:?}").contains("sentinel")
                && io.order.contains(&"close") == (mode != 0)
                && io.order.contains(&"release") == (mode >= 3)
                && io.order.contains(&"emit") == (mode == 6),
            "DLL failed lifecycle leaked payload or skipped independent cleanup"
        );
        if mode == 7 {
            let group = error
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("DLL error group missing"))?;
            ensure!(
                group.errors.len() == 3
                    && group.errors[0]
                        .downcast_ref::<crate::windows_security::sxs::PrivateFailure>()
                        .is_some_and(
                            |first| first.original().to_string() == "private-dll-path-sentinel"
                        ),
                "DLL error group lost original-first private cause"
            );
        }
    }
    let identity = ManifestIdentity {
        language: 1033,
        length: 4,
        image_length: 512,
        digest: "fixed".into(),
        image_digest: "image".into(),
    };
    require_same(&identity, &identity)?;
    ensure!(
        metadata(
            &identity,
            Outcome {
                created: true,
                error: 0,
                released: true
            }
        )?
        .contains("created=True win32_error=0 release_returned=True")
            && metadata(
                &identity,
                Outcome {
                    created: false,
                    error: 14001,
                    released: false
                }
            )?
            .contains("created=False win32_error=14001 release_returned=False"),
        "DLL fixed metadata differs"
    );
    let empty = ManifestIdentity {
        language: 0,
        length: 0,
        image_length: 0,
        digest: String::new(),
        image_digest: String::new(),
    };
    ensure!(
        require_same(&identity, &empty).is_err(),
        "DLL original incomplete identity fixture accepted"
    );
    let changed = ManifestIdentity {
        language: 0,
        ..identity.clone()
    };
    ensure!(
        require_same(&identity, &changed).is_err(),
        "DLL manifest identity drift accepted"
    );
    for value in [
        Outcome {
            created: true,
            error: 5,
            released: true,
        },
        Outcome {
            created: true,
            error: 0,
            released: false,
        },
        Outcome {
            created: false,
            error: 0,
            released: false,
        },
        Outcome {
            created: false,
            error: 5,
            released: true,
        },
    ] {
        ensure!(
            metadata(&identity, value).is_err(),
            "DLL inconsistent outcome metadata accepted"
        );
    }
    Ok(())
}
