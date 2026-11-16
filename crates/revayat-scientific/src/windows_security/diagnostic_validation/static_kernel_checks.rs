//! StaticKernelInspection.cs:185–285, preserving ordered error identities and privacy.
use super::*;
use crate::windows_security::image::{self, KernelImage};
use std::cell::{Cell, RefCell};

#[derive(Debug)]
struct Wrapper {
    original: SharedError,
}
impl fmt::Display for Wrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private-wrapper-sentinel")
    }
}
impl Error for Wrapper {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
fn new_carrier(phase: &'static str, original: SharedError) -> Result<SharedError> {
    Ok(Arc::new(ActivationFailure::new(phase, original)?))
}
fn group(errors: Vec<SharedError>) -> SharedError {
    Arc::new(scratch::Failures { errors })
}
pub fn check_static_kernel_inspection_validation() -> Result<()> {
    let timeout: SharedError = Arc::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "private-timeout-sentinel",
    ));
    let cleanup = scratch::failure("private-cleanup-sentinel");
    let native: SharedError = Arc::new(std::io::Error::from_raw_os_error(5));
    let original = group(vec![timeout.clone(), cleanup.clone(), native.clone()]);
    let carrier = new_carrier("tool", original.clone())?;
    let value = carrier.downcast_ref::<ActivationFailure>().unwrap();
    let outcomes = original.downcast_ref::<scratch::Failures>().unwrap();
    ensure!(
        Arc::ptr_eq(&value.original, &original)
            && carrier.source().is_none()
            && outcomes.errors.len() == 3
            && Arc::ptr_eq(&outcomes.errors[0], &timeout)
            && Arc::ptr_eq(&outcomes.errors[1], &cleanup)
            && Arc::ptr_eq(&outcomes.errors[2], &native),
        "static activation failure lost original ordered outcomes"
    );
    let wrapper = Wrapper {
        original: carrier.clone(),
    };
    let expected = "WINDOWS_STATIC_ACTIVATION failure_phase=tool\nWINDOWS_STATIC_ACTIVATION cause_index=0 category=timeout\nWINDOWS_STATIC_ACTIVATION cause_index=1 category=io_error\nWINDOWS_STATIC_ACTIVATION cause_index=2 category=os_error winerror=5\nWINDOWS_STATIC_ACTIVATION failure_causes=3 truncated=False";
    let report = activation_failure_report(&wrapper);
    let propagated = carrier.clone();
    let reporting = scratch::failure("private-reporting-sentinel");
    retain_activation_reporting_failure(&wrapper, Some(reporting.clone()))?;
    let retained = value.reporting_failures.lock().unwrap();
    ensure!(
        retained.len() == 1
            && Arc::ptr_eq(&retained[0], &reporting)
            && Arc::ptr_eq(&value.original, &original)
            && activation_failure_report(carrier.as_ref()).as_deref() == Some(expected),
        "static reporting failure replaced original outcomes"
    );
    let unrelated = std::io::Error::other("private-unrelated-sentinel");
    ensure!(
        report.as_deref() == Some(expected)
            && Arc::ptr_eq(&propagated, &carrier)
            && !format!("{carrier:?} {carrier}").contains("sentinel")
            && activation_failure_report(&unrelated).is_none(),
        "static failure reporting lost order, status or privacy"
    );
    let cleanup_only = new_carrier("held-close", group(vec![cleanup.clone(), native.clone()]))?;
    let report = activation_failure_report(cleanup_only.as_ref()).unwrap();
    ensure!(report.contains("cause_index=0 category=io_error\nWINDOWS_STATIC_ACTIVATION cause_index=1 category=os_error winerror=5")
        && !report.contains("primary") && !report.contains("private"), "cleanup-only reporting invented a primary role");
    let wide =
        activation_failure_report(new_carrier("tool", group(vec![timeout.clone(); 40]))?.as_ref())
            .unwrap();
    let mut nested = timeout;
    for _ in 0..5 {
        nested = group(vec![nested]);
    }
    let deep = activation_failure_report(new_carrier("tool", nested)?.as_ref()).unwrap();
    ensure!(
        wide.ends_with("failure_causes=16 truncated=True")
            && deep.ends_with("failure_causes=0 truncated=True")
            && !wide.contains("private")
            && !deep.contains("private"),
        "static report exceeded traversal bounds"
    );
    let bytes = image::static_validation_fixture();
    let identity = KernelImage::from_static(&bytes)?.kernelbase_identity()?;
    require_same(
        Some(&identity),
        Some(&KernelImage::from_static(&bytes.clone())?.kernelbase_identity()?),
    )?;
    let worker_identity = KernelImage::from_activation_worker(&bytes)?.kernel32_identity()?;
    require_same(
        Some(&worker_identity),
        Some(&KernelImage::from_activation_worker(&bytes.clone())?.kernel32_identity()?),
    )?;
    let mut changed = bytes.clone();
    changed[0x700] ^= 1;
    ensure!(
        require_same(
            Some(&worker_identity),
            Some(&KernelImage::from_activation_worker(&changed)?.kernel32_identity()?)
        )
        .is_err(),
        "static worker binding accepted changed held bytes"
    );
    let changed_identity = KernelImage::from_static(&changed)?.kernelbase_identity()?;
    let trailing_identity = format!("{identity} ");
    for invalid in [
        None,
        Some(""),
        Some(trailing_identity.as_str()),
        Some(changed_identity.as_str()),
    ] {
        ensure!(
            require_same(Some(&identity), invalid).is_err(),
            "same-run binding accepted missing/changed identity"
        );
    }
    let profiles = image::observation_profiles();
    ensure!(
        require_same(Some(&profiles[0].identity), Some(&profiles[1].identity)).is_err(),
        "static LOAD switched supported profiles"
    );
    ensure!(require_same(Some("phase=image-identity module=kernel32.dll sha256=347f1ac1b7dbec710cf06fb3f67d131bceebbc19076bc77daacd31cfe452b496 pe_timestamp=4227614027 image_size=823296 file_size=836208"), Some("phase=image-identity module=kernel32.dll sha256=601aaacb3bdcbea24aec832d08a2f12ec7046183b6f40d18d61458d5e7008991 pe_timestamp=1269129758 image_size=823296 file_size=853648")).is_err(), "static LOAD switched supported kernel32 profiles");
    check_qualification(&identity, &worker_identity)?;
    check_actual_worker_binding()?;
    ensure!(
        require_same(None, Some(&identity)).is_err(),
        "static binding accepted absent preparation identity"
    );
    Ok(())
}
/// These synthetic bytes may reach static disassembly qualification, but can
/// never satisfy the production full-hash callback gate or create a LOAD claim.
fn check_actual_worker_binding() -> Result<()> {
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::rc::Rc;
    const TEXT: &str = "  0000000180001020: B8 01 00 00 00     mov eax,1\n  0000000180001025: E9 D6 FF FF FF     jmp 0000000180001000\n";
    let bytes = image::activation_worker_validation_fixture();
    let parsed = KernelImage::from_activation_worker(&bytes)?;
    let identity = parsed.kernel32_identity()?;
    ensure!(
        parsed.require_module_callback_profile().is_err(),
        "synthetic worker acquired full-hash callback admission"
    );
    let mut binding = SameRunBinding::default();
    ensure!(
        binding.bind_activation_load(&parsed).is_err(),
        "LOAD bound without a qualified static worker"
    );
    let order = RefCell::new(Vec::new());
    let reported = RefCell::new(String::new());
    let failure = binding
        .inspect_activation_worker(
            &mut Cursor::new(bytes.clone()),
            |slice| {
                order.borrow_mut().push("tool");
                if slice.rva != 0x1020 || slice.start != 0x180001020 || slice.length != 1504 {
                    return Err(retained(anyhow::anyhow!(
                        "tool received wrong fixed worker slice"
                    )));
                }
                Ok(TEXT.into())
            },
            || {
                order.borrow_mut().push("post-path");
                Ok(())
            },
            |line| {
                order.borrow_mut().push("report");
                *reported.borrow_mut() = line.into();
                Ok(())
            },
        )
        .err()
        .ok_or_else(|| anyhow::anyhow!("synthetic worker unexpectedly qualified"))?;
    let carrier = failure.downcast_ref::<ActivationFailure>().unwrap();
    ensure!(
        carrier.phase == "module-callback-profile"
            && *order.borrow() == ["tool", "post-path", "report"]
            && *reported.borrow()
                == format!("WINDOWS_STATIC_ACTIVATION profile_accepted=False {identity}")
            && binding.activation.is_none()
            && binding.bind_activation_load(&parsed).is_err(),
        "worker refusal lost order/metadata or bound unqualified image"
    );
    let reporting = scratch::failure("private-worker-reporting-sentinel");
    let failure = binding
        .inspect_activation_worker(
            &mut Cursor::new(bytes.clone()),
            |_| Ok(TEXT.into()),
            || Ok(()),
            |_| Err(reporting.clone()),
        )
        .err()
        .unwrap();
    let carrier = failure.downcast_ref::<ActivationFailure>().unwrap();
    let outcomes = carrier
        .original
        .downcast_ref::<scratch::Failures>()
        .unwrap();
    ensure!(
        carrier.phase == "module-callback-profile"
            && outcomes.errors.len() == 2
            && Arc::ptr_eq(&outcomes.errors[1], &reporting)
            && binding.activation.is_none()
            && !format!("{failure:?} {failure}").contains("sentinel"),
        "worker reporting replaced qualification failure or disclosed private cause"
    );
    for phase in ["tool", "post-path"] {
        let primary = scratch::failure("private-worker-operation-sentinel");
        let failure = binding
            .inspect_activation_worker(
                &mut Cursor::new(bytes.clone()),
                |_| {
                    if phase == "tool" {
                        Err(primary.clone())
                    } else {
                        Ok(TEXT.into())
                    }
                },
                || Err(primary.clone()),
                |_| panic!("failed pre-qualification operation must not emit profile refusal"),
            )
            .err()
            .unwrap();
        let carrier = failure.downcast_ref::<ActivationFailure>().unwrap();
        ensure!(
            carrier.phase == phase
                && Arc::ptr_eq(&carrier.original, &primary)
                && binding.activation.is_none(),
            "worker operation phase/identity changed or image bound"
        );
    }
    let mut missing_export = bytes.clone();
    missing_export[0x108..0x10c].fill(0);
    let failure = binding
        .inspect_activation_worker(
            &mut Cursor::new(missing_export),
            |_| panic!("invalid export reached tool"),
            || panic!("invalid export reached post-path"),
            |_| panic!("invalid export reached profile reporter"),
        )
        .err()
        .unwrap();
    ensure!(
        failure.downcast_ref::<ActivationFailure>().unwrap().phase == "fixed-export"
            && binding.activation.is_none(),
        "worker export was not checked before tool"
    );
    struct SharedHeld(Rc<RefCell<Cursor<Vec<u8>>>>);
    impl Read for SharedHeld {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().read(out)
        }
    }
    impl Seek for SharedHeld {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.0.borrow_mut().seek(position)
        }
    }
    let data = Rc::new(RefCell::new(Cursor::new(bytes.clone())));
    let failure = binding
        .inspect_activation_worker(
            &mut SharedHeld(data.clone()),
            |_| {
                data.borrow_mut().get_mut()[0x700] ^= 1;
                Ok(TEXT.into())
            },
            || Ok(()),
            |_| panic!("changed held bytes reached profile reporter"),
        )
        .err()
        .unwrap();
    ensure!(
        failure.downcast_ref::<ActivationFailure>().unwrap().phase == "posthash"
            && binding.activation.is_none(),
        "worker accepted changed same-held-file bytes"
    );
    let failure = binding
        .inspect_activation_worker(
            &mut Cursor::new(bytes),
            |_| Ok("private-unqualified-tool-output".into()),
            || Ok(()),
            |_| panic!("unqualified disassembly reached profile reporter"),
        )
        .err()
        .unwrap();
    ensure!(
        failure.downcast_ref::<ActivationFailure>().unwrap().phase == "qualifier"
            && binding.activation.is_none(),
        "worker profile or binding preceded static disassembly qualification"
    );
    Ok(())
}
fn check_qualification(identity: &str, worker_identity: &str) -> Result<()> {
    let qualification: SharedError = Arc::new(ContractFailure);
    let reporting = scratch::failure("fixed identity reporting");
    let reported = RefCell::new(String::new());
    report_observation_failure(
        qualification.clone(),
        identity,
        |line| {
            *reported.borrow_mut() = line.into();
            Ok(())
        },
        false,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(
        *reported.borrow() == format!("WINDOWS_STATIC_KERNEL profile_accepted=False {identity}"),
        "refused static identity metadata differs"
    );
    let combined = report_observation_failure(
        qualification.clone(),
        identity,
        |_| Err(reporting.clone()),
        false,
    )
    .unwrap_err();
    require_group(&combined, &qualification, &reporting)?;
    let bound = Cell::new(false);
    let order = RefCell::new(String::new());
    let propagated = qualify_activation(
        || {
            order.borrow_mut().push_str("qualify,");
            Err(qualification.clone())
        },
        worker_identity,
        |line| {
            *reported.borrow_mut() = line.into();
            order.borrow_mut().push_str("report,");
            Ok(())
        },
        || {
            bound.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        !bound.get()
            && *order.borrow() == "qualify,report,"
            && Arc::ptr_eq(&propagated, &qualification)
            && *reported.borrow()
                == format!("WINDOWS_STATIC_ACTIVATION profile_accepted=False {worker_identity}"),
        "refused activation profile was bound or lost metadata"
    );
    let combined = qualify_activation(
        || Err(qualification.clone()),
        worker_identity,
        |_| Err(reporting.clone()),
        || {
            bound.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(!bound.get(), "activation refusal bound identity");
    require_group(&combined, &qualification, &reporting)?;
    order.borrow_mut().clear();
    qualify_activation(
        || {
            order.borrow_mut().push_str("qualify,");
            Ok(())
        },
        worker_identity,
        |_| panic!("unexpected success report"),
        || {
            order.borrow_mut().push_str("bind,");
            bound.set(true);
            Ok(())
        },
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(
        bound.get() && *order.borrow() == "qualify,bind,",
        "activation identity bound before qualification"
    );
    Ok(())
}
fn require_group(error: &SharedError, first: &SharedError, second: &SharedError) -> Result<()> {
    let group = error
        .downcast_ref::<scratch::Failures>()
        .ok_or_else(|| anyhow::anyhow!("qualification lost aggregate"))?;
    ensure!(
        group.errors.len() == 2
            && Arc::ptr_eq(&group.errors[0], first)
            && Arc::ptr_eq(&group.errors[1], second),
        "qualification reporting replaced primary failure"
    );
    Ok(())
}
