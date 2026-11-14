//! One fixed standard-tool capture around the existing qualified LPAC authority lifecycle.
//! Host collector evidence proves recording, never child visibility or an original failing call.
use super::{
    SessionSnapshot, StorageLifecycle, capture, native_identity::finish,
    native_session::SessionOwner, native_storage::Storage,
};
use crate::windows_security::activation::diagnostics::{self, Stage};
use crate::windows_security::{
    activation::native::{ManifestRole, observe_manifest, require_host},
    native::{
        AuthorityObserver, NativeRunView, ScratchVolume, run_observed, run_owned_observed,
        run_sxs_tool,
    },
};
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    path::Path,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    AfterStorage,
    AfterDenial,
    AfterBind,
    BeforeAuthorityResume,
    BeforeControl,
    BeforeStop,
    AfterStop,
}
#[derive(Debug)]
pub struct CaptureProof {
    pub starter_reaped: bool,
    pub session_stopped: bool,
    pub storage_qualified: bool,
    pub authority_completed: bool,
    pub evidence: String,
}
struct Capture<'a, F> {
    volume: &'a Path,
    view: Option<&'a NativeRunView>,
    observe: F,
    subject: Option<std::path::PathBuf>,
    authority_reaped: bool,
    session: SessionOwner<'a>,
    storage: Option<Storage>,
    lifecycle: StorageLifecycle,
    package: Option<String>,
    bound: Option<SessionSnapshot>,
    attempted: bool,
    reaped: bool,
    denied: bool,
    stopped: bool,
    collector: bool,
    stop_attempted: bool,
    start: Instant,
}
impl<F: FnMut(Boundary) -> Result<()>> Capture<'_, F> {
    fn storage(&self) -> Result<&Storage> {
        self.storage
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS storage is not prepared"))
    }
    fn deadline(&self) -> Result<()> {
        ensure!(
            self.start.elapsed() < Duration::from_secs(30),
            "SxS fixed capture deadline exceeded"
        );
        require_host()
    }
    fn logfile(&self) -> Result<String> {
        Ok(self
            .storage()?
            .path("capture.etl")?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("SxS logfile encoding differs"))?
            .to_owned())
    }
    fn control(&mut self) -> Result<()> {
        self.deadline()?;
        ensure!(
            self.bound.is_some() && !self.collector,
            "SxS collector is unavailable or already attempted"
        );
        self.collector = true;
        (self.observe)(Boundary::BeforeControl)?;
        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SxS storage unavailable"))?;
        let bytes = ManifestRole::CollectorControl.bytes(&storage.run)?;
        storage.write("collector.manifest", &bytes)?;
        let path = storage.require("collector.manifest")?;
        observe_manifest(&path, &storage.run, ManifestRole::CollectorControl)?;
        storage.require("collector.manifest")?;
        self.deadline()
    }
    fn stop(&mut self) -> Result<()> {
        ensure!(!self.stop_attempted, "SxS collector stop already attempted");
        self.stop_attempted = true;
        let mut errors = Vec::new();
        // An observer error cannot suppress real collector cleanup.
        if let Err(error) = (self.observe)(Boundary::BeforeStop) {
            errors.push(error);
        }
        let result = if self.attempted || self.session.durable_pending()? {
            (|| {
                let logfile = self.logfile()?;
                self.storage()?.require("capture.etl")?;
                self.session.stop(
                    &logfile,
                    self.reaped,
                    self.bound.is_some(),
                    self.bound.as_ref(),
                )?;
                self.stopped = true;
                Ok(())
            })()
        } else {
            self.stopped = true;
            Ok(())
        };
        if result.is_ok()
            && let Err(error) = (self.observe)(Boundary::AfterStop)
        {
            errors.push(error);
        }
        finish(result, errors)
    }
    fn parse(&mut self, success: bool) -> Result<String> {
        ensure!(
            self.bound.is_some() && self.stopped && self.reaped,
            "SxS parsing lacks stopped owned capture"
        );
        let storage = self
            .storage
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SxS storage unavailable"))?;
        capture::at_parse(0, || storage.require("capture.etl").map(|_| ()))?;
        capture::at_parse(1, || {
            storage.require_evidence_length("capture.etl", 8_388_608)
        })?;
        let parsing_started = Instant::now();
        let remaining = || Ok(10.0 - parsing_started.elapsed().as_secs_f64());
        let storage = std::cell::RefCell::new(storage);
        capture::at_parse(2, || {
            super::seed::prepare_text(
                remaining,
                || storage.borrow().require_absent("capture.txt"),
                || storage.borrow_mut().write("capture.txt", b""),
                || storage.borrow().require_empty("capture.txt"),
            )
        })?;
        let mut parser_reaped = true;
        let parsing = capture::at_parse(3, || {
            run_sxs_tool(
                &storage.borrow().folder,
                true,
                &mut parser_reaped,
                remaining,
            )
        });
        self.reaped &= parser_reaped;
        parsing?;
        ensure!(parser_reaped, "SxS parser was not reaped");
        capture::at_parse(4, || storage.borrow().require("capture.txt").map(|_| ()))?;
        let subject = self
            .subject
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS actual authority subject was not bound"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("SxS authority path encoding differs"))?;
        let control = storage.borrow().path("collector.manifest")?;
        let control = control
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("SxS control path encoding differs"))?;
        capture::at_parse(5, || {
            storage.borrow().read_evidence("capture.txt", |bytes| {
                if success {
                    super::success_evidence(bytes, subject, control)
                } else {
                    super::failure_evidence(bytes, subject)
                }
            })
        })
    }

    fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        let journal_pending = match self.session.durable_pending() {
            Ok(pending) => pending,
            Err(error) => {
                errors.push(error);
                true
            }
        };
        // Never delete live collector/parser storage. The outer owner must recover uncertain state.
        if self.stopped
            && !journal_pending
            && self.reaped
            && self.authority_reaped
            && let Some(storage) = &mut self.storage
        {
            if let Err(error) = storage.close() {
                errors.push(error);
            }
        } else if self.storage.is_some() {
            errors.push(anyhow::anyhow!(
                "SxS private storage retained because process/session cleanup is uncertain"
            ));
            // Prevent deletion when any producer remains uncertain, without leaking Rust ownership.
            if let Some(storage) = &mut self.storage {
                storage.retain();
            }
        }
        if let Err(error) = self.session.close() {
            errors.push(error);
        }
        finish(Ok(()), errors)
    }
}
impl<F: FnMut(Boundary) -> Result<()>> AuthorityObserver for Capture<'_, F> {
    fn prepare(&mut self, package: &str) -> Result<()> {
        self.deadline()?;
        ensure!(
            self.storage.is_none() && self.package.is_none(),
            "SxS authority preparation repeated"
        );
        if let Some(view) = self.view {
            view.require()?;
            ensure!(
                view.package_sid() == package,
                "SxS actual profile differs from durable run"
            );
        }
        self.package = Some(package.to_owned());
        let storage = &mut self.storage;
        let lifecycle = &mut self.lifecycle;
        capture::boundary(0, || {
            lifecycle.prepare(|| {
                *storage = Some(
                    match self.view {
                        Some(view) => Storage::prepare_owned(self.volume, package, view.run_id()),
                        None => Storage::prepare(self.volume, package),
                    }
                    .map_err(|error| diagnostics::at(error, Stage::SxsStorage))?,
                );
                storage
                    .as_ref()
                    .unwrap()
                    .require_seed()
                    .map_err(|error| diagnostics::at(error, Stage::SxsStorage))
            })
        })?;
        (self.observe)(Boundary::AfterStorage)
    }
    fn before_create(&mut self) -> Result<()> {
        self.authority_reaped = false;
        Ok(())
    }
    fn after_reap(&mut self, reaped: bool) -> Result<()> {
        self.authority_reaped = reaped;
        Ok(())
    }
    fn before_resume(&mut self, process: *mut c_void, package: &str, image: &Path) -> Result<()> {
        self.deadline()?;
        ensure!(
            self.package.as_deref() == Some(package) && !self.attempted,
            "SxS actual authority profile changed or launch repeated"
        );
        ensure!(
            self.subject.is_none() && image.is_absolute(),
            "SxS actual authority image binding differs"
        );
        self.subject = Some(image.to_owned());
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS storage unavailable"))?;
        capture::boundary(1, || self.lifecycle.seal(|| storage.require_seed()))?;
        capture::boundary(2, || self.lifecycle.enter(|| storage.require_seed()))?;
        let started = Instant::now();
        storage
            .deny(process, package)
            .map_err(|error| diagnostics::at(error, Stage::SxsStorage))?;
        self.denied = true;
        (self.observe)(Boundary::AfterDenial)?;
        {
            let current = std::cell::RefCell::new(&mut *self);
            capture::start_sequence(
                || Ok(10.0 - started.elapsed().as_secs_f64()),
                || {
                    let mut current = current.borrow_mut();
                    let logfile = current.logfile()?;
                    current
                        .session
                        .preabsent(&logfile)
                        .map_err(|error| diagnostics::at(error, Stage::SxsBind))?;
                    current.attempted = true;
                    Ok(())
                },
                || {
                    let mut current = current.borrow_mut();
                    let folder = current.storage()?.folder.clone();
                    run_sxs_tool(&folder, false, &mut current.reaped, || {
                        Ok(10.0 - started.elapsed().as_secs_f64())
                    })
                    .map_err(|error| diagnostics::at(error, Stage::SxsStart))
                },
                || Ok(current.borrow().reaped),
                || {
                    let mut current = current.borrow_mut();
                    let logfile = current.logfile()?;
                    current.bound = Some(
                        current
                            .session
                            .bind(&logfile)
                            .map_err(|error| diagnostics::at(error, Stage::SxsBind))?,
                    );
                    (current.observe)(Boundary::AfterBind)
                },
            )?;
        }

        self.deadline()?;
        (self.observe)(Boundary::BeforeAuthorityResume)
    }
}
/// The no-observer authority API remains unchanged; this is an explicit recording job only.
pub fn collect_authority(authority: &Path, volume: &Path) -> Result<CaptureProof> {
    collect_authority_observed(authority, volume, |_| Ok(()))
}
pub fn collect_authority_observed(
    authority: &Path,
    volume: &Path,
    observe: impl FnMut(Boundary) -> Result<()>,
) -> Result<CaptureProof> {
    collect(authority, volume, None, observe)
}
/// Separate bound Rust-consumer control. Genuine Python handoff remains a different subject.
pub fn collect_owned_authority(
    authority: &Path,
    volume: &ScratchVolume,
    view: &NativeRunView,
) -> Result<CaptureProof> {
    volume.require_sxs_view(view)?;
    let result = collect(
        authority,
        Path::new(volume.drive_root()),
        Some(view),
        |_| Ok(()),
    );
    finish(
        result,
        volume.require_sxs_view(view).err().into_iter().collect(),
    )
}
fn collect(
    authority: &Path,
    volume: &Path,
    view: Option<&NativeRunView>,
    observe: impl FnMut(Boundary) -> Result<()>,
) -> Result<CaptureProof> {
    require_host()?;
    let mut capture = Capture {
        volume,
        view,
        observe,
        subject: None,
        authority_reaped: true,
        session: match view {
            Some(view) => SessionOwner::acquire_bound(view),
            None => SessionOwner::acquire_ephemeral(),
        }
        .map_err(|error| diagnostics::at(error, Stage::SxsBind))?,
        storage: None,
        lifecycle: StorageLifecycle::default(),
        package: None,
        bound: None,
        attempted: false,
        reaped: true,
        denied: false,
        stopped: false,
        collector: false,
        stop_attempted: false,
        start: Instant::now(),
    };
    // Share the exact source-derived operation/control/stop/parse ordering with its validator.
    // A failed launch before binding has no capture to parse; stop/close still run independently.
    let completed = std::cell::Cell::new(false);
    let qualified = std::cell::Cell::new(false);
    let mut evidence = String::new();
    let execution = {
        let capture_ref = std::cell::RefCell::new(&mut capture);
        super::execute_capture(
            || {
                // run_observed reaps the authority and descendants before returning an error.
                let result = match view {
                    Some(view) => {
                        run_owned_observed(authority, view, &mut **capture_ref.borrow_mut())
                    }
                    None => run_observed(authority, &mut **capture_ref.borrow_mut()),
                }
                .map_err(|error| {
                    diagnostics::at(super::safe(error, "authority"), Stage::SxsAuthority)
                });
                completed.set(result.is_ok());
                result.map(|_| ())
            },
            || {
                capture_ref
                    .borrow_mut()
                    .control()
                    .map_err(|error| diagnostics::at(error, Stage::SxsControl))?;
                qualified.set(true);
                Ok(())
            },
            || {
                capture_ref
                    .borrow_mut()
                    .stop()
                    .map_err(|error| diagnostics::at(error, Stage::SxsStop))
            },
            |success| {
                let mut current = capture_ref.borrow_mut();
                if current.bound.is_some() {
                    evidence = current
                        .parse(success)
                        .map_err(|error| diagnostics::at(error, Stage::SxsParse))?;
                }
                Ok(())
            },
        )
    };
    let primary = execution.err();
    let completed = completed.get();
    let qualified = qualified.get();
    let proof = CaptureProof {
        starter_reaped: capture.reaped,
        session_stopped: capture.stopped,
        storage_qualified: capture.denied,
        authority_completed: completed,
        evidence,
    };
    let result = (|| {
        if let Some(error) = primary {
            return Err(error);
        }
        ensure!(
            qualified
                && capture.authority_reaped
                && proof.storage_qualified
                && proof.session_stopped
                && proof.starter_reaped,
            "SxS capture qualification incomplete"
        );
        Ok(proof)
    })();
    let errors = capture.close().err().into_iter().collect();
    finish(result, errors)
}
