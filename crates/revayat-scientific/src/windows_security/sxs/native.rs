//! One fixed standard-tool capture around the existing qualified LPAC authority lifecycle.
//! Host collector evidence proves recording, never child visibility or an original failing call.
use super::{
    SessionSnapshot, native_identity::finish, native_session::SessionOwner, native_storage::Storage,
};
use crate::windows_security::{
    activation::native::{ManifestRole, observe_manifest, require_host},
    native::{AuthorityObserver, run_observed, run_sxs_tool},
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
    observe: F,
    subject: Option<std::path::PathBuf>,
    authority_reaped: bool,
    session: SessionOwner,
    storage: Option<Storage>,
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
        let result = if self.attempted {
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
        let logfile = storage.require("capture.etl")?;
        let length = std::fs::metadata(&logfile)?.len();
        ensure!(
            (1..=8_388_608).contains(&length),
            "SxS ETL length outside bound"
        );
        storage.write("capture.txt", b"")?;
        ensure!(
            storage.read("capture.txt", 0)?.is_empty(),
            "SxS parse seed is not empty"
        );
        let mut parser_reaped = true;
        let parsing = run_sxs_tool(&storage.folder, true, &mut parser_reaped);
        self.reaped &= parser_reaped;
        parsing?;
        ensure!(parser_reaped, "SxS parser was not reaped");
        let mut bytes = storage.read("capture.txt", 1_048_576)?;
        let subject = self
            .subject
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS actual authority subject was not bound"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("SxS authority path encoding differs"))?;
        let control = storage.path("collector.manifest")?;
        let result = if success {
            super::success_evidence(
                &bytes,
                subject,
                control
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("SxS control path encoding differs"))?,
            )
        } else {
            super::failure_evidence(&bytes, subject)
        };
        bytes.fill(0);
        result
    }
    fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        // Never delete live collector/parser storage. The outer owner must recover uncertain state.
        if self.stopped
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
        self.package = Some(package.to_owned());
        self.storage = Some(Storage::prepare(self.volume, package)?);
        self.storage()?.require_seed()?;
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
        self.storage()?.deny(process, package)?;
        self.denied = true;
        (self.observe)(Boundary::AfterDenial)?;
        let logfile = self.logfile()?;
        self.session.preabsent(&logfile)?;
        self.attempted = true;
        let folder = self.storage()?.folder.clone();
        run_sxs_tool(&folder, false, &mut self.reaped)?;
        ensure!(self.reaped, "SxS starter was not reaped");
        self.bound = Some(self.session.bind(&logfile)?);
        (self.observe)(Boundary::AfterBind)?;
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
    require_host()?;
    let mut capture = Capture {
        volume,
        observe,
        subject: None,
        authority_reaped: true,
        session: SessionOwner::acquire()?,
        storage: None,
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
                let result = run_observed(authority, &mut **capture_ref.borrow_mut())
                    .map_err(|error| super::safe(error, "authority"));
                completed.set(result.is_ok());
                result.map(|_| ())
            },
            || {
                capture_ref.borrow_mut().control()?;
                qualified.set(true);
                Ok(())
            },
            || capture_ref.borrow_mut().stop(),
            |success| {
                let mut current = capture_ref.borrow_mut();
                if current.bound.is_some() {
                    evidence = current.parse(success)?;
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
