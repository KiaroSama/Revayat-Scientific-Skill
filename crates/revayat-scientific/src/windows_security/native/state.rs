//! Trusted outer-owned state. Locators and immutable intent are never admission or reaping proof.
use super::authority::{Descriptor, wide};
use super::*;
use crate::identity::{self, ObjectId};
use crate::windows_security::{
    activation::Failures,
    policy::{Acl, Descriptor as Relative},
    sxs::current_user_sid,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::{ffi::OsString, path::PathBuf};
#[path = "state_io.rs"]
mod io;
#[cfg(test)]
use io::private_sddl;
use io::{Pin, anchors, create_private, private, write_new};
fn finish<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(error)) => Err(Failures {
            errors: vec![primary, error],
        }
        .into()),
    }
}
fn identifier(text: &str, length: usize) -> Result<()> {
    ensure!(
        text.len() == length
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid native run identity"
    );
    Ok(())
}
fn identity_text(id: ObjectId) -> String {
    format!("{:016x}:{:016x}", id.volume, id.index)
}
fn parse_identity(text: &str) -> Result<ObjectId> {
    let fields = text.split(':').collect::<Vec<_>>();
    ensure!(fields.len() == 2, "invalid native state identity");
    identifier(fields[0], 16)?;
    identifier(fields[1], 16)?;
    Ok(ObjectId {
        volume: u64::from_str_radix(fields[0], 16)?,
        index: u64::from_str_radix(fields[1], 16)?,
    })
}
fn intent_text(name: &str, package: &str) -> Result<String> {
    let run = name
        .strip_prefix("Scientific.Security.")
        .context("invalid owned profile name")?;
    identifier(run, 32)?;
    crate::windows_security::package_sid(package)?;
    Ok(format!("{name}\n{package}\nintent\n"))
}
fn require_intent(bytes: &[u8], name: &str, package: &str) -> Result<()> {
    ensure!(
        bytes.len() <= 512 && bytes == intent_text(name, package)?.as_bytes(),
        "profile cleanup ownership receipt differs"
    );
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    run: String,
    binding: String,
    identity: ObjectId,
    host: String,
    package: String,
}
pub struct NativeRunOwner {
    pub(super) view: NativeRunView,
    manifest: Manifest,
    closed: bool,
    uncertain: bool,
    pub(super) recovered: bool,
}
pub struct NativeRunView {
    manifest: Manifest,
    state: PathBuf,
    pins: Vec<Pin>,
    ancestors: Vec<Pin>,
}
fn canonical_json(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut value = serde_json::to_vec(manifest)?;
    value.push(b'\n');
    ensure!(value.len() <= 4096, "native state manifest exceeds bound");
    Ok(value)
}
fn nonce(length: usize) -> Result<String> {
    let mut bytes = vec![0; length];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("native run nonce failed"))?;
    let value = bytes.iter().map(|b| format!("{b:02x}")).collect();
    bytes.fill(0);
    Ok(value)
}
impl NativeRunOwner {
    pub fn create(root: &Path) -> Result<Self> {
        plain_path(root)?;
        let root = root.canonicalize()?;
        ensure!(root.is_dir(), "native repository root unavailable");
        let host = current_user_sid()?;
        let run = nonce(16)?;
        let binding = nonce(32)?;
        let name = format!("Scientific.Security.{run}");
        let package = authority::assigned_package(&name)?;
        let scratch = root.join(".scratch");
        if !scratch.try_exists()? {
            create_private(&scratch, &host)?;
        }
        plain_path(&scratch)?;
        let state = scratch.join(format!("security-windows-{run}"));
        let ancestors = anchors(&state)?;
        create_private(&state, &host)?;
        let pin = Pin::open(&state, true)?;
        private(pin.file.as_ref().unwrap(), &host, true)?;
        let manifest = Manifest {
            version: 1,
            run,
            binding,
            identity: pin.id,
            host,
            package,
        };
        let view = NativeRunView {
            manifest: manifest.clone(),
            state,
            pins: vec![pin],
            ancestors,
        };
        let mut owner = Self {
            view,
            manifest,
            closed: false,
            uncertain: false,
            recovered: false,
        };
        owner.write_private("owner.json", &canonical_json(&owner.manifest)?)?;
        let intent = intent_text(&name, &owner.manifest.package)?;
        owner.write_private("profile.receipt", intent.as_bytes())?;
        owner.view.require()?;
        Ok(owner)
    }
    fn write_private(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            matches!(name, "owner.json" | "profile.receipt") && bytes.len() <= 4096,
            "unsupported native durable record"
        );
        let path = self.view.state.join(name);
        write_new(&path, &self.manifest.host, bytes)?;
        let pin = Pin::open(&path, false)?;
        self.view.pins.push(pin);
        private(
            self.view.pins.last().unwrap().file.as_ref().unwrap(),
            &self.manifest.host,
            false,
        )
    }
    pub fn run_id(&self) -> &str {
        &self.manifest.run
    }
    pub fn state_path(&self) -> &Path {
        &self.view.state
    }
    pub fn state_identity(&self) -> ObjectId {
        self.manifest.identity
    }
    pub fn recovery_binding(&self) -> &str {
        &self.manifest.binding
    }
    pub fn binding(&self) -> &str {
        self.recovery_binding()
    }
    pub fn worker_arguments(&self) -> Vec<OsString> {
        vec![
            self.view.state.as_os_str().to_owned(),
            self.manifest.run.clone().into(),
            self.manifest.binding.clone().into(),
            identity_text(self.manifest.identity).into(),
        ]
    }
    pub fn recover(&mut self, proof: &crate::runtime::ReapedProcessTree) -> Result<()> {
        super::recovery::recover_profile(self, proof)
    }
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            ensure!(!self.uncertain, "native state close remains uncertain");
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        for pin in self
            .view
            .pins
            .iter_mut()
            .rev()
            .chain(self.view.ancestors.iter_mut().rev())
        {
            if let Err(error) = pin.close() {
                errors.push(error);
            }
        }
        self.uncertain |= !errors.is_empty();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    }
}
impl Drop for NativeRunOwner {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
impl NativeRunView {
    pub fn from_arguments(args: &[OsString]) -> Result<Self> {
        ensure!(
            args.len() == 4,
            "native worker locator requires four fields"
        );
        let state = PathBuf::from(&args[0]);
        let run = args[1].to_str().context("native run encoding")?;
        let binding = args[2].to_str().context("native binding encoding")?;
        let identity = parse_identity(args[3].to_str().context("native state identity encoding")?)?;
        identifier(run, 32)?;
        identifier(binding, 64)?;
        plain_path(&state)?;
        ensure!(
            state.is_absolute()
                && state.file_name().and_then(|x| x.to_str())
                    == Some(format!("security-windows-{run}").as_str())
                && state
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|x| x.to_str())
                    == Some(".scratch"),
            "native state locator shape differs"
        );
        let ancestors = anchors(&state)?;
        let root = Pin::open(&state, true)?;
        ensure!(
            root.id == identity,
            "native state locator object identity differs"
        );
        let mut record = Pin::open(&state.join("owner.json"), false)?;
        let bytes = record.bytes()?;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        ensure!(
            canonical_json(&manifest)? == bytes
                && manifest.version == 1
                && manifest.run == run
                && manifest.binding == binding
                && manifest.identity == identity
                && manifest.host == current_user_sid()?,
            "native owner manifest binding differs"
        );
        crate::windows_security::package_sid(&manifest.package)?;
        ensure!(
            authority::assigned_package(&format!("Scientific.Security.{run}"))? == manifest.package,
            "native profile SID/name binding differs"
        );
        private(root.file.as_ref().unwrap(), &manifest.host, true)?;
        private(record.file.as_ref().unwrap(), &manifest.host, false)?;
        let receipt = Pin::open(&state.join("profile.receipt"), false)?;
        let view = Self {
            manifest,
            state,
            pins: vec![root, record, receipt],
            ancestors,
        };
        view.require()?;
        Ok(view)
    }
    pub fn require(&self) -> Result<()> {
        ensure!(self.pins.len() == 3, "native durable state pins incomplete");
        ensure!(
            current_user_sid()? == self.manifest.host,
            "native durable state current host differs"
        );
        for pin in &self.ancestors {
            pin.require()?;
        }
        for pin in &self.pins {
            pin.require()?;
            private(
                pin.file.as_ref().context("native state pin closed")?,
                &self.manifest.host,
                pin.directory,
            )?;
        }
        let bytes = self.pins[2].read_bytes()?;
        require_intent(&bytes, &self.profile_name(), &self.manifest.package)
    }
    pub fn run_id(&self) -> &str {
        &self.manifest.run
    }
    pub fn profile_name(&self) -> String {
        format!("Scientific.Security.{}", self.manifest.run)
    }
    pub fn package_sid(&self) -> &str {
        &self.manifest.package
    }
    pub fn state_identity(&self) -> ObjectId {
        self.manifest.identity
    }
    pub(super) fn begin_profile(&self) -> Result<()> {
        self.require()?;
        for name in ["profile.started", "profile.created", "profile.not-created"] {
            ensure!(
                !self.state.join(name).try_exists()?,
                "profile creation phase already recorded"
            );
        }
        self.write_phase("profile.started", b"started\n")
    }
    pub(super) fn profile_result(&self, status: i32) -> Result<()> {
        self.require()?;
        if status == 0 {
            self.write_phase("profile.created", b"created\n")
        } else {
            self.write_phase("profile.not-created", b"not-created\n")
        }
    }
    fn write_phase(&self, name: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            matches!(
                name,
                "profile.started" | "profile.created" | "profile.not-created"
            ),
            "unsupported owned profile phase"
        );
        write_new(&self.state.join(name), &self.manifest.host, bytes)
    }
    pub(super) fn recovery_disposition(&self) -> Result<bool> {
        self.require()?;
        let read = |name: &str, expected: &[u8]| -> Result<bool> {
            let path = self.state.join(name);
            if !path.try_exists()? {
                return Ok(false);
            }
            let mut pin = Pin::open(&path, false)?;
            let result = (|| {
                private(pin.file.as_ref().unwrap(), &self.manifest.host, false)?;
                let bytes = pin.bytes()?;
                ensure!(bytes == expected, "owned profile phase differs");
                Ok(true)
            })();
            finish(result, pin.close())
        };
        let started = read("profile.started", b"started\n")?;
        let created = read("profile.created", b"created\n")?;
        let not_created = read("profile.not-created", b"not-created\n")?;
        ensure!(
            !(created && not_created) && (started || (!created && !not_created)),
            "owned profile phase sequence differs"
        );
        // A flushed start follows exact new-package preabsence and owns crash-window recovery.
        Ok(started && !not_created)
    }
}
#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
