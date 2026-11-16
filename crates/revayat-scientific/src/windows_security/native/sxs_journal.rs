//! Protected, identity-bound ETW intent and bound records. Records never attest an event.
use super::super::{
    NativeRunView,
    scratch_access::{self as access, Identity, Owned},
};
use crate::{
    identity::ObjectId,
    windows_security::{
        quota_controls::Sid,
        sxs::{self, SessionSnapshot},
    },
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
const INTENT: &str = "sxs-trace.intent";
const BOUND: &str = "sxs-trace.bound";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    run: String,
    state: ObjectId,
    package: String,
    host: String,
    text: String,
    root: Identity,
    folder: Identity,
    etl: Identity,
    native_root: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    version: u32,
    intent_sha256: String,
    text: String,
}
fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut data = serde_json::to_vec(value)?;
    data.push(b'\n');
    ensure!(data.len() <= 4096, "SxS durable record exceeds bound");
    Ok(data)
}
fn present(state: &Path, name: &str) -> Result<bool> {
    let path = state.join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !crate::identity::is_link(&path)?,
                "SxS durable record is not a plain file"
            );
            crate::windows_security::plain_path(&path)?;
            Ok(true)
        }
    }
}
fn read<T: for<'de> Deserialize<'de> + Serialize>(
    view: &NativeRunView,
    host: &str,
    name: &str,
) -> Result<Option<T>> {
    view.require()?;
    if !present(view.state_path(), name)? {
        return Ok(None);
    }
    let data = access::read_record(view.state_path(), host, name)?
        .ok_or_else(|| anyhow::anyhow!("SxS durable record disappeared"))?;
    ensure!(data.len() <= 4096, "SxS durable record exceeds bound");
    let value = serde_json::from_slice(&data)?;
    ensure!(
        bytes(&value)? == data,
        "SxS durable record is not canonical"
    );
    view.require()?;
    Ok(Some(value))
}
struct Pins {
    root: Owned,
    folder: Owned,
    etl: Owned,
}
impl Pins {
    fn open(volume: &str, run: &str) -> Result<Self> {
        let folder = PathBuf::from(format!("{volume}sxs-trace-{run}"));
        let etl = folder.join("capture.etl");
        crate::windows_security::plain_path(&folder)?;
        crate::windows_security::plain_path(&etl)?;
        let mut root = Owned::open(volume, 0x20080, 3, 0x2200000)?;
        let mut directory = match Owned::open(&folder, 0x20080, 3, 0x2200000) {
            Ok(file) => file,
            Err(primary) => return access::combine(Err(primary), root.close()),
        };
        let etl = match Owned::open(&etl, 0x20080, 3, 0x200000) {
            Ok(file) => file,
            Err(primary) => {
                return access::combine(
                    access::combine(Err(primary), directory.close()),
                    root.close(),
                );
            }
        };
        Ok(Self {
            root,
            folder: directory,
            etl,
        })
    }
    fn require(&self, intent: &Intent) -> Result<()> {
        ensure!(
            access::identity(self.root.0, true)? == intent.root
                && access::identity(self.folder.0, true)? == intent.folder
                && access::identity(self.etl.0, false)? == intent.etl
                && access::name(self.root.0)? == intent.native_root,
            "SxS durable storage object identity differs"
        );
        let suffix = format!("sxs-trace-{}", intent.run);
        ensure!(
            access::name(self.folder.0)? == format!("{}{suffix}", intent.native_root)
                && access::name(self.etl.0)?
                    == format!("{}{suffix}\\capture.etl", intent.native_root),
            "SxS durable storage native name differs"
        );
        let user = Sid::text(&intent.host)?;
        let package = Sid::text(&intent.package)?;
        sxs::storage::require_policy(
            &access::security(self.folder.0, 5)?,
            true,
            user.bytes(),
            package.bytes(),
        )?;
        sxs::storage::require_policy(
            &access::security(self.etl.0, 5)?,
            false,
            user.bytes(),
            package.bytes(),
        )
    }
    fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        for handle in [&mut self.etl, &mut self.folder, &mut self.root] {
            if let Err(error) = handle.close() {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::windows_security::activation::Failures { errors }.into())
        }
    }
}
struct Live {
    intent: Intent,
    pins: Pins,
    bound: Option<Bound>,
}
/// A borrow of the actual immutable run view, never a caller-created cleanup certificate.
pub(crate) struct SxsJournal<'a> {
    view: &'a NativeRunView,
    host: String,
    live: Option<Live>,
}
impl<'a> SxsJournal<'a> {
    pub(crate) fn has_records(view: &NativeRunView) -> Result<bool> {
        view.require()?;
        Ok(present(view.state_path(), INTENT)? || present(view.state_path(), BOUND)?)
    }
    pub(crate) fn new(view: &'a NativeRunView) -> Result<Self> {
        view.require()?;
        let host = sxs::current_user_sid()?;
        ensure!(
            !present(view.state_path(), INTENT)? && !present(view.state_path(), BOUND)?,
            "SxS durable ownership already pending"
        );
        Ok(Self {
            view,
            host,
            live: None,
        })
    }
    fn validate(&self, intent: &Intent) -> Result<String> {
        self.view.require()?;
        ensure!(
            intent.version == 1
                && intent.run == self.view.run_id()
                && intent.state == self.view.state_identity()
                && intent.package == self.view.package_sid()
                && intent.host == self.host,
            "SxS durable ownership belongs to a different run"
        );
        let volume = sxs::intent_volume(&intent.text, &intent.run)?;
        ensure!(
            volume.as_bytes()[0].is_ascii_uppercase(),
            "SxS durable volume case differs"
        );
        let suffix = intent
            .native_root
            .strip_prefix("\\Device\\HarddiskVolume")
            .and_then(|value| value.strip_suffix('\\'))
            .ok_or_else(|| anyhow::anyhow!("SxS durable native root differs"))?;
        ensure!(
            !suffix.is_empty() && suffix.len() <= 20 && suffix.bytes().all(|b| b.is_ascii_digit()),
            "SxS durable native root differs"
        );
        Ok(format!("{volume}sxs-trace-{}\\capture.etl", intent.run))
    }
    pub(crate) fn intent(&mut self, logfile: &str) -> Result<()> {
        ensure!(self.live.is_none(), "SxS intent already attempted");
        self.view.require()?;
        ensure!(logfile.len() >= 3, "SxS durable logfile is invalid");
        let volume = logfile
            .get(..3)
            .ok_or_else(|| anyhow::anyhow!("SxS logfile encoding differs"))?;
        let text = sxs::intent_text(self.view.run_id(), volume)?;
        let mut pins = Pins::open(volume, self.view.run_id())?;
        let operation = (|| {
            let intent = Intent {
                version: 1,
                run: self.view.run_id().into(),
                state: self.view.state_identity(),
                package: self.view.package_sid().into(),
                host: self.host.clone(),
                text,
                root: access::identity(pins.root.0, true)?,
                folder: access::identity(pins.folder.0, true)?,
                etl: access::identity(pins.etl.0, false)?,
                native_root: access::name(pins.root.0)?,
            };
            ensure!(
                self.validate(&intent)? == logfile,
                "SxS durable logfile differs from run"
            );
            pins.require(&intent)?;
            access::write_record(self.view.state_path(), &self.host, INTENT, &bytes(&intent)?)?;
            self.view.require()?;
            Ok(intent)
        })();
        match operation {
            Ok(intent) => {
                self.live = Some(Live {
                    intent,
                    pins,
                    bound: None,
                });
                Ok(())
            }
            Err(primary) => access::combine(Err(primary), pins.close()),
        }
    }
    pub(crate) fn bind(&mut self, snapshot: &SessionSnapshot) -> Result<()> {
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS bound session lacks intent"))?;
        ensure!(
            live.bound.is_none() && snapshot.path == self.validate(&live.intent)?,
            "SxS bound session differs from intent"
        );
        live.pins.require(&live.intent)?;
        snapshot.require_capture()?;
        let record = Bound {
            version: 1,
            intent_sha256: crate::windows_security::image::sha256(&bytes(&live.intent)?),
            text: sxs::bound_text(self.view.run_id(), snapshot)?,
        };
        access::write_record(self.view.state_path(), &self.host, BOUND, &bytes(&record)?)?;
        self.live.as_mut().unwrap().bound = Some(record);
        self.view.require()
    }
    pub(crate) fn close(&mut self) -> Result<()> {
        self.live.as_mut().map_or(Ok(()), |live| live.pins.close())
    }
    pub(crate) fn pending(&self) -> Result<bool> {
        Ok(present(self.view.state_path(), INTENT)? || present(self.view.state_path(), BOUND)?)
    }
    pub(crate) fn expected(&self, logfile: &str) -> Result<Option<SessionSnapshot>> {
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SxS journal lacks live intent"))?;
        ensure!(
            self.validate(&live.intent)? == logfile,
            "SxS journal logfile changed"
        );
        live.pins.require(&live.intent)?;
        live.bound
            .as_ref()
            .map(|bound| sxs::decode_bound(&bound.text, self.view.run_id(), logfile))
            .transpose()
    }
    /// Invoked only after actual stop and both enumeration/query absence checks succeeded.
    pub(crate) fn stopped(&mut self) -> Result<()> {
        let live = self
            .live
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("SxS journal lacks stopped intent"))?;
        live.pins.require(&live.intent)?;
        if let Some(bound) = &live.bound {
            access::remove_record(self.view.state_path(), &self.host, BOUND, &bytes(bound)?)?;
        }
        access::remove_record(
            self.view.state_path(),
            &self.host,
            INTENT,
            &bytes(&live.intent)?,
        )?;
        let closed = live.pins.close();
        self.live.take();
        access::combine(closed, self.view.require())
    }
    pub(crate) fn recovery(view: &'a NativeRunView) -> Result<Option<(Self, String)>> {
        view.require()?;
        let host = sxs::current_user_sid()?;
        let intent: Option<Intent> = read(view, &host, INTENT)?;
        let bound: Option<Bound> = read(view, &host, BOUND)?;
        let Some(intent) = intent else {
            ensure!(bound.is_none(), "SxS bound record lacks intent");
            return Ok(None);
        };
        let mut journal = Self {
            view,
            host,
            live: None,
        };
        let logfile = journal.validate(&intent)?;
        if let Some(bound) = &bound {
            ensure!(
                bound.version == 1
                    && bound.intent_sha256
                        == crate::windows_security::image::sha256(&bytes(&intent)?),
                "SxS bound ownership identity differs"
            );
            sxs::decode_bound(&bound.text, view.run_id(), &logfile)?;
        }
        let volume = sxs::intent_volume(&intent.text, view.run_id())?;
        let mut pins = Pins::open(&volume, view.run_id())?;
        if let Err(primary) = pins.require(&intent) {
            return access::combine(Err(primary), pins.close());
        }
        journal.live = Some(Live {
            intent,
            pins,
            bound,
        });
        Ok(Some((journal, logfile)))
    }
}

impl super::super::NativeRunOwner {
    pub(crate) fn sxs_recovery_view(
        &self,
        proof: &crate::runtime::ReapedProcessTree,
    ) -> Result<&NativeRunView> {
        proof.require_binding(self.recovery_binding())?;
        ensure!(!self.recovered, "profile recovery already completed");
        self.view.require()?;
        Ok(&self.view)
    }
}
impl super::super::ScratchVolume {
    pub(crate) fn require_sxs_view(&self, view: &NativeRunView) -> Result<()> {
        view.require()?;
        self.require()?;
        ensure!(
            self.intent.run == view.run_id()
                && self.intent.state == view.state_identity()
                && self.intent.package == view.package_sid(),
            "SxS scratch volume belongs to a different run"
        );
        Ok(())
    }
}
