//! Fixed arguments derived from one real profile, scratch volume and fresh owned image root.
use super::{NativeRunView, ScratchVolume, profile_storage::Storage};
use crate::windows_security::native::dos_path::existing as dos;
use crate::windows_security::quota_controls::{Role, WorkerPlan};
use anyhow::{Result, ensure};
pub(super) struct PreparedQuota {
    pub plan: WorkerPlan,
    pub directory: tempfile::TempDir,
    pub arguments_sha256: String,
}
impl PreparedQuota {
    pub fn new(view: &NativeRunView, volume: &ScratchVolume) -> Result<Self> {
        Self::prepare(view, volume, None, || view.quota_canary())
    }
    pub fn with_canary(
        view: &NativeRunView,
        volume: &ScratchVolume,
        canary: &super::super::state::QuotaCanary,
    ) -> Result<Self> {
        Self::prepare(view, volume, Some(view.state_path()), || {
            canary.require(view)?;
            Ok(canary.path().to_owned())
        })
    }
    fn prepare(
        view: &NativeRunView,
        volume: &ScratchVolume,
        parent: Option<&std::path::Path>,
        canary: impl FnOnce() -> Result<std::path::PathBuf>,
    ) -> Result<Self> {
        view.require()?;
        volume.require()?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("revayat-quota-image-");
        let directory = if let Some(parent) = parent {
            ensure!(
                crate::identity::path_object_id(parent)? == view.state_identity(),
                "kernel image parent is not its owned native state"
            );
            builder.tempdir_in(parent)?
        } else {
            builder.tempdir()?
        };
        let operation = (|| {
            let root = dos(directory.path())?;
            let canary = canary()?;
            let plan = WorkerPlan {
                role: Role::Primary,
                run: view.run_id().into(),
                scratch: volume.drive_root().into(),
                package: view.package_sid().into(),
                auxiliary_image: root.join("revayat-quota-worker.exe"),
                readonly_root: root,
                host_canary: dos(&canary)?,
                profile_ac: dos(&Storage::existing_ac(
                    &view.profile_name(),
                    view.package_sid(),
                )?)?,
            };
            let arguments = plan.arguments(Role::Primary)?;
            let digest = crate::windows_security::image::sha256(arguments.join("\0").as_bytes());
            view.require()?;
            volume.require()?;
            Ok((plan, digest))
        })();
        match operation {
            Ok((plan, arguments_sha256)) => Ok(Self {
                plan,
                directory,
                arguments_sha256,
            }),
            Err(primary) => {
                crate::runtime::with_cleanup(Err(primary), directory.close().map_err(Into::into))
            }
        }
    }
}
