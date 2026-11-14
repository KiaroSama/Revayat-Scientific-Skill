//! Fixed arguments derived from one real profile, scratch volume and fresh owned image root.
use super::{NativeRunView, ScratchVolume, profile_storage::Storage};
use crate::windows_security::native::dos_path::existing as dos;
use crate::windows_security::quota_controls::{Role, WorkerPlan};
use anyhow::Result;
pub(super) struct PreparedQuota {
    pub plan: WorkerPlan,
    pub directory: tempfile::TempDir,
    pub arguments_sha256: String,
}
impl PreparedQuota {
    pub fn new(view: &NativeRunView, volume: &ScratchVolume) -> Result<Self> {
        view.require()?;
        volume.require()?;
        let directory = tempfile::Builder::new()
            .prefix("revayat-quota-image-")
            .tempdir()?;
        let operation = (|| {
            let root = dos(directory.path())?;
            let canary = view.quota_canary()?;
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
