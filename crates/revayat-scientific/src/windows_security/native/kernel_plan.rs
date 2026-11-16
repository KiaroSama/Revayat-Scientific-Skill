//! Fixed kernel subjects are prepared independently and bound to the same owned run/volume.
use super::{quota_plan::PreparedQuota, *};
use crate::windows_security::{
    kernel_controls::{KernelPlan, Role},
    native::dos_path::existing,
};

pub(super) struct PreparedKernel {
    pub plan: KernelPlan,
    pub directory: tempfile::TempDir,
    pub arguments_sha256: String,
}
impl PreparedKernel {
    pub fn new(
        view: &NativeRunView,
        volume: &ScratchVolume,
        canary: &super::super::state::QuotaCanary,
        role: Role,
        tcp_port: u16,
        udp_port: u16,
    ) -> Result<Self> {
        ensure!(
            matches!(role, Role::KernelPrimary | Role::KernelWall),
            "host cannot prepare a descendant kernel role"
        );
        let PreparedQuota {
            plan: quota,
            directory,
            ..
        } = PreparedQuota::with_canary(view, volume, canary)?;
        let prepared = (|| {
            let system_root = existing(&std::path::PathBuf::from(
                std::env::var_os("SystemRoot").context("SystemRoot is required")?,
            ))?;
            let chromium = existing(&crate::render::discover_browser(None)?)?;
            let plan = KernelPlan {
                role,
                quota,
                system_root,
                chromium,
                tcp_port,
                udp_port,
            };
            plan.validate()?;
            let arguments_sha256 = plan.arguments_digest(role)?;
            view.require()?;
            volume.require()?;
            Ok((plan, arguments_sha256))
        })();
        match prepared {
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
