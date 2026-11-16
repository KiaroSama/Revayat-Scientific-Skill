//! Actual closed environment, protected writes, private canary and profile-directory observations.
use super::super::{ffi::*, files};
use crate::windows_security::kernel_controls::KernelPlan;
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    path::Path,
    ptr::{null, null_mut},
};
pub(super) fn environment(plan: &KernelPlan) -> Result<()> {
    let mut actual = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        let name = name
            .into_string()
            .map_err(|_| anyhow::anyhow!("kernel environment name is not Unicode"))?
            .to_ascii_uppercase();
        let value = value
            .into_string()
            .map_err(|_| anyhow::anyhow!("kernel environment value is not Unicode"))?;
        ensure!(
            actual.insert(name, value).is_none(),
            "kernel environment contains case-alias names"
        );
    }
    ensure!(
        actual == plan.environment()?
            && actual.len() == 13
            && !actual.contains_key("SCIENTIFIC_AMBIENT_CANARY"),
        "kernel exact environment differs from closed plan"
    );
    ensure!(
        std::env::current_dir().map_err(|_| anyhow::anyhow!("kernel CWD query failed"))?
            == Path::new(&plan.quota.scratch),
        "kernel actual CWD differs from scratch"
    );
    Ok(())
}
fn denied(path: &Path, read: bool) -> Result<()> {
    let path = wide(
        path.to_str()
            .ok_or_else(|| anyhow::anyhow!("kernel fixed denied path is not Unicode"))?,
    );
    // SAFETY: fixed authored read-only/canary leaf; no arbitrary target is admitted.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            if read { 0x80000000 } else { 0x40000000 },
            7,
            null(),
            if read { 3 } else { 2 },
            0x80,
            null_mut(),
        )
    };
    let error = unsafe { GetLastError() };
    if !raw.is_null() && raw as isize != -1 {
        let mut owner = Owned::new(raw)?;
        return combine(
            Err(anyhow::anyhow!(
                "kernel protected file operation was permitted"
            )),
            owner.close(),
        );
    }
    ensure!(
        raw as isize == -1
            && std::io::Error::from_raw_os_error(error as i32).kind()
                == std::io::ErrorKind::PermissionDenied,
        "kernel protected file operation failed without access denial"
    );
    Ok(())
}
pub(super) fn controls(plan: &KernelPlan) -> Result<()> {
    let image =
        std::env::current_exe().map_err(|_| anyhow::anyhow!("kernel fixed image query failed"))?;
    for parent in [
        &plan.quota.readonly_root,
        image
            .parent()
            .ok_or_else(|| anyhow::anyhow!("kernel image parent absent"))?,
        plan.quota
            .auxiliary_image
            .parent()
            .ok_or_else(|| anyhow::anyhow!("kernel auxiliary parent absent"))?,
        plan.quota
            .readonly_root
            .parent()
            .ok_or_else(|| anyhow::anyhow!("kernel prepared parent absent"))?,
    ] {
        denied(&parent.join("forbidden-write"), false)?;
    }
    denied(&plan.quota.host_canary, true)?;
    let profile = plan
        .quota
        .profile_ac
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("kernel profile path is not Unicode"))?;
    let mut directory = open(profile, 0x80, 7, 3, 0x02200000, null())?;
    let result = (|| {
        files::identity(directory.0, true)?;
        denied(
            &plan.quota.profile_ac.join("forbidden-profile-write"),
            false,
        )?;
        denied(
            &plan
                .quota
                .profile_ac
                .parent()
                .ok_or_else(|| anyhow::anyhow!("kernel profile parent absent"))?
                .join("forbidden-profile-parent-write"),
            false,
        )
    })();
    combine(result, directory.close())
}
