//! Actual ordinary, sparse logical-EOF and aggregate owner-quota controls.
use super::{
    ffi::*,
    files::{self, Root},
};
use crate::windows_security::quota_controls::QUOTA_BYTES;
use anyhow::{Result, ensure};
use std::ptr::null_mut;
fn denied(code: Option<i32>) -> bool {
    matches!(code, Some(112 | 39 | 1816))
}
pub(super) fn sparse(handle: Raw) -> Result<()> {
    let mut returned = 0;
    // SAFETY: fixed FSCTL_SET_SPARSE with no input sets the sparse bit on this owned write handle.
    ensure!(
        unsafe {
            DeviceIoControl(
                handle,
                0x900c4,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        } != 0,
        "native quota sparse control failed"
    );
    Ok(())
}
fn seek(handle: Raw, length: u64) -> Result<()> {
    let mut position = 0;
    // SAFETY: bounded nonnegative file offset and writable position output.
    ensure!(
        unsafe { SetFilePointerEx(handle, length as i64, &mut position, 0) } != 0
            && position == length as i64,
        "native quota EOF seek failed"
    );
    Ok(())
}
pub(super) fn native(handle: Raw, make_sparse: bool) -> Result<()> {
    if make_sparse {
        sparse(handle)?;
    }
    seek(handle, 1024)?;
    // SAFETY: live write-capable file handle positioned within the admitted 16MiB bound.
    ensure!(
        unsafe { SetEndOfFile(handle) } != 0,
        "native permitted quota EOF failed"
    );
    seek(handle, QUOTA_BYTES + 1)?;
    let success = unsafe { SetEndOfFile(handle) };
    let error = unsafe { GetLastError() };
    ensure!(
        success == 0 && denied(Some(error as i32)),
        "native excessive quota EOF was not denied by space/quota policy"
    );
    seek(handle, 0)?;
    ensure!(
        unsafe { SetEndOfFile(handle) } != 0,
        "native quota file reset failed"
    );
    Ok(())
}
pub(super) fn controls(root: &Root) -> Result<()> {
    for make_sparse in [false, true] {
        let mut leaf = root.create(if make_sparse {
            "quota-sparse"
        } else {
            "quota-ordinary"
        })?;
        let result = (|| {
            leaf.require()?;
            native(leaf.handle.0, make_sparse)?;
            if make_sparse {
                sparse(leaf.handle.0)?;
            }
            let result = files::file(leaf.handle.0).set_len(QUOTA_BYTES + 1);
            ensure!(
                result
                    .as_ref()
                    .is_err_and(|error| denied(error.raw_os_error())),
                "standard file logical EOF was not denied by space/quota policy"
            );
            Ok(())
        })();
        combine(result, leaf.close())?;
    }
    let mut leaves = Vec::new();
    let result = (|| {
        for index in 0..2 {
            leaves.push(root.create(if index == 0 {
                "quota-aggregate-0"
            } else {
                "quota-aggregate-1"
            })?);
            let leaf = leaves.last().expect("just pushed fixed leaf");
            leaf.require()?;
            sparse(leaf.handle.0)?;
            let result = files::file(leaf.handle.0).set_len(9 * 1024 * 1024);
            if index == 0 {
                ensure!(
                    result.is_ok(),
                    "aggregate quota denied the first 9MiB sparse file"
                );
            } else {
                ensure!(
                    result
                        .as_ref()
                        .is_err_and(|error| denied(error.raw_os_error())),
                    "aggregate quota admitted two 9MiB sparse files or denied for a different reason"
                );
            }
        }
        Ok(())
    })();
    combine(result, all(leaves.iter_mut().map(|leaf| leaf.close())))
}
