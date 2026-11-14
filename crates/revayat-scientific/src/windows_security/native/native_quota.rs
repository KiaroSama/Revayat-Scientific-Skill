//! Genuine Windows token-owner and NTFS quota controls for a dedicated fixed worker.
//! This leaf cannot mint profile/session tickets or outer process retirement evidence.
use crate::windows_security::quota_controls::{self as contract, OwnerInventory, Role, WorkerPlan};
use anyhow::{Result, ensure};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
#[path = "quota_child.rs"]
mod child;
#[path = "quota_eof.rs"]
mod eof;
#[path = "quota_ffi.rs"]
mod ffi;
#[path = "quota_files.rs"]
mod files;
#[path = "native_kernel.rs"]
mod kernel;
#[path = "quota_private.rs"]
mod private;
#[path = "quota_token.rs"]
mod token;

/// Call only while the actual native completion owner still holds the child suspended.
/// Every finite owner is synchronously persisted and read back by `persist_owner`.
/// The private inventory contains measurements; the caller separately seals its genuine plan ticket.
pub(crate) fn prepare_token(
    process: BorrowedHandle<'_>,
    package: &str,
    persist_owner: impl FnMut(&str) -> Result<()>,
) -> Result<OwnerInventory> {
    token::prepare(process.as_raw_handle(), package, persist_owner)
}

fn observe(plan: &WorkerPlan) -> Result<String> {
    plan.validate()?;
    let inventory = token::current(&plan.package)?;
    let mut root = files::Root::open(&plan.scratch)?;
    let operation = (|| {
        // Bind actual CWD as well as the pinned root before fixed file operations.
        std::env::set_current_dir(&plan.scratch)
            .map_err(|_| anyhow::anyhow!("quota worker could not enter owned scratch"))?;
        let cwd = std::env::current_dir()
            .map_err(|_| anyhow::anyhow!("quota worker current directory query failed"))?;
        ensure!(
            cwd == std::path::Path::new(&plan.scratch),
            "quota worker current directory differs from owned drive root"
        );
        root.require()?;
        files::positive(&root, &inventory, plan.role == Role::TokenChild)?;
        match plan.role {
            Role::TokenChild => contract::token_record(&inventory),
            Role::Primary => {
                child::observe(plan, &inventory)?;
                private::controls(&root, plan, &inventory)?;
                eof::controls(&root)?;
                root.require()?;
                // A fresh token inventory detects unexpected owner/privilege changes after the controls.
                ensure!(
                    token::current(&plan.package)?.digest() == inventory.digest(),
                    "quota primary token inventory changed during native controls"
                );
                Ok(contract::success(plan, &inventory))
            }
        }
    })();
    let operation = ffi::combine(operation, root.close());
    let registry_cleanup_failed = registry_authority::protocol::take_cleanup_failure();
    ffi::combine(
        operation,
        if ffi::cleanup_ok() && !registry_cleanup_failed {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "quota native cleanup uncertainty prevents a passed record"
            ))
        },
    )
}

pub(crate) fn worker_main() -> i32 {
    let mut kernel_role = false;
    let result: Result<()> = (|| {
        let image = std::env::current_exe()
            .map_err(|_| anyhow::anyhow!("quota worker image lookup failed"))?;
        ensure!(
            image.file_name() == Some(std::ffi::OsStr::new("revayat-quota-worker.exe")),
            "quota worker fixed image name differs"
        );
        let args = std::env::args_os()
            .skip(1)
            .take(13)
            .map(|arg| {
                arg.into_string()
                    .map_err(|_| anyhow::anyhow!("quota worker argument is not Unicode"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            args.len() <= 12,
            "fixed worker argument count exceeds bound"
        );
        kernel_role = args
            .first()
            .is_some_and(|arg| crate::windows_security::kernel_controls::Role::parse(arg).is_ok());
        let result = if kernel_role {
            kernel::observe(&crate::windows_security::kernel_controls::KernelPlan::parse(&args)?)?
        } else {
            observe(&WorkerPlan::parse(&args)?)?
        };
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        out.write_all(result.as_bytes())
            .map_err(|_| anyhow::anyhow!("quota control result write failed"))?;
        out.flush()
            .map_err(|_| anyhow::anyhow!("quota control result flush failed"))?;
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(_) => {
            // Never format native errors or their causes: paths, token SIDs and captured child bytes stay private.
            if kernel_role {
                eprintln!("WINDOWS_KERNEL_FAILURE phase=native kind=control_or_cleanup");
            } else {
                eprintln!("WINDOWS_QUOTA_FAILURE phase=native kind=control_or_cleanup");
            }
            1
        }
    }
}
