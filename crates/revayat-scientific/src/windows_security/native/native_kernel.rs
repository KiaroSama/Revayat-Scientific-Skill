//! Actual fixed kernel actors. No host gate, natural retirement or expected-wall proof is minted.
use super::{eof, ffi::*, files, private, token};
use crate::windows_security::{
    kernel_controls::{self as contract, KernelPlan, Role},
    quota_controls,
};
use anyhow::{Result, ensure};
#[path = "kernel_child_controls.rs"]
mod child_controls;
#[path = "kernel_children.rs"]
mod children;
#[path = "kernel_files.rs"]
mod filesystem;
#[path = "kernel_job.rs"]
mod job;
#[path = "kernel_network.rs"]
mod network;
#[path = "kernel_registry.rs"]
mod registry;

pub(super) fn observe(plan: &KernelPlan) -> Result<String> {
    plan.validate()?;
    // These fixed bodies have no extra assertions whose failure could masquerade
    // as a PID denial. Their parent already attested the actual token/job/stds
    // while suspended. In particular, an admitted PidExtra must exit zero.
    match plan.role {
        Role::PidHold => {
            std::thread::sleep(std::time::Duration::from_secs(10));
            return Ok(String::new());
        }
        Role::PidExtra => return Ok(String::new()),
        Role::WallHold => {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return Ok(String::new());
        }
        _ => {}
    }
    let inventory = token::current(&plan.quota.package)?;
    std::env::set_current_dir(&plan.quota.scratch)
        .map_err(|_| anyhow::anyhow!("kernel actor could not enter owned scratch"))?;
    filesystem::environment(plan)?;
    job::require()?;
    ensure!(
        cleanup_ok() && !registry_authority::protocol::take_cleanup_failure(),
        "kernel initial native handle cleanup is uncertain"
    );
    if plan.role == Role::KernelWall {
        return child_controls::wall(plan, &inventory);
    }
    let mut root = files::Root::open(&plan.quota.scratch)?;
    let operation = (|| {
        root.require()?;
        if plan.role == Role::TokenChild {
            return quota_controls::token_record(&inventory);
        }
        ensure!(
            plan.role == Role::KernelPrimary,
            "kernel actor role is not a primary"
        );
        files::positive(&root, &inventory, false)?;
        child_controls::token_child(plan, &inventory)?;
        private::controls(&root, &plan.quota, &inventory)?;
        filesystem::controls(plan)?;
        registry::controls(plan)?;
        network::controls(plan)?;
        job::require()?;
        job::memory()?;
        child_controls::pids(plan, &inventory)?;
        eof::controls(&root)?;
        root.require()?;
        ensure!(
            token::current(&plan.quota.package)?.digest() == inventory.digest(),
            "kernel actual token inventory changed during controls"
        );
        contract::primary_record(plan, &inventory)
    })();
    let operation = combine(operation, root.close());
    let registry_failed = registry_authority::protocol::take_cleanup_failure();
    combine(
        operation,
        if cleanup_ok() && !registry_failed {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "kernel actual cleanup uncertainty prevents a passed observation"
            ))
        },
    )
}
