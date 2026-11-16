//! Exact direct TrustedSetup.CheckValidation lineage: TrustedSetup.cs:389–498.
use super::*;
use crate::windows_security::scratch;
use std::{cell::Cell, sync::Arc};

fn refused(result: Result<()>) -> Result<()> {
    let error = result.expect_err("unrelated launch must be refused before effects");
    ensure!(
        !format!("{error:#}").contains("private-sentinel"),
        "launch refusal disclosed private arguments"
    );
    Ok(())
}
pub fn check_trusted_setup_validation() -> Result<()> {
    super::super::capture::check_strict_capture_cleanup()?;
    let cwd = std::env::current_dir()?.join("python");
    let parent = cwd.parent().unwrap();
    let empty = Vec::new();
    let private = vec!["private-sentinel".to_owned()];
    let dll = cwd.join("startup-dll-resource.exe");
    require_dll_launch(&dll, Some(&empty), &cwd)?;
    refused(require_dll_launch(&dll, Some(&private), &cwd))?;
    refused(require_dll_launch(&dll, None, &cwd))?;
    refused(require_dll_launch(&dll, Some(&empty), parent))?;
    refused(require_dll_launch(
        &cwd.join("startup-activation.exe"),
        Some(&empty),
        &cwd,
    ))?;
    refused(require_route(&dll, Some(&empty), &cwd, true, 0, true))?;
    refused(require_route(&dll, Some(&empty), &cwd, false, 0, false))?;
    let images = [
        "startup-self-activation.exe",
        "startup-manual-activation.exe",
        "startup-explicit-id2.exe",
    ];
    for (role, image) in images.iter().enumerate() {
        let executable = cwd.join(image);
        require_self_launch(&executable, Some(&empty), &cwd, role as i32)?;
        for other in images {
            if other != *image {
                refused(require_self_launch(
                    &cwd.join(other),
                    Some(&empty),
                    &cwd,
                    role as i32,
                ))?;
            }
        }
    }
    // Source repeats explicit manual and ID2 argument/cwd checks in addition to
    // the complete cross-role product; retain both sets of calls.
    for role in [1, 2] {
        let executable = cwd.join(images[role]);
        refused(require_self_launch(
            &executable,
            Some(&private),
            &cwd,
            role as i32,
        ))?;
        refused(require_self_launch(
            &executable,
            Some(&empty),
            parent,
            role as i32,
        ))?;
        if role == 2 {
            refused(require_self_launch(&executable, None, &cwd, role as i32))?;
        }
    }
    for invalid in [-1, 3, i32::MAX] {
        refused(require_route(
            Path::new(""),
            None,
            Path::new(""),
            true,
            invalid,
            false,
        ))?;
    }
    let original = cwd.join(images[0]);
    refused(require_self_launch(&original, Some(&private), &cwd, 0))?;
    refused(require_self_launch(&original, Some(&empty), parent, 0))?;
    refused(require_self_launch(
        &original.with_extension("dll"),
        Some(&empty),
        &cwd,
        0,
    ))?;
    refused(require_self_launch(&original, None, &cwd, 0))?;
    ensure!(
        SELF_CREATION_FLAGS == 0x0008040c,
        "fixed host activation launch flags differ"
    );
    for tool in [
        "startup-dll-resource.exe",
        images[0],
        images[1],
        images[2],
        "rc.exe",
        "csc.exe",
    ] {
        ensure!(
            stage(tool, "create-before")?
                == format!("WINDOWS_SETUP_STAGE tool={tool} stage=create-before"),
            "trusted setup fixed stage differs"
        );
    }
    for (tool, phase) in [
        ("C:\\private\\csc.exe", "create-before"),
        ("csc.exe", "secret"),
    ] {
        ensure!(
            stage(tool, phase).is_err(),
            "trusted setup stage accepted private metadata"
        );
    }
    for fail_flush in [false, true] {
        let primary = scratch::failure("fixed operation fixture");
        let cleanup = scratch::failure("fixed cleanup fixture");
        let marker = scratch::failure("fixed marker fixture");
        let writes = Cell::new(0);
        let flushes = Cell::new(0);
        let attempts = Cell::new(0);
        let emit = |phase| {
            emit_stage_with(
                "csc.exe",
                phase,
                |_| {
                    writes.set(writes.get() + 1);
                    if fail_flush {
                        Ok(())
                    } else {
                        Err(marker.clone())
                    }
                },
                || {
                    flushes.set(flushes.get() + 1);
                    Err(marker.clone())
                },
            )
        };
        let failure = finish_cleanup(
            Some(primary.clone()),
            vec![
                Box::new(|| emit("cleanup-before")),
                Box::new(|| {
                    attempts.set(attempts.get() + 1);
                    Err(cleanup.clone())
                }),
                Box::new(|| {
                    attempts.set(attempts.get() + 1);
                    Ok(())
                }),
                Box::new(|| emit("cleanup-after")),
            ],
        )
        .unwrap_err();
        let group = failure
            .downcast_ref::<scratch::Failures>()
            .ok_or_else(|| anyhow::anyhow!("setup cleanup lost aggregate"))?;
        ensure!(
            attempts.get() == 2
                && writes.get() == 2
                && flushes.get() == (if fail_flush { 2 } else { 0 })
                && group.errors.len() == 4
                && Arc::ptr_eq(&group.errors[0], &primary)
                && Arc::ptr_eq(&group.errors[1], &marker)
                && Arc::ptr_eq(&group.errors[2], &cleanup)
                && Arc::ptr_eq(&group.errors[3], &marker),
            "trusted setup marker failure replaced operation or skipped cleanup"
        );
        let retained = match finish_cleanup(Some(primary.clone()), vec![Box::new(|| Ok(()))]) {
            Ok(()) => primary.clone(),
            Err(error) => error,
        };
        ensure!(
            Arc::ptr_eq(&retained, &primary),
            "successful cleanup replaced original operation failure"
        );
    }
    Ok(())
}
