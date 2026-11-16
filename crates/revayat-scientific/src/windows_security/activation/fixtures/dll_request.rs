//! Child-process DLL file request; distinct from direct host-module observation.
use super::{child, source};
use crate::windows_security::activation::{Failures, dll_request as wire};
use anyhow::{Result, ensure};
use std::path::Path;
pub fn require_role(preflight: bool, others: &[bool]) -> Result<()> {
    ensure!(
        preflight && !others.contains(&true),
        "fixed DLL resource request contract failed"
    );
    Ok(())
}
pub fn require_positive(positive: bool) -> Result<()> {
    ensure!(positive, "fixed DLL resource request contract failed");
    Ok(())
}
pub fn complete_host(
    run: impl FnOnce() -> Result<String>,
    close: impl FnOnce() -> Result<()>,
    accept: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let primary = run().and_then(|value| {
        ensure!(
            value == wire::SUCCESS,
            "fixed DLL resource request contract failed"
        );
        Ok(())
    });
    let closing = close();
    match (primary, closing) {
        (Ok(()), Ok(())) => accept(),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
pub fn check_dll_request_validation() -> Result<()> {
    use std::{cell::Cell, sync::Arc};
    wire::check_wire_validation()?;
    ensure!(
        child::require_result(Some(&(wire::SUCCESS.to_owned() + "\n"))).is_err(),
        "DLL result crossed child-executable wire role"
    );
    let path = std::env::current_dir()?
        .join("python")
        .join("python311.dll");
    let header = source::header(&path, 1033, true)?;
    ensure!(
        header
            == format!(
                "pub static FIXED_PYTHON: &[u16] = &[{}];\npub static FIXED_DIRECTORY: &[u16] = &[{}];\npub const FIXED_LANGUAGE: u16 = 1033;\n",
                child::numeric(&child::path_units(&path)?)?,
                child::numeric(&child::path_units(path.parent().unwrap())?)?
            ),
        "DLL Rust input header differs"
    );
    ensure!(
        source::header(&path.with_extension("exe"), 1033, true).is_err(),
        "DLL request admitted executable input role"
    );
    source::with_owned(&source::owned_directory(), &["child.rs", "abi.rs"], || {
        source::require_source(source::CHILD, source::CHILD_SHA256)?;
        let generated = source::dll_source(source::CHILD)?;
        ensure!(
            generated
                == source::CHILD
                    .replace(
                        "pub const RESOURCE_ID: u16 = 1;",
                        "pub const RESOURCE_ID: u16 = 2;"
                    )
                    .replace(
                        "WINDOWS_CHILD_ACTIVATION",
                        "WINDOWS_DLL_RESOURCE_ACTIVATION"
                    )
                && generated.contains("flags: 0x2e")
                && generated.contains("source: config::FIXED_PYTHON.as_ptr()")
                && generated.contains("application: config::FIXED_PYTHON.as_ptr()")
                && generated.contains("module: core::ptr::null_mut()")
                && source::ABI.contains("size_of::<ActCtx>() == 56")
                && source::ABI.contains("offset_of!(ActCtx, module) == 48"),
            "DLL Rust source lost ACTCTX ABI/input/resource binding"
        );
        ensure!(
            source::dll_source(&(source::CHILD.to_owned() + " ")).is_err(),
            "changed DLL source accepted"
        );
        for literal in [
            "pub const RESOURCE_ID: u16 = 1;",
            "WINDOWS_CHILD_ACTIVATION",
        ] {
            ensure!(
                source::replace_once("unrelated", literal, "fixed").is_err()
                    && source::replace_once(&literal.repeat(2), literal, "fixed").is_err(),
                "missing/duplicate DLL source edit accepted"
            );
        }
        Ok(())
    })?;
    #[derive(Debug)]
    struct Id(Arc<std::io::Error>);
    impl std::fmt::Display for Id {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fixed DLL host failure")
        }
    }
    impl std::error::Error for Id {}
    for mode in 0..5 {
        let runs = Cell::new(0);
        let closes = Cell::new(0);
        let accepts = Cell::new(0);
        let operation = Arc::new(std::io::Error::other("fixed DLL operation"));
        let close = Arc::new(std::io::Error::other("fixed DLL close"));
        let caught = complete_host(
            || {
                runs.set(runs.get() + 1);
                if mode == 1 || mode == 4 {
                    Err(Id(operation.clone()).into())
                } else {
                    Ok(if mode == 2 {
                        wire::DENIAL
                    } else {
                        wire::SUCCESS
                    }
                    .into())
                }
            },
            || {
                closes.set(closes.get() + 1);
                if mode == 3 || mode == 4 {
                    Err(Id(close.clone()).into())
                } else {
                    Ok(())
                }
            },
            || {
                accepts.set(accepts.get() + 1);
                Ok(())
            },
        )
        .err();
        ensure!(
            runs.get() == 1
                && closes.get() == 1
                && accepts.get() == usize::from(mode == 0)
                && caught.is_some() == (mode != 0),
            "DLL host completion skipped close or latched invalid result"
        );
        if mode == 1 || mode == 3 {
            ensure!(
                Arc::ptr_eq(
                    &caught.as_ref().unwrap().downcast_ref::<Id>().unwrap().0,
                    if mode == 1 { &operation } else { &close }
                ),
                "DLL host changed single failure identity"
            );
        }
        if mode == 4 {
            let group = caught.as_ref().unwrap().downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && Arc::ptr_eq(&group.errors[0].downcast_ref::<Id>().unwrap().0, &operation)
                    && Arc::ptr_eq(&group.errors[1].downcast_ref::<Id>().unwrap().0, &close),
                "DLL host changed ordered operation/close failures"
            );
        }
    }
    ensure!(
        require_positive(false).is_err(),
        "DLL host accepted missing positive"
    );
    require_positive(true)?;
    ensure!(
        require_role(true, &[true]).is_err() && require_role(false, &[false]).is_err(),
        "DLL request role overlapped unrelated launch"
    );
    require_role(true, &[false])
}
pub fn prepared_input(path: &Path) -> Result<()> {
    child::canonical_input(path, "python311.dll")
}
