//! Qualified primary/duplicate/effective-token operation lifetime, shared by fixed observations.
use super::*;
pub(in super::super) fn authority<T>(
    process: Raw,
    package: &str,
    body: impl FnOnce(&dyn Fn() -> Result<()>) -> Result<T>,
) -> Result<T> {
    authority_context(process, package, || Ok(()), || Ok(()), body, || Ok(()))
}
pub(crate) fn with_authority<T>(
    process: Raw,
    package: &str,
    checkpoint: impl Fn() -> Result<()>,
    body: impl FnOnce(&dyn Fn() -> Result<()>) -> Result<T>,
) -> Result<T> {
    authority_context(process, package, checkpoint, || Ok(()), body, || Ok(()))
}
pub(super) fn authority_context<T>(
    process: Raw,
    package: &str,
    checkpoint: impl Fn() -> Result<()>,
    host: impl FnOnce() -> Result<()>,
    body: impl FnOnce(&dyn Fn() -> Result<()>) -> Result<T>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<T> {
    let mut primary = Handle(null_mut());
    let mut copy = Handle(null_mut());
    let result = (|| {
        checkpoint()?;
        require_host()?;
        primary = open(process)?;
        checkpoint()?;
        let expected = Snapshot::read(primary.0, false)?;
        ensure!(
            sid_text(&expected.package)? == package,
            "SxS authority is not the assigned actual profile"
        );
        checkpoint()?;
        copy = duplicate(primary.0, false)?;
        checkpoint()?;
        expected.require_same(&Snapshot::read(copy.0, true)?)?;
        checkpoint()?;
        host()?;
        let scoped_result = scoped(copy.0, || {
            body(&|| {
                let mut thread = effective()?;
                let result = Snapshot::read(thread.0, true)
                    .and_then(|actual| expected.require_same(&actual));
                finish(result, thread.close().err().into_iter().collect())
            })
        });
        let checked = checkpoint();
        finish(scoped_result, checked.err().into_iter().collect())
    })();
    // scoped has restored host identity, or aborted, before any observer handle closes.
    let errors = [cleanup(), copy.close(), primary.close()]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    finish(result, errors)
}
pub(super) fn startup_outcome(
    label: &str,
    opened: bool,
    handle: Raw,
    error: u32,
) -> Result<String> {
    crate::windows_security::policy::token_validation::startup_outcome(
        label,
        opened,
        handle as usize,
        error,
    )
}
pub(super) fn startup_query(
    process: Raw,
    label: &str,
    owner: &mut Handle,
    lines: &mut Vec<String>,
) -> Result<bool> {
    ensure!(owner.0.is_null(), "token-query handle was not released");
    let mut raw = null_mut();
    let success = unsafe { OpenProcessToken(process, 8, &mut raw) };
    let error = if success == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    owner.0 = if raw as usize == usize::MAX {
        null_mut()
    } else {
        raw
    };
    lines.push(startup_outcome(label, success != 0, raw, error)?);
    Ok(success != 0)
}
pub(crate) fn observe_startup_token(
    process: Raw,
    package: &str,
    emit: impl FnOnce(&[String]) -> Result<()>,
) -> Result<()> {
    use std::{
        cell::RefCell,
        time::{Duration, Instant},
    };
    require_host()?;
    let started = Instant::now();
    let deadline = || {
        ensure!(
            started.elapsed() <= Duration::from_secs(10),
            "fixed token-query comparison exceeded 10 seconds"
        );
        Ok(())
    };
    let query = RefCell::new(Handle(null_mut()));
    let lines = RefCell::new(Vec::with_capacity(2));
    let operation = authority_context(
        process,
        package,
        deadline,
        || {
            deadline()?;
            ensure!(
                startup_query(
                    process,
                    "host",
                    &mut query.borrow_mut(),
                    &mut lines.borrow_mut()
                )?,
                "host token-query positive control failed"
            );
            deadline()?;
            query.borrow_mut().close()?;
            deadline()
        },
        |require_same| {
            require_same()?;
            deadline()?;
            startup_query(
                process,
                "lpac",
                &mut query.borrow_mut(),
                &mut lines.borrow_mut(),
            )?;
            require_same()?;
            deadline()
        },
        || query.borrow_mut().close(),
    );
    let operation = finish(operation, deadline().err().into_iter().collect());
    let reporting = emit(&lines.borrow());
    finish(operation, reporting.err().into_iter().collect())
}
