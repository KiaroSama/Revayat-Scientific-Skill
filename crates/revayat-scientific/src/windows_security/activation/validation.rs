//! Original StartupActivationAccess.CheckValidation body; these checks do not attest LPAC access.
use super::*;
use std::{
    cell::{Cell, RefCell},
    mem::{offset_of, size_of},
};

/// Owns the exact terminated source/directory storage used by a borrowed ACTCTX call.
pub struct FixedPathCall {
    role: CallRole,
    source: Vec<u16>,
    directory: Vec<u16>,
    language: u16,
}
impl FixedPathCall {
    pub fn new(role: CallRole, path: &str, language: u16) -> Result<Self> {
        ensure!(
            !path.is_empty() && !path.contains('\0'),
            "activation source path encoding differs"
        );
        let directory = path
            .rsplit_once(['\\', '/'])
            .map(|(directory, _)| directory)
            .ok_or_else(|| anyhow::anyhow!("activation source directory missing"))?;
        let directory = if directory.len() == 2 && directory.ends_with(':') {
            format!("{directory}\\")
        } else {
            directory.to_owned()
        };
        let source = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        ensure!(
            source.len() <= 32768,
            "activation source path exceeds native bound"
        );
        Ok(Self {
            role,
            source,
            directory: directory.encode_utf16().chain(Some(0)).collect(),
            language,
        })
    }
    /// Keep this owner alive until the native operation returns; the context borrows its buffers.
    pub fn context(&self) -> ActCtx {
        ActCtx::fixed(
            self.role,
            self.source.as_ptr() as usize,
            self.directory.as_ptr() as usize,
            self.language,
        )
    }
    pub fn source_units(&self) -> &[u16] {
        &self.source
    }
    pub fn directory_units(&self) -> &[u16] {
        &self.directory
    }
}

pub fn startup_outcome(context: &str, handle: usize, error: u32) -> Result<String> {
    ensure!(
        handle != 0 && (handle == usize::MAX || error == 0),
        "activation context result/handle is inconsistent"
    );
    ensure!(
        matches!(context, "host" | "lpac"),
        "activation observation context differs"
    );
    Ok(format!(
        "WINDOWS_STARTUP_ACTIVATION context={context} resource_type=24 resource_id=1 created={} win32_error={error} activated=False child_equivalence_claimed=False cause_claimed=False",
        if handle == usize::MAX {
            "False"
        } else {
            "True"
        }
    ))
}
/// Validate the entire output before invoking any emitter, preserving the original report bound.
pub fn report(
    lines: &[String],
    newline: &str,
    mut emit: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    bounded_report(lines, newline)?;
    for line in lines {
        emit(line)?;
    }
    Ok(())
}
/// Exact distinction between a false reversion and a thrown reversion. A failing fail-fast callback
/// takes precedence, and a returning fail-fast callback can never reach release or output.
pub fn finalize_checked<'a>(
    primary: Option<anyhow::Error>,
    impersonating: bool,
    revert: impl FnOnce() -> Result<bool>,
    fatal: impl FnOnce() -> Result<()>,
    cleanup: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
    emit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if impersonating {
        match revert() {
            Ok(true) => {}
            Ok(false) => {
                fatal()?;
                anyhow::bail!("activation identity restoration did not terminate");
            }
            Err(error) => {
                fatal()?;
                return Err(error);
            }
        }
    }
    let mut errors = primary.into_iter().collect::<Vec<_>>();
    for mut action in cleanup {
        if let Err(error) = action() {
            errors.push(error);
        }
    }
    if let Err(error) = emit() {
        errors.push(error);
    }
    finish(errors)
}
/// Source counterpart of StartupActivationAccess.CheckValidation, including its three helpers.
pub fn check_startup_activation_validation() -> Result<()> {
    ensure!(
        size_of::<usize>() == 8 && size_of::<ActCtx>() == 56,
        "activation context requires Windows x64 ABI"
    );
    ensure!(
        [
            offset_of!(ActCtx, size),
            offset_of!(ActCtx, flags),
            offset_of!(ActCtx, source),
            offset_of!(ActCtx, architecture),
            offset_of!(ActCtx, language),
            offset_of!(ActCtx, directory),
            offset_of!(ActCtx, resource),
            offset_of!(ActCtx, application),
            offset_of!(ActCtx, module)
        ] == [0, 4, 8, 16, 18, 24, 32, 40, 48],
        "activation context field offset differs"
    );
    let fixed_call = FixedPathCall::new(CallRole::Executable, "C:\\owned space\\python.exe", 1033)?;
    let value = fixed_call.context();
    ensure!(
        value.flags == 0x2e
            && value.size == 56
            && value.language == 1033
            && value.architecture == 0
            && value.module == 0
            && value.resource == 1
            && value.source == fixed_call.source_units().as_ptr() as usize
            && value.application == value.source
            && value.directory == fixed_call.directory_units().as_ptr() as usize
            && String::from_utf16(
                &fixed_call.directory_units()[..fixed_call.directory_units().len() - 1]
            )? == "C:\\owned space",
        "activation fixed call contract differs"
    );
    ensure!(
        startup_outcome("lpac", usize::MAX, 5)?
            == "WINDOWS_STARTUP_ACTIVATION context=lpac resource_type=24 resource_id=1 created=False win32_error=5 activated=False child_equivalence_claimed=False cause_claimed=False"
            && startup_outcome("host", 1, 0)?.contains("created=True win32_error=0")
            && startup_outcome("host", 0, 0).is_err()
            && startup_outcome("host", 1, 5).is_err(),
        "activation result formatting or inconsistent-handle refusal differs"
    );
    check_finalization()?;
    check_reporting()?;
    assembly::check_cleanup_validation()?;
    let attempts = Cell::new(0);
    let error = finalize_checked(
        Some(anyhow::anyhow!("fixed primary")),
        false,
        || Ok(true),
        || Ok(()),
        vec![
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                anyhow::bail!("fixed cleanup")
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Ok(())
            }),
        ],
        || Ok(()),
    )
    .unwrap_err();
    let errors = &error
        .downcast_ref::<Failures>()
        .ok_or_else(|| anyhow::anyhow!("activation cleanup group missing"))?
        .errors;
    ensure!(
        attempts.get() == 2
            && errors.iter().map(ToString::to_string).collect::<Vec<_>>()
                == ["fixed primary", "fixed cleanup"],
        "activation cleanup failure was hidden"
    );
    Ok(())
}
fn check_reporting() -> Result<()> {
    for newline in ["\n", "\r\n"] {
        let emitted = Cell::new(0);
        let emit = |_: &str| {
            emitted.set(emitted.get() + 1);
            Ok(())
        };
        report(&["x".repeat(12288 - newline.len())], newline, emit)?;
        ensure!(emitted.get() == 1, "activation reporting boundary differs");
        for lines in [
            vec!["x".repeat(12289 - newline.len())],
            vec![String::new(); 16],
        ] {
            ensure!(
                report(&lines, newline, emit).is_err() && emitted.get() == 1,
                "activation reporting emitted beyond its bound"
            );
        }
        report(&vec!["fixed".into(); 15], newline, emit)?;
        ensure!(
            emitted.get() == 16,
            "activation reporting line boundary differs"
        );
    }
    Ok(())
}
fn check_finalization() -> Result<()> {
    let order = RefCell::new(Vec::new());
    let reverted = Cell::new(false);
    finalize_checked(
        None,
        true,
        || {
            order.borrow_mut().push("revert");
            reverted.set(true);
            Ok(true)
        },
        || anyhow::bail!("unexpected fail-fast"),
        vec![
            Box::new(|| {
                order.borrow_mut().push("first cleanup");
                Ok(())
            }),
            Box::new(|| {
                order.borrow_mut().push("second cleanup");
                Ok(())
            }),
        ],
        || {
            ensure!(reverted.get(), "activation output preceded reversion");
            order.borrow_mut().push("fixed buffered metadata");
            Ok(())
        },
    )?;
    ensure!(
        *order.borrow()
            == [
                "revert",
                "first cleanup",
                "second cleanup",
                "fixed buffered metadata"
            ],
        "activation finalization order differs"
    );
    for throws in [false, true] {
        order.borrow_mut().clear();
        let error = finalize_checked(
            None,
            true,
            || {
                order.borrow_mut().push("revert");
                if throws {
                    anyhow::bail!("fixed revert failure");
                }
                Ok(false)
            },
            || {
                order.borrow_mut().push("fail-fast");
                anyhow::bail!("fixed fail-fast")
            },
            vec![Box::new(|| {
                order.borrow_mut().push("cleanup");
                Ok(())
            })],
            || {
                order.borrow_mut().push("emit");
                Ok(())
            },
        )
        .unwrap_err();
        ensure!(
            error.to_string() == "fixed fail-fast" && *order.borrow() == ["revert", "fail-fast"],
            "failed reversion allowed finalization or lost fatal error"
        );
    }
    order.borrow_mut().clear();
    let error = finalize_checked(
        None,
        true,
        || Ok(false),
        || {
            order.borrow_mut().push("fail-fast");
            Ok(())
        },
        vec![Box::new(|| {
            order.borrow_mut().push("cleanup");
            Ok(())
        })],
        || {
            order.borrow_mut().push("emit");
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        error.to_string() == "activation identity restoration did not terminate"
            && *order.borrow() == ["fail-fast"],
        "returning fail-fast allowed output"
    );
    for impersonating in [false, true] {
        order.borrow_mut().clear();
        let error = finalize_checked(
            Some(anyhow::anyhow!("fixed operation")),
            impersonating,
            || {
                order.borrow_mut().push("revert");
                Ok(true)
            },
            || anyhow::bail!("fixed fail-fast"),
            vec![
                Box::new(|| {
                    order.borrow_mut().push("first cleanup");
                    anyhow::bail!("fixed cleanup")
                }),
                Box::new(|| {
                    order.borrow_mut().push("second cleanup");
                    Ok(())
                }),
            ],
            || {
                order.borrow_mut().push("emit");
                anyhow::bail!("fixed reporting")
            },
        )
        .unwrap_err();
        let errors = &error
            .downcast_ref::<Failures>()
            .ok_or_else(|| anyhow::anyhow!("activation finalization group missing"))?
            .errors;
        let expected: &[&str] = if impersonating {
            &["revert", "first cleanup", "second cleanup", "emit"]
        } else {
            &["first cleanup", "second cleanup", "emit"]
        };
        ensure!(
            errors.iter().map(ToString::to_string).collect::<Vec<_>>()
                == ["fixed operation", "fixed cleanup", "fixed reporting"]
                && *order.borrow() == expected,
            "activation finalization lost ordered failures"
        );
    }
    Ok(())
}
