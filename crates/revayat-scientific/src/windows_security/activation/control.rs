//! The fixed collector negative control and its independently attempted cleanup obligations.
//! These seams are used by the real Windows adapter; their validators do not attest ETW recording.
use super::{ActCtx, CallRole, Failures};
use anyhow::{Result, ensure};

pub fn manifest_bytes(run: &str) -> Result<Vec<u8>> {
    ensure!(
        run.len() == 32
            && run
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid activation fixture run identity"
    );
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<assembly manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" name=\"Scientific.Security.TraceControl.{run}\"/></assembly>\n").into_bytes())
}

/// Ownership of `Held` transfers to `close` exactly once, including after a failed read or call.
/// `create` must capture the native error before making another call or allocating.
pub trait TraceControlIo {
    type Held;
    fn acquire(&mut self) -> Result<Self::Held>;
    fn create(&mut self) -> Result<(usize, u32)>;
    fn release(&mut self, handle: usize) -> Result<()>;
    fn readback(&mut self, held: &mut Self::Held) -> Result<()>;
    fn close(&mut self, held: Self::Held) -> Result<()>;
    fn deadline(&mut self) -> Result<()>;
    fn emit(&mut self) -> Result<()>;
}

/// Source counterpart of StartupActivationAccess.ExecuteTraceControl.
pub fn execute(io: &mut impl TraceControlIo) -> Result<()> {
    let mut held = None;
    let mut handle = usize::MAX;
    let primary = (|| {
        io.deadline()?;
        held = Some(io.acquire()?);
        io.readback(held.as_mut().unwrap())?;
        io.deadline()?;
        let outcome = io.create()?;
        handle = outcome.0;
        ensure!(
            handle == usize::MAX && outcome.1 == 14001,
            "fixed collector negative-control outcome differs"
        );
        io.deadline()
    })();
    let mut errors = primary.err().into_iter().collect::<Vec<_>>();
    if handle != 0
        && handle != usize::MAX
        && let Err(error) = io.release(handle)
    {
        errors.push(error);
    }
    if let Err(error) = io.deadline() {
        errors.push(error);
    }
    if let Some(mut held) = held {
        if let Err(error) = io.readback(&mut held) {
            errors.push(error);
        }
        if let Err(error) = io.close(held) {
            errors.push(error);
        }
    }
    if let Err(error) = io.deadline() {
        errors.push(error);
    }
    ensure!(errors.is_empty(), Failures { errors });
    io.emit()?;
    io.deadline()
}

/// Source counterpart of SxsTraceCapture.WriteFixed. Flush follows a complete write, and close
/// runs independently. A failed close groups the original write/flush error before the close error.
pub fn write_fixed<H>(
    bytes: &[u8],
    acquire: impl FnOnce() -> Result<H>,
    write: impl FnOnce(&mut H, &[u8]) -> Result<()>,
    flush: impl FnOnce(&mut H) -> Result<()>,
    close: impl FnOnce(H) -> Result<()>,
) -> Result<()> {
    let mut held = acquire()?;
    let operation = write(&mut held, bytes).and_then(|()| flush(&mut held));
    match close(held) {
        Ok(()) => operation,
        Err(error) => {
            let mut errors = operation.err().into_iter().collect::<Vec<_>>();
            errors.push(error);
            Err(Failures { errors }.into())
        }
    }
}

/// Runs the original direct bootstrap validator's literal, handle/error, failure-order, writer,
/// capture-lifecycle and successful-consumer parser assertions. This executes validation bodies;
/// native capture evidence is still produced only by the Windows operation that uses these seams.
pub fn check_trace_control_validation() -> Result<()> {
    const RUN: &str = "0123456789abcdef0123456789abcdef";
    let bytes = manifest_bytes(RUN)?;
    ensure!(bytes == concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<assembly manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" ",
        "name=\"Scientific.Security.TraceControl.0123456789abcdef0123456789abcdef\"/></assembly>\n"
    ).as_bytes() && bytes.len() <= 512, "collector literal manifest differs");
    for invalid in [
        String::new(),
        format!("{RUN}0"),
        RUN.to_uppercase(),
        "private-path-sentinel".into(),
    ] {
        ensure!(
            manifest_bytes(&invalid).is_err(),
            "collector invalid run accepted"
        );
    }
    let context = ActCtx::fixed(CallRole::StandaloneManifest, 0x1000, 0, 0);
    ensure!(
        context.size == 56
            && context.source == 0x1000
            && context.flags == 0
            && context.resource == 0
            && context.architecture == 0
            && context.language == 0
            && context.directory == 0
            && context.application == 0
            && context.module == 0,
        "collector ACTCTX contract differs"
    );
    ensure!(
        std::mem::size_of::<usize>() == 8 && std::mem::size_of::<ActCtx>() == 56,
        "collector ACTCTX ABI differs"
    );
    for handle in [0, usize::MAX, 7] {
        for error in [0, 5, 14001, u32::MAX] {
            let mut io = CheckIo::new(handle, error, 0);
            let result = execute(&mut io);
            let expected = handle == usize::MAX && error == 14001;
            ensure!(
                result.is_ok() == expected
                    && io.emits == usize::from(expected)
                    && io.releases == usize::from(handle != 0 && handle != usize::MAX)
                    && io.closes == 1
                    && io.reads == 2,
                "collector handle/error lifetime differs"
            );
        }
    }
    for mode in 0..=8 {
        let mut io = CheckIo::new(if mode == 8 { 7 } else { usize::MAX }, 14001, mode);
        let result = execute(&mut io);
        ensure!(
            result.is_ok() == (mode == 0)
                && io.emits == usize::from(mode == 0)
                && io.closes == usize::from(mode != 1)
                && io.releases == usize::from(mode == 8),
            "collector injected failure lifetime differs"
        );
        if mode == 7 {
            let failure = result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("collector ordered error group missing"))?;
            ensure!(
                failure
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    == [
                        "private-control-first",
                        "private-control-later",
                        "private-control-later"
                    ],
                "collector ordered errors differ"
            );
        }
        if let Err(error) = result {
            ensure!(
                !format!(
                    "{:?}",
                    crate::windows_security::sxs::safe(error, "collector-control")
                )
                .contains("private-"),
                "collector error disclosed raw payload"
            );
        }
    }
    for mode in 0..8 {
        let mut io = CheckIo::new(usize::MAX, 14001, 0);
        io.writer_mode = Some(mode);
        let result = execute(&mut io);
        let success = mode == 0;
        ensure!(
            result.is_ok() == success
                && io.acquires == 1
                && io.writer_closes == 1
                && io.writer_order == (if mode & 1 != 0 { "wd" } else { "wfd" })
                && io.qualified == usize::from(success)
                && io.calls == usize::from(success)
                && io.emits == usize::from(success)
                && io.closes == usize::from(success),
            "collector writer/control lifecycle differs"
        );
        if success {
            continue;
        }
        let outer = result
            .as_ref()
            .unwrap_err()
            .downcast_ref::<Failures>()
            .ok_or_else(|| anyhow::anyhow!("collector writer outer error group missing"))?;
        ensure!(
            outer.errors.len() == 1,
            "collector writer outer error count differs"
        );
        let writer = &outer.errors[0];
        if mode & 4 != 0 {
            let failure = writer
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("collector writer inner error group missing"))?;
            let expected: &[&str] = if mode & 3 != 0 {
                &["private-control-write", "private-control-close"]
            } else {
                &["private-control-close"]
            };
            ensure!(
                failure
                    .errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    == expected,
                "collector writer ordered errors differ"
            );
        } else {
            ensure!(
                writer.to_string() == "private-control-write",
                "collector writer primary error differs"
            );
        }
        ensure!(
            !format!(
                "{:?}",
                crate::windows_security::sxs::safe(result.unwrap_err(), "collector-control")
            )
            .contains("private-"),
            "collector writer disclosed raw payload"
        );
    }
    check_capture_lifecycle()?;
    crate::windows_security::sxs::check_success_validation()
}

struct CheckIo {
    handle: usize,
    error: u32,
    mode: u8,
    reads: usize,
    releases: usize,
    closes: usize,
    emits: usize,
    acquires: usize,
    qualified: usize,
    calls: usize,
    writer_mode: Option<u8>,
    writer_order: String,
    writer_closes: usize,
}
impl CheckIo {
    fn new(handle: usize, error: u32, mode: u8) -> Self {
        Self {
            handle,
            error,
            mode,
            reads: 0,
            releases: 0,
            closes: 0,
            emits: 0,
            acquires: 0,
            qualified: 0,
            calls: 0,
            writer_mode: None,
            writer_order: String::new(),
            writer_closes: 0,
        }
    }
}
impl TraceControlIo for CheckIo {
    type Held = ();
    fn acquire(&mut self) -> Result<()> {
        use std::cell::{Cell, RefCell};
        self.acquires += 1;
        if self.mode == 1 {
            anyhow::bail!("private-control-first");
        }
        if let Some(mode) = self.writer_mode {
            let bytes = manifest_bytes("0123456789abcdef0123456789abcdef")?;
            let order = RefCell::new(String::new());
            let closes = Cell::new(0);
            let result = write_fixed(
                &bytes,
                || Ok(()),
                |_, actual| {
                    order.borrow_mut().push('w');
                    ensure!(
                        std::ptr::eq(actual.as_ptr(), bytes.as_ptr())
                            && actual.len() == bytes.len(),
                        "collector writer changed fixed bytes"
                    );
                    if mode & 1 != 0 {
                        anyhow::bail!("private-control-write");
                    }
                    Ok(())
                },
                |_| {
                    order.borrow_mut().push('f');
                    if mode & 2 != 0 {
                        anyhow::bail!("private-control-write");
                    }
                    Ok(())
                },
                |_| {
                    order.borrow_mut().push('d');
                    closes.set(closes.get() + 1);
                    if mode & 4 != 0 {
                        anyhow::bail!("private-control-close");
                    }
                    Ok(())
                },
            );
            self.writer_order = order.into_inner();
            self.writer_closes = closes.get();
            result?;
        }
        self.qualified += 1;
        Ok(())
    }
    fn create(&mut self) -> Result<(usize, u32)> {
        self.calls += 1;
        if matches!(self.mode, 3 | 7) {
            anyhow::bail!("private-control-first");
        }
        Ok((self.handle, self.error))
    }
    fn release(&mut self, handle: usize) -> Result<()> {
        ensure!(handle == self.handle, "collector release changed handle");
        self.releases += 1;
        if self.mode == 8 {
            anyhow::bail!("private-control-later");
        }
        Ok(())
    }
    fn readback(&mut self, _: &mut ()) -> Result<()> {
        self.reads += 1;
        if self.reads == 1 && self.mode == 2 {
            anyhow::bail!("private-control-first");
        }
        if self.reads == 2 && matches!(self.mode, 4 | 7) {
            anyhow::bail!("private-control-later");
        }
        Ok(())
    }
    fn close(&mut self, _: ()) -> Result<()> {
        self.closes += 1;
        if matches!(self.mode, 5 | 7) {
            anyhow::bail!("private-control-later");
        }
        Ok(())
    }
    fn deadline(&mut self) -> Result<()> {
        if self.mode == 6 && self.closes != 0 {
            anyhow::bail!("private-control-first");
        }
        Ok(())
    }
    fn emit(&mut self) -> Result<()> {
        self.emits += 1;
        Ok(())
    }
}
fn check_capture_lifecycle() -> Result<()> {
    use crate::windows_security::sxs::execute_capture;
    use std::cell::RefCell;
    for mode in 0..7 {
        let order = RefCell::new(String::new());
        let result = execute_capture(
            || {
                order.borrow_mut().push('o');
                if matches!(mode, 1 | 5) {
                    anyhow::bail!("private-consumer");
                }
                Ok(())
            },
            || {
                order.borrow_mut().push('c');
                if mode == 2 {
                    anyhow::bail!("private-control");
                }
                Ok(())
            },
            || {
                order.borrow_mut().push('s');
                if matches!(mode, 3 | 5) {
                    anyhow::bail!("private-stop");
                }
                Ok(())
            },
            |success| {
                order.borrow_mut().push(if success { 'p' } else { 'f' });
                if matches!(mode, 4 | 6) {
                    anyhow::bail!("private-parse");
                }
                Ok(())
            },
        );
        let expected = match mode {
            1 => "osf",
            2 | 3 => "ocs",
            5 => "os",
            _ => "ocsp",
        };
        ensure!(
            *order.borrow() == expected && result.is_ok() == (mode == 0),
            "collector capture lifecycle differs"
        );
        if mode == 1 {
            ensure!(
                result.as_ref().unwrap_err().to_string() == "private-consumer",
                "consumer primary error changed"
            );
        }
        if mode == 5 {
            let group = result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("consumer cleanup error group missing"))?;
            ensure!(
                group.errors[0].to_string() == "private-consumer",
                "consumer primary error order changed"
            );
        }
        if let Err(error) = result {
            ensure!(
                !format!(
                    "{:?}",
                    crate::windows_security::sxs::safe(error, "capture-lifecycle")
                )
                .contains("private-"),
                "collector lifecycle disclosed private payload"
            );
        }
    }
    Ok(())
}
