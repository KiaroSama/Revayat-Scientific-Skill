//! Strict capture cleanup: retire numeric ownership before close and retain sticky uncertainty.
use super::Failures;
use anyhow::{Result, ensure};
use std::cell::{Cell, RefCell};

#[derive(Default)]
pub struct CloseState {
    uncertain: bool,
}
impl CloseState {
    pub fn uncertain(&self) -> bool {
        self.uncertain
    }
    /// `slot` is the owner's actual handle slot, not a copy. It is retired before the callback.
    /// A failed or unwinding callback never permits that numeric handle to be retried.
    pub fn close(
        &mut self,
        slot: &Cell<usize>,
        close: impl FnOnce(usize) -> Result<bool>,
    ) -> Result<()> {
        let owned = slot.replace(0);
        if owned == 0 {
            return Ok(());
        }
        let previous = self.uncertain;
        self.uncertain = true;
        if close(owned)? {
            self.uncertain = previous;
            Ok(())
        } else {
            anyhow::bail!("fixed activation capture close remains uncertain")
        }
    }
    pub fn require_closed(&self) -> Result<()> {
        ensure!(
            !self.uncertain,
            "fixed activation capture close remains uncertain"
        );
        Ok(())
    }
}
pub fn finish_strict(actions: Vec<Box<dyn FnMut() -> Result<()> + '_>>) -> Result<()> {
    let mut errors = Vec::new();
    for mut action in actions {
        if let Err(error) = action() {
            errors.push(error);
        }
    }
    ensure!(errors.is_empty(), Failures { errors });
    Ok(())
}
/// The capture owner supplies real close/cancel/drain/buffer operations. Each is attempted even
/// after another action fails. Snapshot runs both before closing and after joining the drain.
pub trait StrictCaptureIo {
    fn snapshot(&mut self) -> Result<()>;
    fn close_writer(&mut self) -> Result<()>;
    fn cancel(&mut self) -> Result<()>;
    fn close_reader(&mut self) -> Result<()>;
    fn join(&mut self) -> Result<()>;
    fn check_drain(&mut self) -> Result<()>;
    fn dispose_buffer(&mut self) -> Result<()>;
    fn check_closed(&mut self) -> Result<()>;
}
pub fn dispose_strict<I: StrictCaptureIo>(io: &mut I) -> Result<()> {
    let actions: [fn(&mut I) -> Result<()>; 9] = [
        I::snapshot,
        I::close_writer,
        I::cancel,
        I::close_reader,
        I::join,
        I::snapshot,
        I::check_drain,
        I::dispose_buffer,
        I::check_closed,
    ];
    let mut errors = Vec::new();
    for action in actions {
        if let Err(error) = action(io) {
            errors.push(error);
        }
    }
    ensure!(errors.is_empty(), Failures { errors });
    Ok(())
}
pub fn prefix(bytes: &[u8]) -> (Vec<u8>, bool) {
    (bytes[..bytes.len().min(512)].to_vec(), bytes.len() > 512)
}
fn zero(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: uniquely borrowed initialized bytes. Volatile stores keep cleanup observable
        // even when the receipt is immediately dropped after returning a private failure.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}
struct Receipt {
    bytes: Vec<u8>,
    truncated: bool,
}
struct ZeroOnExit<'a>(&'a mut [u8]);
impl Drop for ZeroOnExit<'_> {
    fn drop(&mut self) {
        zero(self.0);
    }
}
impl Receipt {
    fn new(bytes: &[u8]) -> Self {
        let (bytes, truncated) = prefix(bytes);
        Self { bytes, truncated }
    }
    fn retain(&mut self, retain: impl FnOnce(&[u8], bool) -> Result<()>) -> Result<()> {
        let guard = ZeroOnExit(&mut self.bytes);
        retain(guard.0, self.truncated)
    }
}
impl Drop for Receipt {
    fn drop(&mut self) {
        zero(&mut self.bytes);
    }
}
pub fn retain_failure_receipt(
    bytes: &[u8],
    retain: impl FnOnce(&[u8], bool) -> Result<()>,
) -> Result<()> {
    Receipt::new(bytes).retain(retain)
}

struct CheckCapture {
    writer: Cell<usize>,
    reader: Cell<usize>,
    state: CloseState,
    mode: u8,
    order: Vec<&'static str>,
    attempted: Vec<usize>,
    buffer: Vec<u8>,
    joined: bool,
}
impl CheckCapture {
    fn new(mode: u8) -> Self {
        Self {
            writer: Cell::new(11),
            reader: Cell::new(12),
            state: CloseState::default(),
            mode,
            order: Vec::new(),
            attempted: Vec::new(),
            buffer: vec![0x5a; 16],
            joined: false,
        }
    }
    fn close_writer(&mut self) -> Result<()> {
        let mode = self.mode;
        let slot = &self.writer;
        let order = &mut self.order;
        let attempted = &mut self.attempted;
        self.state.close(slot, |owned| {
            ensure!(
                slot.get() == 0,
                "capture writer was not retired before close"
            );
            attempted.push(owned);
            order.push("writer");
            Ok(!matches!(mode, 1 | 3))
        })
    }
    fn close_reader(&mut self) -> Result<()> {
        let mode = self.mode;
        let slot = &self.reader;
        let order = &mut self.order;
        let attempted = &mut self.attempted;
        self.state.close(slot, |owned| {
            ensure!(
                slot.get() == 0,
                "capture reader was not retired before close"
            );
            attempted.push(owned);
            order.push("reader");
            Ok(!matches!(mode, 2 | 3))
        })
    }
    fn cancel(&mut self) -> Result<()> {
        self.order.push("cancel");
        ensure!(
            self.reader.get() == 12,
            "capture reader closed before cancellation"
        );
        Ok(())
    }
    fn join(&mut self) -> Result<()> {
        self.order.push("join");
        self.joined = true;
        Ok(())
    }
    fn buffer(&mut self) -> Result<()> {
        self.order.push("buffer");
        ensure!(self.joined, "capture buffer disposed before join attempt");
        zero(&mut self.buffer);
        Ok(())
    }
}
/// Source counterpart of Capture.CheckStrictCleanup. The returned error comes from the actual
/// both-close-failed callback execution, after every ownership and prefix assertion has run.
pub fn check_strict_cleanup() -> Result<anyhow::Error> {
    let mut actual = None;
    for mode in 0..4 {
        let owner = RefCell::new(CheckCapture::new(mode));
        let result = finish_strict(vec![
            Box::new(|| owner.borrow_mut().close_writer()),
            Box::new(|| owner.borrow_mut().cancel()),
            Box::new(|| owner.borrow_mut().close_reader()),
            Box::new(|| owner.borrow_mut().join()),
            Box::new(|| owner.borrow_mut().buffer()),
            Box::new(|| owner.borrow().state.require_closed()),
        ]);
        let repeated = finish_strict(vec![
            Box::new(|| owner.borrow_mut().close_writer()),
            Box::new(|| owner.borrow_mut().close_reader()),
            Box::new(|| owner.borrow().state.require_closed()),
        ]);
        let owner = owner.into_inner();
        ensure!(
            owner.writer.get() == 0
                && owner.reader.get() == 0
                && owner.attempted == [11, 12]
                && owner.order == ["writer", "cancel", "reader", "join", "buffer"]
                && owner.state.uncertain() == (mode != 0)
                && result.is_err() == (mode != 0)
                && repeated.is_err() == (mode != 0)
                && owner.buffer.iter().all(|byte| *byte == 0),
            "capture strict-close ownership or sticky failure differs"
        );
        if mode != 0 {
            let errors = &result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("capture strict-close error group missing"))?
                .errors;
            let repeated_errors = &repeated
                .as_ref()
                .unwrap_err()
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("capture repeated uncertainty group missing"))?
                .errors;
            ensure!(
                errors.len() == if mode == 3 { 3 } else { 2 } && repeated_errors.len() == 1,
                "capture dropped a close failure or retried an uncertain handle"
            );
        }
        if mode == 3 {
            actual = result.err();
        }
    }
    let slot = Cell::new(7);
    let mut state = CloseState::default();
    let failure = state
        .close(&slot, |owned| {
            ensure!(
                owned == 7 && slot.get() == 0,
                "capture error path did not retire ownership first"
            );
            Err(std::io::Error::other("fixed close callback failure").into())
        })
        .err()
        .ok_or_else(|| anyhow::anyhow!("capture close callback error was suppressed"))?;
    ensure!(
        failure.is::<std::io::Error>() && state.uncertain() && slot.get() == 0,
        "capture close callback error lost its type or sticky uncertainty"
    );
    state.close(&slot, |_| anyhow::bail!("uncertain capture handle retried"))?;
    ensure!(
        state.require_closed().is_err(),
        "capture repeated cleanup forgot uncertainty"
    );
    for length in [0, 127, 512, 513, 1024] {
        let input = (0..length)
            .map(|index| (index & 255) as u8)
            .collect::<Vec<_>>();
        let (selected, truncated) = prefix(&input);
        ensure!(
            selected.len() == length.min(512)
                && truncated == (length > 512)
                && input.len() == length
                && selected
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == input[index]),
            "bounded capture prefix differs"
        );
        for fail in [false, true] {
            let mut receipt = Receipt::new(&input);
            let result = receipt.retain(|bytes, limited| {
                ensure!(
                    bytes == selected && limited == truncated,
                    "capture receipt changed retained bytes"
                );
                if fail {
                    anyhow::bail!("fixed receipt callback failure");
                }
                Ok(())
            });
            ensure!(
                result.is_err() == fail && receipt.bytes.iter().all(|byte| *byte == 0),
                "capture failure receipt was not cleared"
            );
        }
    }
    check_dispose_order()?;
    actual.ok_or_else(|| anyhow::anyhow!("capture both-close failure was not retained"))
}
struct CheckDispose {
    calls: Vec<&'static str>,
    fail: Option<usize>,
    buffer: Vec<u8>,
}
impl CheckDispose {
    fn call(&mut self, name: &'static str) -> Result<()> {
        let index = self.calls.len();
        self.calls.push(name);
        if name == "buffer" {
            zero(&mut self.buffer);
        }
        if self.fail == Some(index) {
            anyhow::bail!("fixed capture cleanup callback failure");
        }
        Ok(())
    }
}
impl StrictCaptureIo for CheckDispose {
    fn snapshot(&mut self) -> Result<()> {
        self.call("snapshot")
    }
    fn close_writer(&mut self) -> Result<()> {
        self.call("writer")
    }
    fn cancel(&mut self) -> Result<()> {
        self.call("cancel")
    }
    fn close_reader(&mut self) -> Result<()> {
        self.call("reader")
    }
    fn join(&mut self) -> Result<()> {
        self.call("join")
    }
    fn check_drain(&mut self) -> Result<()> {
        self.call("drain")
    }
    fn dispose_buffer(&mut self) -> Result<()> {
        self.call("buffer")
    }
    fn check_closed(&mut self) -> Result<()> {
        self.call("closed")
    }
}
fn check_dispose_order() -> Result<()> {
    for fail in std::iter::once(None).chain((0..9).map(Some)) {
        let mut io = CheckDispose {
            calls: Vec::new(),
            fail,
            buffer: vec![0x5a; 32],
        };
        let result = dispose_strict(&mut io);
        ensure!(
            result.is_err() == fail.is_some()
                && io.calls
                    == [
                        "snapshot", "writer", "cancel", "reader", "join", "snapshot", "drain",
                        "buffer", "closed"
                    ]
                && io.buffer.iter().all(|byte| *byte == 0),
            "capture disposal skipped independent cleanup or buffer clearing"
        );
    }
    Ok(())
}
