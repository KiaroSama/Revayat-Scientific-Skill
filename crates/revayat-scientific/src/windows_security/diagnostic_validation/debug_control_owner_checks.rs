//! Inert I/O checks of the same register operations used by the trusted native control.
use super::control::{ControlIo, ControlState};
use super::*;
use crate::windows_security::diagnostic_validation::hardware::ContextIo;

struct Io {
    context: Vec<u8>,
    lines: Vec<String>,
    writes: usize,
    fail_write: usize,
    normalize: bool,
}
impl Io {
    fn new() -> Self {
        let mut context = vec![0; activation::CONTEXT_SIZE];
        put(&mut context, 104, 0xfffe0ff0);
        put(&mut context, 112, 0x400);
        put(&mut context, 152, 0x123456789abcdef0);
        Self {
            context,
            lines: Vec::new(),
            writes: 0,
            fail_write: 0,
            normalize: false,
        }
    }
    fn arm(&mut self) -> Result<ControlState> {
        let mut state = ControlState::new(7)?;
        state.received(7, 3)?;
        state.creation(self, 7, 0x8000)?;
        state.continued();
        Ok(state)
    }
    fn trap(&mut self, state: &mut ControlState) -> Result<()> {
        state.received(7, 1)?;
        put(&mut self.context, 104, 0xfffe0ff1);
        put(&mut self.context, 248, 0x8000);
        state.exception(self, 7, 0x80000004, true)
    }
}
impl ContextIo for Io {
    fn read_context(&mut self) -> Result<Vec<u8>> {
        Ok(self.context.clone())
    }
    fn write_context(&mut self, desired: &[u8]) -> Result<()> {
        self.writes += 1;
        self.context.copy_from_slice(desired);
        if self.normalize {
            put(&mut self.context, 104, 0xffff0ff0);
        }
        ensure!(
            self.writes != self.fail_write,
            "fixed test partial setter failure"
        );
        Ok(())
    }
}
impl ControlIo for Io {
    fn emit_control(&mut self, line: &str) -> Result<()> {
        self.lines.push(line.into());
        Ok(())
    }
}
pub(super) fn check_operations() -> Result<()> {
    let mut io = Io::new();
    let baseline = io.context.clone();
    let mut state = io.arm()?;
    ensure!(
        state.require_complete().is_err(),
        "arming certified a complete control"
    );
    state.received(7, 1)?;
    state.exception(&mut io, 7, 0x80000003, true)?;
    ensure!(
        state.exception(&mut io, 7, 0x80000003, true).is_err(),
        "duplicate software stop accepted"
    );
    state.continued();
    io.trap(&mut state)?;
    ensure!(
        io.writes == 2
            && activation::raw_debug_equal(&baseline, &io.context)?
            && value(&io.context, 152)? == value(&baseline, 152)?
            && value(&io.context, 248)? == 0x8000,
        "fixed control restoration changed control/integer or failed raw restoration"
    );
    state.continued();
    state.received(7, 5)?;
    state.process_exit(0)?;
    state.continued();
    state.require_complete()?;
    ensure!(
        io.lines.len() == 5
            && io.lines.iter().all(|line| line.len() < 512
                && !line.contains("123456789ABCDEF0")
                && !line.contains("0x0000000000008000"))
            && io.lines[3].contains("restore-readback")
            && io.lines[4].contains("known_site_b0=True"),
        "fixed control metadata shape or restoration/report order differs"
    );
    for fail in [1, 2] {
        let mut io = Io::new();
        io.fail_write = fail;
        let mut state = ControlState::new(7)?;
        state.received(7, 3)?;
        let armed = state.creation(&mut io, 7, 0x8000);
        let primary = if fail == 1 {
            armed
        } else {
            armed?;
            state.continued();
            io.trap(&mut state)
        };
        ensure!(primary.is_err(), "partial setter error disappeared");
        io.fail_write = 0;
        state.restore(&mut io)?;
        ensure!(
            activation::raw_debug_equal(&baseline, &io.context)?
                && state.require_complete().is_err(),
            "partial setter failure lost restoration duty or became completion"
        );
    }
    let mut io = Io::new();
    io.normalize = true;
    let mut state = ControlState::new(7)?;
    state.received(7, 3)?;
    ensure!(
        state.creation(&mut io, 7, 0x8000).is_err()
            && io
                .lines
                .last()
                .is_some_and(|line| line.contains("raw_debug_equal=False")
                    && line.contains("dr6_actual=0x00000000FFFF0FF0")),
        "raw normalization was not observed before refusal"
    );
    for mode in 0..6 {
        let mut io = Io::new();
        let mut state = io.arm()?;
        state.received(7, 1)?;
        put(&mut io.context, 104, 0xfffe0ff1);
        put(&mut io.context, 248, 0x8000);
        let (thread, first) = match mode {
            0 => (8, true),
            1 => (7, false),
            2 => {
                put(&mut io.context, 248, 0x8001);
                (7, true)
            }
            3 => {
                put(&mut io.context, 80, 0x9999);
                (7, true)
            }
            4 => {
                put(&mut io.context, 104, 0xfffe0ff2);
                (7, true)
            }
            _ => {
                put(&mut io.context, 112, 0x405);
                (7, true)
            }
        };
        ensure!(
            state.exception(&mut io, thread, 0x80000004, first).is_err(),
            "foreign fixed-control trap was accepted"
        );
        state.restore(&mut io)?;
        ensure!(
            state.require_complete().is_err(),
            "refused trap became completion"
        );
    }
    let mut io = Io::new();
    let mut state = io.arm()?;
    state.received(7, 5)?;
    let writes = io.writes;
    state.restore(&mut io)?;
    ensure!(
        io.writes == writes && state.process_exit(0).is_err(),
        "fixed control restored after destruction or accepted a missing trap"
    );
    Ok(())
}
