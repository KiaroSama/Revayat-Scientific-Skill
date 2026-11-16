//! Bounded primary-first operation/cleanup aggregation with original Python references retained.
use super::{
    classify,
    object::{Exception, Fault, Owned, Result, require},
    wire::{Role, Text},
};

struct Event {
    phase: &'static str,
    kind: Option<&'static str>,
    original: Option<Exception>,
    native: Option<u32>,
}
pub struct Events {
    // Metadata is capped at eight; private originals cover every callback in the
    // closed bounded cleanup plan instead of discarding later cleanup failures.
    entries: [Option<Event>; 32],
    length: usize,
    overflow: bool,
    pub child_exit: Option<u32>,
}
impl Events {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            length: 0,
            overflow: false,
            child_exit: None,
        }
    }
    fn push(&mut self, event: Event) {
        if self.length < self.entries.len() {
            self.entries[self.length] = Some(event);
            self.length += 1;
        } else {
            self.overflow = true;
        }
    }
    fn append(&mut self, fault: Fault, phase: &'static str, cleanup: bool) {
        match fault {
            Fault::Control => self.push(Event {
                phase: if cleanup { "close" } else { phase },
                kind: Some(if cleanup { "cleanup" } else { "control" }),
                original: None,
                native: None,
            }),
            Fault::Python(error) => self.push(Event {
                phase: if cleanup { "close" } else { phase },
                kind: if cleanup { Some("cleanup") } else { None },
                original: Some(error),
                native: None,
            }),
            Fault::Events(mut errors) => {
                self.overflow |= errors.overflow;
                if self.child_exit.is_none() {
                    self.child_exit = errors.child_exit;
                }
                for event in errors.entries.iter_mut().take(errors.length) {
                    if let Some(mut event) = event.take() {
                        if cleanup {
                            event.phase = "close";
                            event.kind = Some("cleanup");
                            event.native = None;
                        }
                        self.push(event);
                    }
                }
            }
        }
    }
    pub fn from_fault(fault: Fault, phase: &'static str) -> Self {
        let mut events = Self::new();
        events.append(fault, phase, false);
        events
    }
    pub fn append_fault(&mut self, fault: Fault, phase: &'static str) {
        self.append(fault, phase, false);
    }
    pub fn cleanup(&mut self, fault: Fault) {
        self.append(fault, "close", true);
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn label(&mut self, phase: &'static str, kind: &'static str) {
        self.push(Event {
            phase,
            kind: Some(kind),
            original: None,
            native: None,
        });
    }
    pub fn loader(&mut self, phase: &'static str, code: u32) {
        self.push(Event {
            phase,
            kind: None,
            original: None,
            native: Some(code),
        });
    }
    pub fn wire(&self, role: Role, subprocess: &Owned) -> Result<Text<512>> {
        require(self.length != 0 && !self.overflow)?;
        let mut resolved = Resolved::new();
        for event in self.entries.iter().take(self.length) {
            let event = event.as_ref().ok_or(Fault::Control)?;
            if let Some(kind) = event.kind {
                resolved.push(event.phase, kind, event.native);
            } else if let Some(code) = event.native {
                resolved.push(event.phase, "", Some(code));
            } else {
                resolved.exception(
                    event.original.as_ref().ok_or(Fault::Control)?,
                    event.phase,
                    subprocess,
                    0,
                )?;
            }
        }
        resolved.validate()?;
        let mut text = Text::new();
        for fragment in [
            "REGISTRY_AUTHORITY_FAILURE role=",
            role.name(),
            " child_exit=",
        ] {
            text.push(fragment)?;
        }
        if let Some(exit) = self.child_exit {
            text.hex(exit as u64, 8)?;
        } else {
            text.push("none")?;
        }
        text.push(" errors=")?;
        for (index, event) in resolved.entries.iter().take(resolved.length).enumerate() {
            let (phase, kind, native) = event.ok_or(Fault::Control)?;
            if index != 0 {
                text.push(",")?;
            }
            if let Some(code) = native {
                for fragment in [phase, ":win32-"] {
                    text.push(fragment)?;
                }
                text.hex(code as u64, 8)?;
            } else {
                for fragment in [phase, ":", kind] {
                    text.push(fragment)?;
                }
            }
        }
        text.push("\n")?;
        Ok(text)
    }
}
struct Resolved {
    entries: [Option<(&'static str, &'static str, Option<u32>)>; 8],
    length: usize,
}
impl Resolved {
    fn new() -> Self {
        Self {
            entries: [None; 8],
            length: 0,
        }
    }
    fn push(&mut self, phase: &'static str, kind: &'static str, native: Option<u32>) {
        if self.length < 8 {
            self.entries[self.length] = Some((phase, kind, native));
            self.length += 1;
        }
    }
    fn exception(
        &mut self,
        original: &Exception,
        phase: &'static str,
        subprocess: &Owned,
        depth: usize,
    ) -> Result<()> {
        require(depth < 64)?;
        let value = original.value.as_ref().ok_or(Fault::Control)?;
        let group = Owned::import(c"builtins")?.attr(c"ExceptionGroup")?;
        if value.instance(group.pointer())? {
            let exceptions = value.attr(c"exceptions")?;
            let length = exceptions.length()?;
            require((1..=100000).contains(&length))?;
            for index in 0..length {
                self.exception(
                    &Exception::from_value(&exceptions.index(index)?)?,
                    phase,
                    subprocess,
                    depth + 1,
                )?;
            }
        } else {
            self.push(phase, classify::general(original, subprocess)?, None);
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        require((1..=8).contains(&self.length))?;
        let mut loader = Text::<256>::new();
        let mut found = false;
        let mut ended = false;
        for (phase, kind, native) in self.entries.iter().take(self.length).flatten() {
            if *phase == "loader" || *phase == "loader-release" {
                require(!ended)?;
                if found {
                    loader.push(",")?;
                }
                if let Some(code) = native {
                    for fragment in [*phase, ":win32-"] {
                        loader.push(fragment)?;
                    }
                    loader.hex(*code as u64, 8)?;
                } else {
                    for fragment in [*phase, ":", *kind] {
                        loader.push(fragment)?;
                    }
                }
                found = true;
            } else {
                if found {
                    ended = true;
                }
                require(native.is_none() && super::child_wire::allowed_event(phase, kind))?;
            }
        }
        require(!found || super::child_wire::loader(loader.text()).is_some())
    }
}
pub fn close_result<T>(
    operation: Result<T>,
    cleanup: Result<()>,
    phase: &mut &'static str,
) -> Result<T> {
    match cleanup {
        Ok(()) => operation,
        Err(cleanup) => {
            let mut errors = Events::new();
            if let Err(original) = operation {
                errors.append(original, phase, false);
            }
            errors.append(cleanup, "close", true);
            Err(Fault::Events(errors))
        }
    }
}
