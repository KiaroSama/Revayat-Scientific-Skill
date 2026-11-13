//! Frozen Sandbox.CheckCompletionValidation and CheckPolicyCompletion products.
use super::*;
use crate::windows_security::activation::dispatch::QualifiedFailure;
use std::{cell::Cell, time::Duration};
const FRAME:&[u8]=b"REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native\n";
struct CheckIo {
    mode: Option<u8>,
    role: &'static str,
    order: Vec<&'static str>,
    fault: Option<anyhow::Error>,
    fail_release: bool,
    closed: usize,
}
impl CheckIo {
    fn fail(&mut self) -> Result<()> {
        Err(self
            .fault
            .take()
            .expect("fixed fixture fault is consumed exactly once"))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureStep {
    Snapshot,
    Writer,
    Cancel,
    Reader,
    Join,
    Drain,
    Buffer,
    Close,
}
impl CaptureStep {
    fn name(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Writer => "writer",
            Self::Cancel => "cancel",
            Self::Reader => "reader",
            Self::Join => "join",
            Self::Drain => "drain",
            Self::Buffer => "buffer",
            Self::Close => "capture-close",
        }
    }
}
struct Capture<'a, 'b> {
    io: &'a mut CheckIo,
    retain: ReceiptRetainer<'b>,
}
impl Capture<'_, '_> {
    fn step(&mut self, step: CaptureStep) -> Result<()> {
        self.io.order.push(step.name());
        if step == CaptureStep::Snapshot
            && self.io.mode != Some(5)
            && let Some(retain) = self.retain.as_mut()
        {
            retain(FRAME, self.io.mode == Some(6));
        }
        if step == CaptureStep::Join && self.io.mode == Some(7) {
            return self.io.fail();
        }
        Ok(())
    }
}
impl StrictCaptureIo for Capture<'_, '_> {
    fn snapshot(&mut self) -> Result<()> {
        self.step(CaptureStep::Snapshot)
    }
    fn close_writer(&mut self) -> Result<()> {
        self.step(CaptureStep::Writer)
    }
    fn cancel(&mut self) -> Result<()> {
        self.step(CaptureStep::Cancel)
    }
    fn close_reader(&mut self) -> Result<()> {
        self.step(CaptureStep::Reader)
    }
    fn join(&mut self) -> Result<()> {
        self.step(CaptureStep::Join)
    }
    fn check_drain(&mut self) -> Result<()> {
        self.step(CaptureStep::Drain)
    }
    fn dispose_buffer(&mut self) -> Result<()> {
        self.step(CaptureStep::Buffer)
    }
    fn check_closed(&mut self) -> Result<()> {
        self.step(CaptureStep::Close)
    }
}
impl CompletionIo for CheckIo {
    fn terminate(&mut self) -> Result<()> {
        self.order.push("terminate");
        Ok(())
    }
    fn reap(&mut self) -> Result<()> {
        self.order.push("reap");
        if self.mode == Some(2) {
            self.fail()
        } else {
            Ok(())
        }
    }
    fn confirm_destroyed(&mut self) -> Option<Result<()>> {
        if self.role == "trace" || self.role == "callback" {
            self.order.push("destroy");
            Some(Ok(()))
        } else {
            None
        }
    }
    fn query_exit(&mut self) -> Result<Option<u32>> {
        self.order.push("query");
        ensure!(self.mode.is_some(), "unexpected authority query");
        if self.mode == Some(3) {
            return self.fail().map(|_| None);
        }
        Ok(if self.mode == Some(4) {
            None
        } else {
            Some(125)
        })
    }
    fn close_output(&mut self) -> Result<()> {
        self.order.push("stdout");
        Ok(())
    }
    fn close_error(&mut self, retain: ReceiptRetainer<'_>) -> Result<()> {
        self.order.push("stderr");
        self.closed += 1;
        if self.mode.is_some() {
            dispose_strict(&mut Capture { io: self, retain })
        } else {
            ensure!(
                retain.is_none(),
                "successful or nonauthority completion retained a receipt"
            );
            Ok(())
        }
    }
    fn release_count(&self) -> usize {
        if self.mode.is_some() { 4 } else { 2 }
    }
    fn release(&mut self, index: usize) -> Result<()> {
        if self.mode.is_some() {
            self.order
                .push(["thread", "process", "job", "lease"][index]);
            if index == 2 && self.mode == Some(8) {
                return self.fail();
            }
        } else {
            self.order.push(["thread", "lease"][index]);
            if index == 0 && self.fail_release {
                return self.fail();
            }
        }
        Ok(())
    }
    fn metadata(&mut self) -> Result<String> {
        ensure!(self.role == "trace", "unexpected completion metadata");
        Ok("fixed".into())
    }
    fn emit(&mut self, _: &str) -> Result<()> {
        self.order.push("emit");
        Ok(())
    }
}
fn fault(text: &'static str) -> (anyhow::Error, *const std::io::Error) {
    let error = anyhow::Error::new(std::io::Error::other(text));
    let address = error.downcast_ref::<std::io::Error>().unwrap() as *const _;
    (error, address)
}
fn same(error: &anyhow::Error, address: *const std::io::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|value| std::ptr::eq(value, address))
}
/// Inert original callback fixture: qualification is produced by the real completion
/// path after every destruction/release callback, never by constructing a carrier in a test.
pub fn check_callback_completion(operation: anyhow::Error) -> Result<anyhow::Error> {
    let address = operation.as_ref() as *const (dyn std::error::Error + Send + Sync);
    let mut io = CheckIo {
        mode: None,
        role: "callback",
        order: Vec::new(),
        fault: None,
        fail_release: false,
        closed: 0,
    };
    let completed = complete_run(
        Some(operation),
        Flags {
            callback: true,
            started: true,
            signaled: true,
            ..Flags::default()
        },
        &mut io,
    );
    ensure!(
        completed.reaped
            && completed.destroyed
            && io.order
                == [
                    "terminate",
                    "reap",
                    "destroy",
                    "stdout",
                    "stderr",
                    "thread",
                    "lease"
                ],
        "callback fixture did not complete destruction/release ordering"
    );
    let error = completed
        .failure
        .ok_or_else(|| anyhow::anyhow!("callback fixture lost its diagnostic"))?;
    let qualified = error
        .downcast_ref::<QualifiedModuleCallbackFailure<anyhow::Error>>()
        .ok_or_else(|| anyhow::anyhow!("callback fixture did not qualify cleanup"))?;
    ensure!(
        std::ptr::addr_eq(
            qualified.original.as_ref() as *const (dyn std::error::Error + Send + Sync),
            address
        ),
        "callback completion replaced original"
    );
    Ok(error)
}
fn policies() -> Result<()> {
    use std::cell::RefCell;
    for mode in 0..5 {
        let (original, address) = fault("fixed operation");
        let (cleanup, cleanup_address) = fault("fixed restoration");
        let cleanup = RefCell::new(Some(cleanup));
        let order = RefCell::new(Vec::new());
        let mut restore = |clean| {
            order
                .borrow_mut()
                .push(format!("restore:{}", if clean { "True" } else { "False" }));
            if mode == 2 {
                Err(cleanup.borrow_mut().take().unwrap())
            } else {
                Ok(())
            }
        };
        let mut volume = |clean| {
            order
                .borrow_mut()
                .push(format!("volume:{}", if clean { "True" } else { "False" }));
            if mode == 3 {
                Err(cleanup.borrow_mut().take().unwrap())
            } else {
                Ok(())
            }
        };
        let mut registry = |clean| {
            order
                .borrow_mut()
                .push(format!("registry:{}", if clean { "True" } else { "False" }));
            if mode == 4 {
                Err(cleanup.borrow_mut().take().unwrap())
            } else {
                Ok(())
            }
        };
        let result = complete_policies(
            if mode == 0 { None } else { Some(original) },
            mode != 1,
            &mut [&mut restore, &mut volume, &mut registry],
        );
        let expected = match mode {
            1 => "restore:False,volume:False,registry:False",
            2 => "restore:True,volume:False,registry:False",
            3 => "restore:True,volume:True,registry:False",
            _ => "restore:True,volume:True,registry:True",
        };
        ensure!(
            order.borrow().join(",") == expected,
            "policy completion lost sticky uncertainty"
        );
        if mode == 0 {
            ensure!(
                result.is_ok(),
                "successful policy completion invented a failure"
            );
        } else if mode == 1 {
            ensure!(
                same(&result.unwrap_err(), address),
                "policy completion replaced original"
            );
        } else {
            let error = result.unwrap_err();
            let group = error.downcast_ref::<Failures>().unwrap();
            ensure!(
                group.errors.len() == 2
                    && same(&group.errors[0], address)
                    && same(&group.errors[1], cleanup_address),
                "policy completion failure order/identity differs"
            );
        }
    }
    Ok(())
}
pub fn check_validation() -> Result<()> {
    policies()?;
    let queries = Cell::new(0);
    ensure!(
        actual_exit(
            false,
            || anyhow::bail!("unexpected signal"),
            || {
                queries.set(1);
                Ok(1)
            }
        )?
        .is_none(),
        "unstarted process was queried"
    );
    ensure!(
        actual_exit(
            true,
            || Ok(0x102),
            || {
                queries.set(1);
                Ok(259)
            }
        )?
        .is_none()
            && queries.get() == 0,
        "live process exit was queried"
    );
    ensure!(
        actual_exit(
            true,
            || Ok(0),
            || {
                queries.set(queries.get() + 1);
                Ok(259)
            }
        )? == Some(259)
            && queries.get() == 1,
        "natural exit259 was treated as still-active"
    );
    for query_failure in [false, true] {
        ensure!(
            actual_exit(
                true,
                || Ok(if query_failure { 0 } else { u32::MAX }),
                || anyhow::bail!("fixed query failed")
            )
            .is_err(),
            "failed signal/query accepted"
        );
    }
    for mode in 0..10 {
        let operation = if mode == 9 {
            let invalid = vec![0xed, 0xa0, 0x80];
            anyhow::Error::new(String::from_utf8(invalid).unwrap_err())
        } else if mode == 1 {
            anyhow::anyhow!("private-abort")
        } else {
            anyhow::Error::new(crate::runtime::DeadlineExceeded {
                idle: false,
                limit: Duration::from_secs(1),
            })
        };
        let operation_address = operation.as_ref() as *const (dyn std::error::Error + Send + Sync);
        let mut io = CheckIo {
            mode: Some(mode),
            role: "authority",
            order: Vec::new(),
            fault: Some(anyhow::anyhow!("private-close")),
            fail_release: false,
            closed: 0,
        };
        let result = complete_run(
            Some(operation),
            Flags {
                authority: true,
                undebugged: true,
                started: true,
                ..Flags::default()
            },
            &mut io,
        );
        let error = result
            .failure
            .ok_or_else(|| anyhow::anyhow!("failed authority completion lost operation"))?;
        ensure!(
            !error.is::<QualifiedFailure>()
                && io.order.join(",")
                    == "terminate,reap,query,stdout,stderr,snapshot,writer,cancel,reader,join,snapshot,drain,buffer,capture-close,thread,process,job,lease",
            "authority completion ordering/qualification differs"
        );
        let report = wire::safe_report(&error);
        ensure!(
            !report.contains("private")
                && !report.contains("[ED]")
                && !report.contains("[A0]")
                && !report.contains("[80]"),
            "authority completion leaked private causes"
        );
        if mode != 5 {
            ensure!(
                report.contains("errors=import-ctypes:import-ctypes-native")
                    && report.contains(if mode == 3 || mode == 4 {
                        "primary_exit=none"
                    } else {
                        "primary_exit=0x0000007D"
                    }),
                "authority receipt lost actual exit/prefix"
            );
        }
        if mode == 9 {
            let group = error.downcast_ref::<Failures>().unwrap();
            let retained = group.errors[1]
                .downcast_ref::<wire::PrivateFailure>()
                .unwrap();
            ensure!(
                std::ptr::addr_eq(
                    retained.original().as_ref() as *const (dyn std::error::Error + Send + Sync),
                    operation_address
                ),
                "authority completion replaced malformed-capture operation"
            );
        }
    }
    let mut io = CheckIo {
        mode: None,
        role: "normal",
        order: Vec::new(),
        fault: None,
        fail_release: false,
        closed: 0,
    };
    let result = complete_run(
        None,
        Flags {
            authority: true,
            undebugged: true,
            started: true,
            signaled: true,
            ..Flags::default()
        },
        &mut io,
    );
    ensure!(
        result.failure.is_none()
            && result.primary.is_none()
            && io.closed == 1
            && !io.order.contains(&"query"),
        "successful completion invented receipt or query"
    );
    for role in ["ordinary", "callback", "trace", "undebugged"] {
        for fail_cleanup in [false, true] {
            let (operation, address) = fault("fixed operation");
            let (cleanup, cleanup_address) = fault("fixed cleanup");
            let mut io = CheckIo {
                mode: None,
                role,
                order: Vec::new(),
                fault: Some(cleanup),
                fail_release: fail_cleanup,
                closed: 0,
            };
            let result = complete_run(
                Some(operation),
                Flags {
                    trace: role == "trace",
                    observed: true,
                    callback: role == "callback",
                    undebugged: role == "undebugged",
                    started: true,
                    signaled: true,
                    authority: false,
                },
                &mut io,
            );
            let expected = format!(
                "terminate,reap,{}stdout,stderr,thread,lease{}",
                if role == "trace" || role == "callback" {
                    "destroy,"
                } else {
                    ""
                },
                if role == "trace" && !fail_cleanup {
                    ",emit"
                } else {
                    ""
                }
            );
            ensure!(
                io.order.join(",") == expected,
                "completion role finalization order differs"
            );
            if fail_cleanup {
                let error = result.failure.unwrap();
                let group = error.downcast_ref::<Failures>().unwrap();
                ensure!(
                    group.errors.len() == 2
                        && same(&group.errors[0], address)
                        && same(&group.errors[1], cleanup_address),
                    "completion cleanup replaced/reordered originals"
                );
            } else if role == "ordinary" {
                ensure!(
                    result.failure.is_none()
                        && result
                            .primary
                            .as_ref()
                            .is_some_and(|error| same(error, address)),
                    "ordinary completion dropped the outer original"
                );
            } else if role == "callback" {
                let error = result.failure.unwrap();
                let carrier = error
                    .downcast_ref::<QualifiedModuleCallbackFailure<anyhow::Error>>()
                    .unwrap();
                ensure!(
                    same(&carrier.original, address),
                    "callback completion replaced original"
                );
            } else {
                let error = result.failure.unwrap();
                ensure!(
                    error
                        .downcast_ref::<QualifiedFailure>()
                        .is_some_and(|failure| same(failure.original(), address)),
                    "trace/undebugged completion qualification or original differs"
                );
            }
        }
    }
    Ok(())
}
