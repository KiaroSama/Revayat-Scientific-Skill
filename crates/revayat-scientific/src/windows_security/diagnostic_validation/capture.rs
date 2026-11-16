//! Owned capture cleanup seams from Capture.cs:66–78,119–178.
use crate::windows_security::scratch::{self, OperationResult, SharedError};
use anyhow::{Result, ensure};
use std::cell::{Cell, RefCell};

/// Consume the numeric handle before calling the OS; uncertainty is sticky even
/// if the callback throws, because retrying that number could close another object.
pub fn close_strict(
    handle: &mut usize,
    uncertain: &mut bool,
    close: impl FnOnce(usize) -> OperationResult<bool>,
) -> OperationResult<()> {
    let owned = std::mem::take(handle);
    if owned == 0 {
        return Ok(());
    }
    match close(owned) {
        Ok(true) => Ok(()),
        Ok(false) => {
            *uncertain = true;
            Err(scratch::failure(
                "fixed activation capture close remains uncertain",
            ))
        }
        Err(error) => {
            *uncertain = true;
            Err(error)
        }
    }
}
pub fn require_closed(uncertain: bool) -> OperationResult<()> {
    if uncertain {
        Err(scratch::failure(
            "fixed activation capture close remains uncertain",
        ))
    } else {
        Ok(())
    }
}
pub fn finish_strict<'a>(
    actions: Vec<Box<dyn FnMut() -> OperationResult<()> + 'a>>,
) -> OperationResult<()> {
    let mut errors = Vec::new();
    for mut action in actions {
        scratch::attempt(&mut errors, action.as_mut());
    }
    scratch::finish(Ok(()), errors)
}
pub fn capture_prefix(bytes: &[u8]) -> (Vec<u8>, bool) {
    (bytes[..bytes.len().min(512)].to_vec(), bytes.len() > 512)
}
/// Every callback is attempted in the same fixed DisposeStrict order, including
/// both failure-receipt snapshots. The caller supplies actual drain/close I/O.
pub fn dispose_strict(
    mut operations: [Box<dyn FnMut() -> OperationResult<()> + '_>; 8],
) -> OperationResult<()> {
    let mut errors = Vec::new();
    for index in [0, 1, 2, 3, 4, 0, 5, 6, 7] {
        scratch::attempt(&mut errors, operations[index].as_mut());
    }
    scratch::finish(Ok(()), errors)
}
pub fn check_strict_capture_cleanup() -> Result<SharedError> {
    let mut actual_failure = None;
    for mode in 0..=3 {
        let writer = Cell::new(11usize);
        let reader = Cell::new(12usize);
        let uncertain = Cell::new(false);
        let order = RefCell::new(Vec::new());
        let attempted = RefCell::new(Vec::new());
        let close = |handle| {
            attempted.borrow_mut().push(handle);
            order
                .borrow_mut()
                .push(if handle == 11 { "writer" } else { "reader" });
            Ok(!(if handle == 11 {
                mode == 1 || mode == 3
            } else {
                mode == 2 || mode == 3
            }))
        };
        let close_cell = |handle: &Cell<usize>| {
            let mut owned = handle.get();
            let mut sticky = uncertain.get();
            let result = close_strict(&mut owned, &mut sticky, close);
            handle.set(owned);
            uncertain.set(sticky);
            result
        };
        let caught = finish_strict(vec![
            Box::new(|| close_cell(&writer)),
            Box::new(|| {
                order.borrow_mut().push("cancel");
                Ok(())
            }),
            Box::new(|| close_cell(&reader)),
            Box::new(|| {
                order.borrow_mut().push("join");
                Ok(())
            }),
            Box::new(|| {
                order.borrow_mut().push("buffer");
                Ok(())
            }),
            Box::new(|| require_closed(uncertain.get())),
        ])
        .err();
        let repeated = finish_strict(vec![
            Box::new(|| close_cell(&writer)),
            Box::new(|| close_cell(&reader)),
            Box::new(|| require_closed(uncertain.get())),
        ])
        .err();
        ensure!(
            writer.get() == 0
                && reader.get() == 0
                && *attempted.borrow() == [11, 12]
                && *order.borrow() == ["writer", "cancel", "reader", "join", "buffer"]
                && uncertain.get() == (mode != 0)
                && caught.is_some() == (mode != 0)
                && repeated.is_some() == (mode != 0),
            "capture strict-close ownership or sticky failure differs"
        );
        if mode == 3 {
            actual_failure = caught;
        }
    }
    for length in [0, 127, 512, 513, 1024] {
        let input = (0..length).map(|index| index as u8).collect::<Vec<_>>();
        let (prefix, truncated) = capture_prefix(&input);
        ensure!(
            prefix.len() == length.min(512)
                && truncated == (length > 512)
                && input.len() == length
                && prefix == input[..prefix.len()],
            "bounded capture prefix differs or invented bytes"
        );
    }
    actual_failure.ok_or_else(|| anyhow::anyhow!("capture fixture lost its actual aggregate"))
}
