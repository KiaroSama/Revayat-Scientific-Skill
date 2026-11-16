//! Original RegistryPolicyLease.CheckValidation and reachable failure protocol, using the transaction itself.
use super::*;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
    for part in parts {
        bytes.extend(part.to_le_bytes());
    }
    bytes
}
fn ace(flags: u8, identity: &[u8]) -> Vec<u8> {
    let mut value = super::super::allow_ace(identity, REGISTRY_READ).unwrap();
    value[1] = flags;
    value
}
pub(super) fn fixture(inherited: bool) -> Vec<u8> {
    let system = sid(5, &[18]);
    let dacl = super::super::encode_acl(
        2,
        &[
            ace(0, &system),
            ace(if inherited { 16 } else { 0 }, &sid(5, &[32, 545])),
        ],
    )
    .unwrap();
    let mut label = ace(0, &sid(16, &[8192]));
    label[0] = 17;
    label[4..8].copy_from_slice(&1u32.to_le_bytes());
    let sacl = super::super::encode_acl(2, &[label]).unwrap();
    let mut bytes = vec![1, 0, 0x14, 0x90];
    bytes.resize(20, 0);
    for (field, value) in [
        (4, system.as_slice()),
        (8, system.as_slice()),
        (12, sacl.as_slice()),
        (16, dacl.as_slice()),
    ] {
        let offset = bytes.len() as u32;
        bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
        bytes.extend(value);
    }
    bytes
}
#[derive(Default)]
struct State {
    current: Vec<u8>,
    receipt: Vec<u8>,
    order: Vec<&'static str>,
    reads: usize,
    writes: usize,
    closes: usize,
    removed: usize,
    fail: Option<(&'static str, anyhow::Error)>,
    supported: bool,
    prewrite: Option<Box<dyn FnOnce() -> Result<()>>>,
}
struct Memory(Rc<RefCell<State>>);
impl Memory {
    fn fail(state: &mut State, name: &'static str) -> Result<()> {
        if state.fail.as_ref().is_some_and(|(point, _)| *point == name) {
            return Err(state.fail.take().unwrap().1);
        }
        Ok(())
    }
}
impl RegistryIo for Memory {
    fn persist(&mut self, bytes: &[u8]) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.order.push("intent");
        Self::fail(&mut state, "persist")?;
        if let Some(prewrite) = state.prewrite.take() {
            prewrite()?;
        }
        ensure!(state.receipt.is_empty(), "receipt collision");
        state.receipt = bytes.into();
        Ok(())
    }
    fn read(&mut self) -> Result<Vec<u8>> {
        let mut state = self.0.borrow_mut();
        state.order.push("read");
        state.reads += 1;
        if state.reads == 3 {
            Self::fail(&mut state, "readback")?;
        }
        Ok(state.current.clone())
    }
    fn write_dacl(&mut self, bytes: &[u8]) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.order.push("write");
        state.writes += 1;
        state.current = bytes.into();
        Self::fail(&mut state, "write")
    }
    fn close(&mut self) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.order.push("close");
        state.closes += 1;
        state.supported = false;
        Self::fail(&mut state, "close")
    }
    fn bind_supported(&mut self) -> Result<()> {
        let mut state = self.0.borrow_mut();
        ensure!(!state.supported, "supported policy already active");
        state.supported = true;
        Ok(())
    }
    fn remove_receipt(&mut self, expected: &[u8]) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.order.push("remove");
        ensure!(state.receipt == expected, "receipt changed");
        state.removed += 1;
        state.receipt.clear();
        Ok(())
    }
}
fn memory(before: &[u8]) -> (Memory, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(State {
        current: before.into(),
        ..Default::default()
    }));
    (Memory(state.clone()), state)
}
fn fault(label: &'static str) -> (anyhow::Error, *const std::io::Error) {
    let error = anyhow::Error::new(std::io::Error::other(label));
    let address = error.downcast_ref::<std::io::Error>().unwrap() as *const _;
    (error, address)
}
fn same_errors(error: &anyhow::Error, expected: &[*const std::io::Error]) -> bool {
    error.downcast_ref::<Failures>().is_some_and(|group| {
        group.errors.len() == expected.len()
            && group.errors.iter().zip(expected).all(|(error, address)| {
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|actual| std::ptr::eq(actual, *address))
            })
    })
}

pub fn check_validation() -> Result<()> {
    use super::super::{Acl, Descriptor};
    let package = sid(15, &[2, 1, 2, 3, 4, 5, 6, 7]);
    let run = "a".repeat(32);
    let nonce = "b".repeat(32);
    let before = fixture(false);
    let after = descriptor_trial(&before, &package, REGISTRY_READ)?;
    let original = Descriptor::parse(&before)?;
    let changed = Descriptor::parse(&after)?;
    let a = Acl::parse(changed.dacl.unwrap())?;
    let b = Acl::parse(original.dacl.unwrap())?;
    ensure!(
        a.aces.len() == 3
            && b.aces.len() == 2
            && a.aces[2].kind == 0
            && a.aces[2].flags == 0
            && a.aces[2].mask()? == REGISTRY_READ
            && a.aces[2].sid()? == package
            && !descriptor_equal(&before, &after)?,
        "registry trial insertion differs"
    );
    let receipt = encode_registry_receipt(&run, &package, &nonce, &before, &after)?;
    let parsed = decode_registry_receipt(&receipt, &run, &package)?;
    ensure!(
        descriptor_equal(&parsed.0, &before)? && descriptor_equal(&parsed.1, &after)?,
        "registry receipt changed policy"
    );
    for text in [
        receipt.replace("sxs-policy", "other"),
        format!("{receipt}extra"),
        receipt.trim_end_matches('\n').into(),
        receipt[..receipt.len() / 2].into(),
        format!("{}{}\n", &receipt[..receipt.len() - 65], "0".repeat(64)),
    ] {
        ensure!(
            decode_registry_receipt(&text, &run, &package).is_err(),
            "malformed registry receipt accepted"
        );
    }
    ensure!(
        decode_registry_receipt(&receipt, &nonce, &package).is_err()
            && descriptor_trial(&after, &package, REGISTRY_READ).is_err()
            && descriptor_equal(&[0; 19], &before).is_err(),
        "registry lease invalid source accepted"
    );
    let mut missing = before.clone();
    missing[16..20].fill(0);
    ensure!(
        descriptor_equal(&missing, &before).is_err(),
        "null registry DACL accepted"
    );
    let inherited = fixture(true);
    let inserted = descriptor_trial(&inherited, &package, REGISTRY_READ)?;
    let d = Descriptor::parse(&inserted)?;
    let acl = Acl::parse(d.dacl.unwrap())?;
    ensure!(
        acl.aces[1].sid()? == package && acl.aces[2].flags & 16 != 0,
        "registry trial crossed inherited ACE boundary"
    );

    let (io, state) = memory(&before);
    let mut lease = RegistryLease::begin(io, &run, &package, &nonce)?;
    ensure!(
        state.borrow().order == ["read", "intent", "read", "write", "read"]
            && descriptor_equal(&state.borrow().current, &after)?,
        "registry install ordering differs"
    );
    lease.finish(true)?;
    ensure!(
        state.borrow().writes == 2
            && state.borrow().closes == 1
            && state.borrow().removed == 1
            && descriptor_equal(&state.borrow().current, &before)?,
        "registry lease completion differs"
    );
    drop(lease);
    ensure!(state.borrow().closes == 1, "registry lease closed twice");

    for point in ["write", "readback"] {
        let (io, state) = memory(&before);
        let operation = anyhow::Error::new(std::io::Error::other("fixed operation"));
        let address = operation.downcast_ref::<std::io::Error>().unwrap() as *const _;
        state.borrow_mut().fail = Some((point, operation));
        let caught = match RegistryLease::begin(io, &run, &package, &nonce) {
            Err(error) => error,
            Ok(_) => anyhow::bail!("partial installation unexpectedly succeeded"),
        };
        ensure!(
            caught
                .downcast_ref::<std::io::Error>()
                .map(|e| e as *const _)
                == Some(address)
                && state.borrow().writes == 2
                && state.borrow().closes == 1
                && descriptor_equal(&state.borrow().current, &before)?,
            "partial registry write failed to preserve and restore"
        );
    }
    let (mut io, state) = memory(&before);
    restore(&mut io, &before, &after, false)?;
    ensure!(
        state.borrow().writes == 0,
        "idempotent registry restore wrote policy"
    );
    state.borrow_mut().current = after.clone();
    ensure!(
        restore(&mut io, &before, &after, false).is_err() && state.borrow().writes == 0,
        "unqualified registry restoration wrote policy"
    );
    restore(&mut io, &before, &after, true)?;
    ensure!(
        state.borrow().writes == 1 && descriptor_equal(&state.borrow().current, &before)?,
        "registry restoration failed"
    );
    let foreign = descriptor_trial(&before, &sid(15, &[2, 7, 6, 5, 4, 3, 2, 1]), REGISTRY_READ)?;
    state.borrow_mut().current = foreign;
    ensure!(
        restore(&mut io, &before, &after, true).is_err() && state.borrow().writes == 1,
        "foreign registry policy was overwritten"
    );
    let (io, state) = memory(&before);
    let mut lease = RegistryLease::begin(io, &run, &package, &nonce)?;
    state.borrow_mut().current = before.clone();
    ensure!(
        lease.finish(false).is_err()
            && state.borrow().removed == 0
            && state.borrow().writes == 1
            && state.borrow().closes == 1,
        "unqualified idempotent restore retired intent"
    );
    let (io, state) = memory(&before);
    let operation = anyhow::Error::new(std::io::Error::other("fixed intent"));
    let address = operation.downcast_ref::<std::io::Error>().unwrap() as *const _;
    state.borrow_mut().fail = Some(("persist", operation));
    let caught = RegistryLease::begin(io, &run, &package, &nonce)
        .err()
        .unwrap();
    ensure!(
        caught
            .downcast_ref::<std::io::Error>()
            .map(|e| e as *const _)
            == Some(address)
            && state.borrow().writes == 0
            && state.borrow().closes == 1,
        "failed intent allowed registry mutation"
    );

    let order = RefCell::new(Vec::new());
    let (operation, operation_address) = fault("operation");
    let (finalization, finalization_address) = fault("finalization");
    let (closing, closing_address) = fault("closing");
    let error = cleanup_owned(
        || {
            order.borrow_mut().push("recovery");
            Err(operation)
        },
        || {
            order.borrow_mut().push("snaps");
            Err(finalization)
        },
        || {
            order.borrow_mut().push("profile");
            Ok(())
        },
        || {
            order.borrow_mut().push("disk");
            Err(closing)
        },
        || {
            order.borrow_mut().push("remove");
            Ok(())
        },
    )
    .unwrap_err();
    let failures = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        same_errors(
            &error,
            &[operation_address, finalization_address, closing_address]
        ) && *order.borrow() == ["recovery", "snaps", "disk"]
            && failures
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                == ["operation", "finalization", "closing"],
        "owned registry cleanup gating or failure order differs"
    );
    let order = RefCell::new(Vec::new());
    let (primary, primary_address) = fault("primary");
    let (cleanup, cleanup_address) = fault("cleanup");
    let cleanup = RefCell::new(Some(cleanup));
    let mut actions: [&mut dyn FnMut() -> Result<()>; 3] = [
        &mut || {
            order.borrow_mut().push(0);
            Err(cleanup.borrow_mut().take().unwrap())
        },
        &mut || {
            order.borrow_mut().push(1);
            Ok(())
        },
        &mut || {
            order.borrow_mut().push(2);
            Ok(())
        },
    ];
    let error = finish(Some(primary), &mut actions).unwrap_err();
    ensure!(
        same_errors(&error, &[primary_address, cleanup_address])
            && *order.borrow() == [0, 1, 2]
            && error
                .downcast_ref::<Failures>()
                .unwrap()
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                == ["primary", "cleanup"],
        "independent registry cleanup was skipped"
    );
    let original = anyhow::Error::new(std::io::Error::other("original without cleanup failures"));
    let address = original.downcast_ref::<std::io::Error>().unwrap() as *const _;
    let retained = finish(Some(original), &mut [])?.unwrap();
    ensure!(
        retained
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| std::ptr::eq(error, address)),
        "successful finalization dropped or replaced its caller-owned primary"
    );
    let closes = RefCell::new(0);
    let (operation, operation_address) = fault("operation");
    let (finalization, finalization_address) = fault("finalization");
    let (closing, closing_address) = fault("closing");
    let error = acquire(
        |h| {
            *h = 1;
            Err(operation)
        },
        || Err(finalization),
        |h| {
            ensure!(h == 1);
            *closes.borrow_mut() += 1;
            Err(closing)
        },
    )
    .unwrap_err();
    ensure!(
        same_errors(
            &error,
            &[operation_address, finalization_address, closing_address]
        ) && *closes.borrow() == 1
            && error
                .downcast_ref::<Failures>()
                .unwrap()
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                == ["operation", "finalization", "closing"],
        "partial registry acquisition failure order differs"
    );
    let (operation, address) = {
        let error = anyhow::Error::new(std::io::Error::other("finalization"));
        let address = error.downcast_ref::<std::io::Error>().unwrap() as *const _;
        (error, address)
    };
    let closes = Cell::new(0);
    let error = acquire(
        |handle| {
            *handle = 1;
            Ok(())
        },
        || Err(operation),
        |handle| {
            ensure!(handle == 1);
            closes.set(closes.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        closes.get() == 1
            && error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| std::ptr::eq(e, address)),
        "registry finalization failure replaced error or skipped partial handle close"
    );
    let mut dummy = ();
    let (operation, operation_address) = fault("operation");
    let (recovery, recovery_address) = fault("recovery");
    let (closing, closing_address) = fault("closing");
    let error = establish(
        &mut dummy,
        |_| Err(operation),
        |_| true,
        |_| Err(recovery),
        |_| Err(closing),
    )
    .unwrap_err();
    ensure!(
        same_errors(
            &error,
            &[operation_address, recovery_address, closing_address]
        ) && error
            .downcast_ref::<Failures>()
            .unwrap()
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            == ["operation", "recovery", "closing"],
        "registry establishment lost independent recovery/close errors"
    );
    let order = RefCell::new(Vec::new());
    let (operation, operation_address) = fault("operation");
    let (closing, closing_address) = fault("closing");
    let error = complete_lease(
        &mut (),
        true,
        |_| {
            order.borrow_mut().push("restore");
            Err(operation)
        },
        |_| {
            order.borrow_mut().push("close");
            Err(closing)
        },
        |_| {
            order.borrow_mut().push("remove");
            Ok(())
        },
    )
    .unwrap_err();
    ensure!(
        same_errors(&error, &[operation_address, closing_address])
            && *order.borrow() == ["restore", "close"]
            && error
                .downcast_ref::<Failures>()
                .unwrap()
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                == ["operation", "closing"],
        "failed registry retirement removed receipt or skipped close"
    );
    for mode in 0..4 {
        let (io, state) = memory(&before);
        let malformed = receipt.clone();
        let package = package.clone();
        let run = run.clone();
        state.borrow_mut().prewrite = Some(Box::new(move || match mode {
            0 => require_absent(|| Ok(0x80)),
            1 => require_plain_attributes(0x400),
            2 => decode_registry_receipt(&malformed[..malformed.len() / 2], &run, &package)
                .map(|_| ()),
            _ => decode_registry_receipt(
                &format!("{}{}\n", &malformed[..malformed.len() - 65], "0".repeat(64)),
                &run,
                &package,
            )
            .map(|_| ()),
        }));
        ensure!(
            RegistryLease::begin(
                io,
                &"a".repeat(32),
                &sid(15, &[2, 1, 2, 3, 4, 5, 6, 7]),
                &nonce
            )
            .is_err()
                && state.borrow().writes == 0
                && state.borrow().receipt.is_empty()
                && state.borrow().closes == 1,
            "registry prewrite rejection persisted intent or mutated policy mode={mode}"
        );
    }
    Ok(())
}
