use super::*;
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};
#[derive(Clone, Debug)]
struct Failure(Arc<()>);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private-canary-operation")
    }
}
impl std::error::Error for Failure {}
fn error(id: &Arc<()>) -> anyhow::Error {
    Failure(id.clone()).into()
}
fn same(error: &anyhow::Error, id: &Arc<()>) -> bool {
    error
        .downcast_ref::<Failure>()
        .is_some_and(|f| Arc::ptr_eq(&f.0, id))
}
struct Scope {
    mode: u8,
    order: std::rc::Rc<RefCell<String>>,
    operation: Arc<()>,
    fatal: Arc<()>,
}
impl ScopeIo for Scope {
    type Output = ();
    fn enter(&mut self) -> Result<bool> {
        self.order.borrow_mut().push('e');
        if self.mode == 1 {
            return Err(error(&self.operation));
        }
        Ok(self.mode != 9)
    }
    fn effective(&mut self) -> Result<()> {
        self.order.borrow_mut().push('q');
        if self.mode == 2 {
            return Err(error(&self.operation));
        }
        Ok(())
    }
    fn body(&mut self) -> Result<()> {
        self.order.borrow_mut().push('b');
        if self.mode == 3 {
            return Err(error(&self.operation));
        }
        Ok(())
    }
    fn revert(&mut self) -> Result<bool> {
        self.order.borrow_mut().push('r');
        if self.mode == 4 {
            return Err(error(&self.operation));
        }
        Ok(!matches!(self.mode, 5 | 8))
    }
    fn absent(&mut self) -> Result<()> {
        self.order.borrow_mut().push('a');
        if self.mode == 6 {
            return Err(error(&self.operation));
        }
        Ok(())
    }
    fn fatal(&mut self) -> Result<()> {
        self.order.borrow_mut().push('f');
        if self.mode != 8 {
            return Err(error(&self.fatal));
        }
        Ok(())
    }
}
pub fn check_validation() -> Result<()> {
    ensure!(
        std::mem::size_of::<usize>() == 8,
        "canary source requires x64"
    );
    absent(false, 1008, 0)?;
    for (opened, error, token) in [
        (true, 0, 1),
        (false, 5, 0),
        (false, 1008, 1),
        (false, 1008, usize::MAX),
    ] {
        ensure!(
            absent(opened, error, token).is_err(),
            "canary absent-token predicate differs"
        );
    }
    let user = [
        1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 233, 3, 0, 0,
    ];
    let other = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    identity(&user, &user, &other, 1, 0, false, false)?;
    identity(&user, &user, &user, 2, 2, true, true)?;
    for (actual, owner, kind, level, duplicate, strict) in [
        (&other[..], &user[..], 2, 2, true, true),
        (&user[..], &other[..], 2, 2, true, true),
        (&user[..], &user[..], 1, 2, true, true),
        (&user[..], &user[..], 2, 1, true, true),
        (&user[..], &user[..], 2, 0, false, false),
    ] {
        ensure!(
            identity(&user, actual, owner, kind, level, duplicate, strict).is_err(),
            "canary identity role accepted foreign token"
        );
    }
    let mut buffer = [0u8; CAPACITY];
    let base = 0x1000;
    owner_input(&mut buffer, base, &user)?;
    ensure!(
        sid(&buffer, base, 36, 4)? == user
            && u64::from_le_bytes(buffer[..8].try_into()?) == base + 8
            && buffer[8] == 1
            && buffer[9] == 5
            && buffer[8..36] == user,
        "canary owner input bytes/pointer differ"
    );
    for corruption in 0..9 {
        owner_input(&mut buffer, base, &user)?;
        let (mut returned, mut kind) = (36, 4);
        match corruption {
            0 => returned = 7,
            1 => returned = 257,
            2 => buffer[..8].copy_from_slice(&(base - 4).to_le_bytes()),
            3 => buffer[..8].copy_from_slice(&(base + 9).to_le_bytes()),
            4 => buffer[8] = 2,
            5 => buffer[9] = 16,
            6 => returned = 35,
            7 => kind = 8,
            _ => kind = 1,
        };
        ensure!(
            sid(&buffer, base, returned, kind).is_err(),
            "canary SID corruption accepted"
        );
    }
    buffer[..4].copy_from_slice(&2u32.to_le_bytes());
    ensure!(
        scalar(&buffer, 4)? == 2 && scalar(&buffer, 8).is_err(),
        "canary scalar query differs"
    );
    let queries = Cell::new(0);
    let returned = query(1, 8, &mut buffer, |token, kind, bytes| {
        queries.set(queries.get() + 1);
        ensure!(
            token == 1 && kind == 8 && bytes.len() == 256,
            "canary query input binding differs"
        );
        ensure!(
            bytes.iter().all(|v| *v == 0),
            "canary query buffer not cleared"
        );
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        Ok(4)
    })?;
    ensure!(
        scalar(&buffer, returned)? == 2
            && queries.get() == 1
            && query(1, 6, &mut buffer, |_, _, _| {
                queries.set(queries.get() + 1);
                Ok(4)
            })
            .is_err()
            && queries.get() == 1,
        "canary query kind/clear ordering differs"
    );
    buffer.fill(0);
    for mode in 0..10 {
        let order = std::rc::Rc::new(RefCell::new(String::new()));
        let operation = Arc::new(());
        let cleanup = Arc::new(());
        let fatal = Arc::new(());
        let mut io = Scope {
            mode,
            order: order.clone(),
            operation: operation.clone(),
            fatal: fatal.clone(),
        };
        let mut trusted = true;
        let result = scope(&mut io, &mut trusted);
        let original = result.err();
        let closing = release(
            original,
            trusted,
            vec![
                Box::new(|| {
                    order.borrow_mut().push('d');
                    if mode == 7 {
                        return Err(error(&cleanup));
                    }
                    Ok(())
                }),
                Box::new(|| {
                    order.borrow_mut().push('p');
                    Ok(())
                }),
            ],
        );
        let caught = match closing {
            Err(error) => Some(error),
            Ok(original) => original,
        };
        ensure!(
            *order.borrow()
                == match mode {
                    1 | 9 => "edp",
                    2 => "eqradp",
                    4 | 5 | 8 => "eqbrf",
                    6 => "eqbraf",
                    _ => "eqbradp",
                }
                && trusted == (mode < 4 || mode == 7 || mode == 9),
            "canary fatal/release ordering differs"
        );
        match mode {
            0 => ensure!(caught.is_none(), "canary positive scope failed"),
            1..=3 => ensure!(
                caught.as_ref().is_some_and(|e| same(e, &operation)),
                "canary operation identity replaced"
            ),
            4..=6 => ensure!(
                caught.as_ref().is_some_and(|e| same(e, &fatal)),
                "canary fatal did not replace uncertain revert"
            ),
            7 => {
                let error = caught.unwrap();
                let errors = &error.downcast_ref::<Failures>().unwrap().errors;
                ensure!(
                    same(&errors[0], &cleanup),
                    "canary close failure not retained"
                );
            }
            _ => ensure!(
                caught.is_some() && !caught.as_ref().is_some_and(|e| same(e, &operation)),
                "canary failed entry/fatal return lost refusal"
            ),
        }
    }
    let first = Arc::new(());
    let second = Arc::new(());
    let attempts = Cell::new(0);
    let caught = release(
        Some(error(&first)),
        true,
        vec![
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Err(error(&second))
            }),
            Box::new(|| {
                attempts.set(attempts.get() + 1);
                Ok(())
            }),
        ],
    )
    .unwrap_err();
    let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        errors.len() == 2
            && same(&errors[0], &first)
            && same(&errors[1], &second)
            && attempts.get() == 2
            && within(100, 16, 108, 8)
            && !within(100, 16, 108, 9)
            && !within(u64::MAX - 8, 8, 1, 1),
        "canary primary/release identity or range bounds differ"
    );
    Ok(())
}
