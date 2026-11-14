//! Original DefaultActivationFixture.CheckLeaseValidation and ModuleActivationFixture.CheckLease.
use super::*;
use crate::windows_security::scratch::{self, SharedError};
use anyhow::ensure;
use std::{
    cell::{Cell, RefCell},
    error::Error,
    fmt,
    rc::Rc,
    sync::Arc,
};
#[derive(Debug)]
struct Identity(SharedError);
impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixed fixture lifecycle failure")
    }
}
impl Error for Identity {}
pub(super) fn identified(error: &SharedError) -> anyhow::Error {
    Identity(error.clone()).into()
}
pub(super) fn same(error: &anyhow::Error, expected: &SharedError) -> bool {
    error
        .downcast_ref::<Identity>()
        .is_some_and(|value| Arc::ptr_eq(&value.0, expected))
}
struct CheckResource {
    name: &'static str,
    order: Rc<RefCell<Vec<&'static str>>>,
    closes: Rc<Cell<usize>>,
    failure: Option<SharedError>,
}
impl CheckResource {
    fn new(
        name: &'static str,
        order: &Rc<RefCell<Vec<&'static str>>>,
        failure: Option<SharedError>,
    ) -> (Self, Rc<Cell<usize>>) {
        let closes = Rc::new(Cell::new(0));
        (
            Self {
                name,
                order: order.clone(),
                closes: closes.clone(),
                failure,
            },
            closes,
        )
    }
}
impl Resource for CheckResource {
    fn close(&mut self) -> Result<()> {
        self.closes.set(self.closes.get() + 1);
        self.order.borrow_mut().push(self.name);
        self.failure
            .as_ref()
            .map_or(Ok(()), |error| Err(identified(error)))
    }
}
pub fn check_default_lease_validation() -> Result<()> {
    let order = Rc::new(RefCell::new(Vec::new()));
    let (source, source_closes) = CheckResource::new("source", &order, None);
    let (image, image_closes) = CheckResource::new("image", &order, None);
    let mut held = acquire(
        vec![Box::new(|| Ok(source)), Box::new(|| Ok(image))],
        CloseOrder::Reverse,
        |values| {
            ensure!(
                values.len() == 2 && values[0].name == "source" && values[1].name == "image",
                "lease qualification received wrong resources"
            );
            Ok(())
        },
    )?;
    ensure!(
        order.borrow().is_empty(),
        "lease closed before ownership transfer"
    );
    held.close()?;
    held.close()?;
    ensure!(
        source_closes.get() == 1
            && image_closes.get() == 1
            && *order.borrow() == ["image", "source"],
        "fixture lease order/idempotence differs"
    );
    for opening_fails in [true, false] {
        order.borrow_mut().clear();
        let primary = scratch::failure("fixed acquisition");
        let (source, source_closes) = CheckResource::new("source", &order, None);
        let (image, image_closes) = CheckResource::new("image", &order, None);
        let result = acquire(
            vec![
                Box::new(|| Ok(source)),
                Box::new(|| {
                    if opening_fails {
                        Err(identified(&primary))
                    } else {
                        Ok(image)
                    }
                }),
            ],
            CloseOrder::Reverse,
            |values| {
                ensure!(
                    values[0].name == "source" && values[1].name == "image",
                    "lease resources differ"
                );
                Err(identified(&primary))
            },
        );
        let error = result.err().unwrap();
        ensure!(
            same(&error, &primary)
                && source_closes.get() == 1
                && image_closes.get() == usize::from(!opening_fails)
                && *order.borrow()
                    == if opening_fails {
                        vec!["source"]
                    } else {
                        vec!["image", "source"]
                    },
            "fixture acquisition changed primary or close order"
        );
    }
    for qualify_fails in [false, true] {
        order.borrow_mut().clear();
        let primary = scratch::failure("fixed qualification");
        let first = scratch::failure("fixed image close");
        let second = scratch::failure("fixed source close");
        let (source, source_closes) = CheckResource::new("source", &order, Some(second.clone()));
        let (image, image_closes) = CheckResource::new("image", &order, Some(first.clone()));
        let acquired = acquire(
            vec![Box::new(|| Ok(source)), Box::new(|| Ok(image))],
            CloseOrder::Reverse,
            |values| {
                ensure!(
                    values[0].name == "source" && values[1].name == "image",
                    "lease resources differ"
                );
                if qualify_fails {
                    Err(identified(&primary))
                } else {
                    Ok(())
                }
            },
        );
        let mut lease = None;
        let error = match acquired {
            Ok(mut value) => {
                ensure!(
                    source_closes.get() == 0 && image_closes.get() == 0,
                    "lease closed before disposal"
                );
                let error = value.close().unwrap_err();
                lease = Some(value);
                error
            }
            Err(error) => error,
        };
        let group = error.downcast_ref::<Failures>().unwrap();
        let offset = usize::from(qualify_fails);
        ensure!(
            group.errors.len() == offset + 2
                && (!qualify_fails || same(&group.errors[0], &primary))
                && same(&group.errors[offset], &first)
                && same(&group.errors[offset + 1], &second)
                && source_closes.get() == 1
                && image_closes.get() == 1
                && *order.borrow() == ["image", "source"],
            "fixture qualification/close failures lost order or identity"
        );
        if let Some(lease) = lease.as_mut() {
            lease.close()?;
            ensure!(
                source_closes.get() == 1 && image_closes.get() == 1,
                "failed close retried numeric ownership"
            );
        }
    }
    Ok(())
}
pub fn check_module_lease_validation() -> Result<()> {
    let order = Rc::new(RefCell::new(Vec::new()));
    let primary = scratch::failure("fixed acquisition");
    let cleanup = scratch::failure("fixed close");
    let (first, _) = CheckResource::new("first", &order, Some(cleanup.clone()));
    let (last, _) = CheckResource::new("last", &order, Some(cleanup.clone()));
    let error = acquire(
        vec![
            Box::new(|| Ok(first)),
            Box::new(|| Ok(last)),
            Box::new(|| Err(identified(&primary))),
        ],
        CloseOrder::Reverse,
        |_| Ok(()),
    )
    .err()
    .unwrap();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 3
            && same(&group.errors[0], &primary)
            && *order.borrow() == ["last", "first"],
        "module acquisition lost primary or reverse close attempts"
    );
    order.borrow_mut().clear();
    let (a, _) = CheckResource::new("a", &order, None);
    let (b, _) = CheckResource::new("b", &order, None);
    let mut held = acquire(
        vec![Box::new(|| Ok(a)), Box::new(|| Ok(b))],
        CloseOrder::Reverse,
        |values| {
            ensure!(values.len() == 2, "module qualified wrong resource count");
            Ok(())
        },
    )?;
    ensure!(
        order.borrow().is_empty(),
        "module closed before lease transfer"
    );
    held.close()?;
    held.close()?;
    ensure!(
        *order.borrow() == ["b", "a"],
        "module lease reverse order/idempotence differs"
    );
    order.borrow_mut().clear();
    let (qualified, _) = CheckResource::new("qualified", &order, Some(cleanup));
    let error = acquire(
        vec![Box::new(|| Ok(qualified))],
        CloseOrder::Reverse,
        |_| Err(identified(&primary)),
    )
    .err()
    .unwrap();
    let group = error.downcast_ref::<Failures>().unwrap();
    ensure!(
        group.errors.len() == 2
            && same(&group.errors[0], &primary)
            && *order.borrow() == ["qualified"],
        "module qualification lost original failure or close"
    );
    Ok(())
}
