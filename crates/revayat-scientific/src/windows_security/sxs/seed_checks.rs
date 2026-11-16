use super::*;
use std::{
    cell::{Cell, RefCell},
    io::{Cursor, Write},
    rc::Rc,
    sync::Arc,
};
#[derive(Clone, Debug)]
struct Failure(Arc<()>);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("private-seed-sentinel")
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
#[derive(Clone)]
struct Stream {
    cursor: Rc<RefCell<Cursor<Vec<u8>>>>,
    order: Rc<RefCell<String>>,
    failure: u8,
    error: Arc<()>,
}
impl Stream {
    fn new(failure: u8, length: usize) -> Self {
        Self {
            cursor: Rc::new(RefCell::new(Cursor::new(vec![0; length]))),
            order: Rc::default(),
            failure,
            error: Arc::new(()),
        }
    }
    fn flush(&mut self) -> Result<()> {
        self.order.borrow_mut().push('f');
        if self.failure & 2 != 0 {
            return Err(error(&self.error));
        }
        Ok(())
    }
    fn close(self) -> Result<()> {
        self.order.borrow_mut().push('d');
        if self.failure & 4 != 0 {
            return Err(error(&self.error));
        }
        Ok(())
    }
    fn length(&mut self) -> Result<u64> {
        Ok(self.cursor.borrow().get_ref().len() as u64)
    }
}
pub fn check_validation() -> Result<()> {
    for mode in 0..6 {
        let stream = Stream::new(
            match mode {
                2 => 2,
                3 => 4,
                4 => 6,
                _ => 0,
            },
            usize::from(mode == 5),
        );
        let acquired = Cell::new(0);
        let result = create(
            || {
                acquired.set(acquired.get() + 1);
                if mode == 1 {
                    return Err(error(&stream.error));
                }
                Ok(stream.clone())
            },
            Stream::length,
            Stream::flush,
            Stream::close,
        );
        ensure!(
            acquired.get() == 1
                && *stream.order.borrow()
                    == if mode == 1 {
                        ""
                    } else if mode == 5 {
                        "d"
                    } else {
                        "fd"
                    },
            "seed create ownership/order differs"
        );
        match mode {
            0 => result?,
            3 | 4 => {
                let caught = result.unwrap_err();
                let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
                ensure!(
                    errors.len() == if mode == 3 { 1 } else { 2 }
                        && errors.iter().all(|e| same(e, &stream.error)),
                    "seed close aggregation differs"
                );
            }
            5 => {
                ensure!(result.is_err(), "nonempty seed accepted");
            }
            _ => ensure!(
                same(&result.unwrap_err(), &stream.error),
                "seed operation error replaced"
            ),
        }
        if mode == 1 {
            stream.clone().close()?;
        }
    }
    for mode in 0..3 {
        let stream = Stream::new(0, usize::from(mode == 2));
        let order = RefCell::new(String::new());
        let result = read(
            || {
                order.borrow_mut().push('p');
                if mode == 1 {
                    return Err(error(&stream.error));
                }
                Ok(())
            },
            || {
                order.borrow_mut().push('r');
                Ok(stream.clone())
            },
            Stream::length,
            Stream::close,
        );
        ensure!(
            *order.borrow() == if mode == 1 { "p" } else { "pr" }
                && *stream.order.borrow() == if mode == 1 { "" } else { "d" }
                && result.is_err() == (mode != 0),
            "seed read policy/length order differs"
        );
        if mode == 1 {
            ensure!(
                same(&result.unwrap_err(), &stream.error),
                "seed policy error replaced"
            );
        }
        if mode == 1 {
            stream.clone().close()?;
        }
    }
    let first = Arc::new(());
    let closing = Stream::new(4, 0);
    let caught = create(
        || Ok(closing.clone()),
        Stream::length,
        |_| Err(error(&first)),
        Stream::close,
    )
    .unwrap_err();
    let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        errors.len() == 2
            && same(&errors[0], &first)
            && same(&errors[1], &closing.error)
            && *closing.order.borrow() == "d",
        "seed flush/close identity order differs"
    );
    let closing = Stream::new(4, 1);
    let caught = read(
        || Ok(()),
        || Ok(closing.clone()),
        Stream::length,
        Stream::close,
    )
    .unwrap_err();
    let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
    ensure!(
        errors.len() == 2
            && !errors[0].is::<Failure>()
            && same(&errors[1], &closing.error)
            && *closing.order.borrow() == "d",
        "seed length/close identity order differs"
    );
    for mode in 0..6 {
        let order = RefCell::new(String::new());
        let clocks = Cell::new(0);
        let step = |phase: u8| -> Result<()> {
            order.borrow_mut().push(char::from(b'0' + phase));
            if mode == phase + 1 {
                return Err(error(&first));
            }
            Ok(())
        };
        let result = prepare_text(
            || {
                clocks.set(clocks.get() + 1);
                Ok(if mode == 4 || mode == 5 && clocks.get() == 2 {
                    0.0
                } else {
                    1.0
                })
            },
            || step(0),
            || step(1),
            || step(2),
        );
        if result.is_ok() {
            order.borrow_mut().push('p');
        }
        ensure!(
            *order.borrow()
                == match mode {
                    0 => "012p",
                    1 => "0",
                    2 => "01",
                    4 => "",
                    _ => "012",
                }
                && result.is_err() == (mode != 0),
            "text seed preparation order differs"
        );
        if (1..=3).contains(&mode) {
            ensure!(
                same(&result.unwrap_err(), &first),
                "text seed callback error replaced"
            );
        }
    }
    Ok(())
}
pub fn check_canary_creation() -> Result<()> {
    for mode in 0..8 {
        let stream = Stream::new(mode, 0);
        let acquired = Cell::new(0);
        let result = crate::windows_security::activation::control::write_fixed(
            CANARY,
            || {
                acquired.set(acquired.get() + 1);
                if mode == 3 {
                    return Err(error(&stream.error));
                }
                Ok(stream.clone())
            },
            |stream, bytes| {
                stream.order.borrow_mut().push('w');
                require_canary(bytes)?;
                ensure!(bytes.len() == 22, "canary width differs");
                if stream.failure & 1 != 0 {
                    return Err(error(&stream.error));
                }
                stream.cursor.borrow_mut().write_all(bytes)?;
                Ok(())
            },
            Stream::flush,
            Stream::close,
        );
        ensure!(
            acquired.get() == 1
                && *stream.order.borrow()
                    == if mode == 3 {
                        ""
                    } else if mode & 1 != 0 {
                        "wd"
                    } else {
                        "wfd"
                    },
            "canary writer order differs"
        );
        if mode == 0 {
            result?;
        } else if mode & 4 != 0 {
            let caught = result.unwrap_err();
            let errors = &caught.downcast_ref::<Failures>().unwrap().errors;
            ensure!(
                errors.len() == if mode & 3 == 0 { 1 } else { 2 }
                    && errors.iter().all(|error| same(error, &stream.error)),
                "canary error aggregation differs"
            );
        } else {
            ensure!(
                same(&result.unwrap_err(), &stream.error),
                "canary original error replaced"
            );
        }
        if mode == 3 {
            stream.clone().close()?;
        }
    }
    require_canary(CANARY)?;
    for bytes in [&[][..], &b"fixed SxS host control!"[..], &[0; 65][..]] {
        ensure!(require_canary(bytes).is_err(), "foreign canary accepted");
    }
    Ok(())
}
