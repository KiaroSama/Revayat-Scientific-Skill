//! Retained fixture resources with explicit close order and all-attempt cleanup.
use super::io::HeldFile;
use crate::windows_security::activation::Failures;
use anyhow::Result;
#[path = "lease_checks.rs"]
mod checks;
pub use checks::{check_default_lease_validation, check_module_lease_validation};
pub trait Resource {
    fn close(&mut self) -> Result<()>;
}
impl Resource for HeldFile {
    fn close(&mut self) -> Result<()> {
        HeldFile::close(self)
    }
}
#[derive(Clone, Copy)]
pub enum CloseOrder {
    Forward,
    Reverse,
}
pub struct Lease<R: Resource> {
    held: Option<Vec<R>>,
    order: CloseOrder,
}
impl<R: Resource> Lease<R> {
    pub fn resources(&mut self) -> &mut [R] {
        self.held.as_mut().map_or(&mut [], Vec::as_mut_slice)
    }
    pub fn close(&mut self) -> Result<()> {
        if let Some(mut held) = self.held.take() {
            release(&mut held, self.order, None)
        } else {
            Ok(())
        }
    }
}
impl<R: Resource> Drop for Lease<R> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub fn finish<'a>(
    primary: Option<anyhow::Error>,
    actions: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
) -> Result<()> {
    let mut errors = Vec::new();
    for mut action in actions {
        if let Err(error) = action() {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        return primary.map_or(Ok(()), Err);
    }
    if let Some(primary) = primary {
        errors.insert(0, primary);
    }
    Err(Failures { errors }.into())
}
fn release<R: Resource>(
    held: &mut [R],
    order: CloseOrder,
    primary: Option<anyhow::Error>,
) -> Result<()> {
    let mut errors = Vec::new();
    match order {
        CloseOrder::Forward => {
            for value in held {
                if let Err(error) = value.close() {
                    errors.push(error);
                }
            }
        }
        CloseOrder::Reverse => {
            for value in held.iter_mut().rev() {
                if let Err(error) = value.close() {
                    errors.push(error);
                }
            }
        }
    }
    if errors.is_empty() {
        return primary.map_or(Ok(()), Err);
    }
    if let Some(primary) = primary {
        errors.insert(0, primary);
    }
    Err(Failures { errors }.into())
}
pub fn acquire<'a, R: Resource>(
    opens: Vec<Box<dyn FnOnce() -> Result<R> + 'a>>,
    order: CloseOrder,
    qualify: impl FnOnce(&mut [R]) -> Result<()>,
) -> Result<Lease<R>> {
    let mut held = Vec::new();
    let result = (|| {
        for open in opens {
            held.push(open()?);
        }
        qualify(&mut held)
    })();
    match result {
        Ok(()) => Ok(Lease {
            held: Some(held),
            order,
        }),
        Err(primary) => {
            release(&mut held, order, Some(primary))?;
            unreachable!("primary failure is always retained")
        }
    }
}
