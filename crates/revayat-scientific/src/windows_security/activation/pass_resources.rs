//! Reverse retirement shared by actual held runtime files and injected acquisition failures.
use super::Failures;
use anyhow::Result;
pub struct Resources<T, C: FnMut(T) -> Result<()>> {
    values: Vec<T>,
    close: C,
}
impl<T, C: FnMut(T) -> Result<()>> Resources<T, C> {
    pub fn close(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        while let Some(value) = self.values.pop() {
            if let Err(error) = (self.close)(value) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    }
}
impl<T, C: FnMut(T) -> Result<()>> Drop for Resources<T, C> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub fn acquire<T, U, C: FnMut(T) -> Result<()>>(
    count: usize,
    mut open: impl FnMut(usize) -> Result<T>,
    qualify: impl FnOnce(&mut [T]) -> Result<U>,
    close: C,
) -> Result<(Resources<T, C>, U)> {
    let mut resources = Resources {
        values: Vec::new(),
        close,
    };
    let operation = (|| {
        for index in 0..count {
            resources.values.push(open(index)?);
        }
        qualify(&mut resources.values)
    })();
    match operation {
        Ok(value) => Ok((resources, value)),
        Err(primary) => {
            let mut errors = vec![primary];
            while let Some(value) = resources.values.pop() {
                if let Err(error) = (resources.close)(value) {
                    errors.push(error);
                }
            }
            if errors.len() == 1 {
                Err(errors.remove(0))
            } else {
                Err(Failures { errors }.into())
            }
        }
    }
}
