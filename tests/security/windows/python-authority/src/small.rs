//! Small bounded owning-object lists, allocated by CPython rather than a hidden Rust allocator.
use super::object::{Fault, Owned, Result, require};
pub struct Objects<const N: usize> {
    items: [Option<Owned>; N],
    length: usize,
}
impl<const N: usize> Objects<N> {
    pub fn new() -> Self {
        Self {
            items: core::array::from_fn(|_| None),
            length: 0,
        }
    }
    pub fn push(&mut self, value: Owned) -> Result<()> {
        require(self.length < N)?;
        self.items[self.length] = Some(value);
        self.length += 1;
        Ok(())
    }
    pub fn get(&self, index: usize) -> Result<&Owned> {
        self.items
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Fault::Control)
    }
    pub fn collect(iter: impl IntoIterator<Item = Result<Owned>>) -> Result<Self> {
        let mut result = Self::new();
        for value in iter {
            result.push(value?)?;
        }
        Ok(result)
    }
    pub fn list(&self) -> Result<Owned> {
        let mut references: [Option<&Owned>; N] = [None; N];
        for (index, value) in references.iter_mut().take(self.length).enumerate() {
            *value = Some(self.get(index)?);
        }
        let result = unsafe { Owned::new(super::ffi::PyList_New(self.length as isize)) }?;
        for (index, value) in references.into_iter().take(self.length).enumerate() {
            let value = value.ok_or(Fault::Control)?;
            unsafe { super::ffi::Py_IncRef(value.pointer()) };
            if unsafe {
                super::ffi::PyList_SetItem(result.pointer(), index as isize, value.pointer())
            } < 0
            {
                return Err(Fault::current());
            }
        }
        Ok(result)
    }
}
