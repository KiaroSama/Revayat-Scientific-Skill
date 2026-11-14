//! Checked owning references; tuple/list insertion accounts for CPython stealing references.
use super::ffi::{self, Object};
use core::{ffi::CStr, ptr::NonNull};
pub struct Owned(NonNull<Object>);
pub struct Exception {
    pub kind: Option<Owned>,
    pub value: Option<Owned>,
    pub trace: Option<Owned>,
}
pub enum Fault {
    Control,
    Python(Exception),
    Events(super::failure::Events),
}
pub type Result<T> = core::result::Result<T, Fault>;
#[inline(always)]
pub fn require(value: bool) -> Result<()> {
    if value { Ok(()) } else { Err(Fault::Control) }
}
impl Exception {
    pub fn fetch() -> Self {
        let (mut kind, mut value, mut trace) = (
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        unsafe {
            ffi::PyErr_Fetch(&mut kind, &mut value, &mut trace);
            ffi::PyErr_NormalizeException(&mut kind, &mut value, &mut trace);
        }
        Self {
            kind: NonNull::new(kind).map(Owned),
            value: NonNull::new(value).map(Owned),
            trace: NonNull::new(trace).map(Owned),
        }
    }
    pub fn from_value(value: &Owned) -> Result<Self> {
        Ok(Self {
            kind: Some(value.kind()?),
            value: Some(value.clone_ref()),
            trace: None,
        })
    }
    pub fn restore(mut self) {
        let take = |value: Option<Owned>| value.map_or(core::ptr::null_mut(), Owned::release);
        unsafe {
            ffi::PyErr_Restore(
                take(self.kind.take()),
                take(self.value.take()),
                take(self.trace.take()),
            )
        }
    }
}
impl Fault {
    pub fn current() -> Self {
        Self::Python(Exception::fetch())
    }
}
impl Owned {
    /// Caller transfers exactly one new reference, or supplies the active Python error.
    pub unsafe fn new(pointer: *mut Object) -> Result<Self> {
        NonNull::new(pointer).map(Self).ok_or_else(Fault::current)
    }
    /// Caller keeps the GIL and proves the borrowed object outlives this increment.
    pub unsafe fn borrowed(pointer: *mut Object) -> Result<Self> {
        require(!pointer.is_null())?;
        unsafe {
            ffi::Py_IncRef(pointer);
            Self::new(pointer)
        }
    }
    pub fn pointer(&self) -> *mut Object {
        self.0.as_ptr()
    }
    pub fn clone_ref(&self) -> Self {
        unsafe { ffi::Py_IncRef(self.pointer()) };
        Self(self.0)
    }
    fn release(self) -> *mut Object {
        let pointer = self.pointer();
        core::mem::forget(self);
        pointer
    }
    pub fn same(&self, other: &Self) -> bool {
        self.pointer() == other.pointer()
    }
    pub fn is_none(&self) -> bool {
        self.pointer() == core::ptr::addr_of!(ffi::_Py_NoneStruct).cast_mut()
    }
    pub fn none() -> Self {
        let pointer = core::ptr::addr_of!(ffi::_Py_NoneStruct).cast_mut();
        unsafe { ffi::Py_IncRef(pointer) };
        // The linked CPython singleton has a non-null static address.
        Self(unsafe { NonNull::new_unchecked(pointer) })
    }
    pub fn text(value: &str) -> Result<Self> {
        unsafe {
            Self::new(ffi::PyUnicode_FromStringAndSize(
                value.as_ptr().cast(),
                value.len() as isize,
            ))
        }
    }
    pub fn bytes(value: &[u8]) -> Result<Self> {
        unsafe {
            Self::new(ffi::PyBytes_FromStringAndSize(
                value.as_ptr().cast(),
                value.len() as isize,
            ))
        }
    }
    pub fn unsigned(value: u64) -> Result<Self> {
        unsafe { Self::new(ffi::PyLong_FromUnsignedLongLong(value)) }
    }
    pub fn signed(value: i64) -> Result<Self> {
        unsafe { Self::new(ffi::PyLong_FromLongLong(value)) }
    }
    pub fn boolean(value: bool) -> Result<Self> {
        unsafe { Self::new(ffi::PyBool_FromLong(value.into())) }
    }
    pub fn attr(&self, name: &CStr) -> Result<Self> {
        unsafe { Self::new(ffi::PyObject_GetAttrString(self.pointer(), name.as_ptr())) }
    }
    pub fn set(&self, name: &CStr, value: &Self) -> Result<()> {
        if unsafe { ffi::PyObject_SetAttrString(self.pointer(), name.as_ptr(), value.pointer()) }
            < 0
        {
            Err(Fault::current())
        } else {
            Ok(())
        }
    }
    pub fn kind(&self) -> Result<Self> {
        unsafe { Self::new(ffi::PyObject_Type(self.pointer())) }
    }
    pub fn exact(&self, expected: *const u8) -> Result<bool> {
        Ok(self.kind()?.pointer().cast::<u8>() == expected.cast_mut())
    }
    pub fn instance(&self, class: *mut Object) -> Result<bool> {
        match unsafe { ffi::PyObject_IsInstance(self.pointer(), class) } {
            -1 => Err(Fault::current()),
            value => Ok(value != 0),
        }
    }
    pub fn truth(&self) -> Result<bool> {
        match unsafe { ffi::PyObject_IsTrue(self.pointer()) } {
            -1 => Err(Fault::current()),
            value => Ok(value != 0),
        }
    }
    pub fn equal(&self, other: &Self) -> Result<bool> {
        match unsafe { ffi::PyObject_RichCompareBool(self.pointer(), other.pointer(), 2) } {
            -1 => Err(Fault::current()),
            value => Ok(value != 0),
        }
    }
    pub fn length(&self) -> Result<usize> {
        let value = unsafe { ffi::PyObject_Length(self.pointer()) };
        if value < 0 {
            Err(Fault::current())
        } else {
            Ok(value as usize)
        }
    }
    pub fn item(&self, key: &Self) -> Result<Self> {
        unsafe { Self::new(ffi::PyObject_GetItem(self.pointer(), key.pointer())) }
    }
    pub fn index(&self, index: usize) -> Result<Self> {
        unsafe { Self::new(ffi::PySequence_GetItem(self.pointer(), index as isize)) }
    }
    pub fn string(&self) -> Result<Self> {
        unsafe { Self::new(ffi::PyObject_Str(self.pointer())) }
    }
    pub fn utf8(&self, maximum: usize) -> Result<&str> {
        require(self.exact(core::ptr::addr_of!(ffi::PyUnicode_Type))?)?;
        let mut length = 0;
        let pointer = unsafe { ffi::PyUnicode_AsUTF8AndSize(self.pointer(), &mut length) };
        if pointer.is_null() {
            return Err(Fault::current());
        }
        require(length >= 0 && length as usize <= maximum)?;
        let bytes = unsafe { core::slice::from_raw_parts(pointer.cast(), length as usize) };
        // CPython guarantees that PyUnicode_AsUTF8AndSize returns valid UTF-8.
        Ok(unsafe { core::str::from_utf8_unchecked(bytes) })
    }
    pub fn raw_bytes(&self, maximum: usize) -> Result<&[u8]> {
        require(self.exact(core::ptr::addr_of!(ffi::PyBytes_Type))?)?;
        let (mut pointer, mut length) = (core::ptr::null_mut(), 0);
        if unsafe { ffi::PyBytes_AsStringAndSize(self.pointer(), &mut pointer, &mut length) } < 0 {
            return Err(Fault::current());
        }
        require(length >= 0 && length as usize <= maximum && !pointer.is_null())?;
        Ok(unsafe { core::slice::from_raw_parts(pointer.cast(), length as usize) })
    }
    pub fn u64(&self) -> Result<u64> {
        let value = unsafe { ffi::PyLong_AsUnsignedLongLong(self.pointer()) };
        if unsafe { ffi::PyErr_Occurred() }.is_null() {
            Ok(value)
        } else {
            Err(Fault::current())
        }
    }
    pub fn i64(&self) -> Result<i64> {
        let value = unsafe { ffi::PyLong_AsLongLong(self.pointer()) };
        if unsafe { ffi::PyErr_Occurred() }.is_null() {
            Ok(value)
        } else {
            Err(Fault::current())
        }
    }
    pub fn import(name: &CStr) -> Result<Self> {
        unsafe { Self::new(ffi::PyImport_ImportModule(name.as_ptr())) }
    }
    pub fn tuple(values: &[&Self]) -> Result<Self> {
        let result = unsafe { Self::new(ffi::PyTuple_New(values.len() as isize)) }?;
        for (index, value) in values.iter().enumerate() {
            if unsafe {
                ffi::PyTuple_SetItem(
                    result.pointer(),
                    index as isize,
                    value.clone_ref().release(),
                )
            } < 0
            {
                return Err(Fault::current());
            }
        }
        Ok(result)
    }
    pub fn list(values: &[&Self]) -> Result<Self> {
        let result = unsafe { Self::new(ffi::PyList_New(values.len() as isize)) }?;
        for (index, value) in values.iter().enumerate() {
            if unsafe {
                ffi::PyList_SetItem(
                    result.pointer(),
                    index as isize,
                    value.clone_ref().release(),
                )
            } < 0
            {
                return Err(Fault::current());
            }
        }
        Ok(result)
    }
    pub fn dict() -> Result<Self> {
        unsafe { Self::new(ffi::PyDict_New()) }
    }
    pub fn put(&self, key: &CStr, value: &Self) -> Result<()> {
        if unsafe { ffi::PyDict_SetItemString(self.pointer(), key.as_ptr(), value.pointer()) } < 0 {
            Err(Fault::current())
        } else {
            Ok(())
        }
    }
    pub fn get(&self, key: &CStr) -> Result<Self> {
        unsafe { Self::borrowed(ffi::PyDict_GetItemString(self.pointer(), key.as_ptr())) }
    }
    pub fn optional(&self, key: &CStr) -> Result<Option<Self>> {
        let pointer = unsafe { ffi::PyDict_GetItemString(self.pointer(), key.as_ptr()) };
        if pointer.is_null() {
            Ok(None)
        } else {
            unsafe { Self::borrowed(pointer).map(Some) }
        }
    }
    pub fn call(&self, values: &[&Self]) -> Result<Self> {
        let args = Self::tuple(values)?;
        unsafe { Self::new(ffi::PyObject_CallObject(self.pointer(), args.pointer())) }
    }
    pub fn call_kw(&self, values: &[&Self], keywords: &Self) -> Result<Self> {
        let args = Self::tuple(values)?;
        unsafe {
            Self::new(ffi::PyObject_Call(
                self.pointer(),
                args.pointer(),
                keywords.pointer(),
            ))
        }
    }
    pub fn method(&self, name: &CStr, values: &[&Self]) -> Result<Self> {
        self.attr(name)?.call(values)
    }
    pub fn multiply(&self, other: &Self) -> Result<Self> {
        unsafe { Self::new(ffi::PyNumber_Multiply(self.pointer(), other.pointer())) }
    }
    pub fn add(&self, other: &Self) -> Result<Self> {
        unsafe { Self::new(ffi::PyNumber_Add(self.pointer(), other.pointer())) }
    }
    pub fn subtract(&self, other: &Self) -> Result<Self> {
        unsafe { Self::new(ffi::PyNumber_Subtract(self.pointer(), other.pointer())) }
    }
    pub fn integer(&self) -> Result<Self> {
        unsafe { Self::new(ffi::PyNumber_Long(self.pointer())) }
    }
    pub fn less(&self, other: &Self) -> Result<bool> {
        match unsafe { ffi::PyObject_RichCompareBool(self.pointer(), other.pointer(), 0) } {
            -1 => Err(Fault::current()),
            value => Ok(value != 0),
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { ffi::Py_DecRef(self.pointer()) }
    }
}
