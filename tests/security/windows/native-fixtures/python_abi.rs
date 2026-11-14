//! Exact non-debug CPython3.11 x64 module-definition ABI, not the limited ABI.
use core::{
    ffi::{c_char, c_void},
    mem::{offset_of, size_of},
};
#[repr(C)]
pub struct Object {
    pub references: isize,
    pub kind: *mut c_void,
}
#[repr(C)]
pub struct ModuleBase {
    pub object: Object,
    pub init: *mut c_void,
    pub index: isize,
    pub copy: *mut Object,
}
#[repr(C)]
pub struct ModuleDef {
    pub base: ModuleBase,
    pub name: *const c_char,
    pub doc: *const c_char,
    pub size: isize,
    pub methods: *mut c_void,
    pub slots: *mut c_void,
    pub traverse: *mut c_void,
    pub clear: *mut c_void,
    pub free: *mut c_void,
}
const _: () = {
    assert!(size_of::<usize>() == 8 && size_of::<Object>() == 16 && size_of::<ModuleBase>() == 40);
    assert!(
        size_of::<ModuleDef>() == 104
            && offset_of!(ModuleDef, name) == 40
            && offset_of!(ModuleDef, size) == 56
    );
    assert!(offset_of!(ModuleDef, methods) == 64 && offset_of!(ModuleDef, free) == 96);
};
#[link(name = "python311")]
unsafe extern "C" {
    pub fn PyModule_Create2(definition: *mut ModuleDef, api: i32) -> *mut Object;
    pub fn PyLong_FromUnsignedLong(value: u32) -> *mut Object;
    pub fn PyModule_AddObject(module: *mut Object, name: *const c_char, value: *mut Object) -> i32;
    pub fn Py_DecRef(value: *mut Object);
    pub fn PyErr_SetString(kind: *mut Object, message: *const c_char);
    pub static mut PyExc_RuntimeError: *mut Object;
}
pub fn constant(module: *mut Object, name: &'static [u8], value: u32) -> i32 {
    let number = unsafe { PyLong_FromUnsignedLong(value) };
    if number.is_null() {
        return -1;
    }
    if unsafe { PyModule_AddObject(module, name.as_ptr().cast(), number) } < 0 {
        unsafe { Py_DecRef(number) };
        return -1;
    }
    0
}
