//! Only the actual release3.11 x64 CPython C API. Every owning reference stays under the GIL.
use core::ffi::{c_char, c_int, c_long, c_void};
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
pub struct Method {
    pub name: *const c_char,
    pub function: Option<unsafe extern "C" fn(*mut Object, *mut Object) -> *mut Object>,
    pub flags: c_int,
    pub doc: *const c_char,
}
#[repr(C)]
pub struct ModuleDef {
    pub base: ModuleBase,
    pub name: *const c_char,
    pub doc: *const c_char,
    pub size: isize,
    pub methods: *mut Method,
    pub slots: *mut c_void,
    pub traverse: *mut c_void,
    pub clear: *mut c_void,
    pub free: *mut c_void,
}
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<usize>() == 8 && size_of::<Object>() == 16);
    assert!(size_of::<ModuleBase>() == 40 && size_of::<ModuleDef>() == 104);
    assert!(size_of::<Method>() == 32 && offset_of!(ModuleDef, methods) == 64);
};
#[link(name = "python311")]
unsafe extern "C" {
    pub fn Py_IncRef(object: *mut Object);
    pub fn Py_DecRef(object: *mut Object);
    pub fn PyImport_ImportModule(name: *const c_char) -> *mut Object;
    pub fn PyObject_GetAttrString(object: *mut Object, name: *const c_char) -> *mut Object;
    pub fn PyObject_SetAttrString(
        object: *mut Object,
        name: *const c_char,
        value: *mut Object,
    ) -> c_int;
    pub fn PyObject_HasAttrString(object: *mut Object, name: *const c_char) -> c_int;
    pub fn PyObject_CallObject(callable: *mut Object, arguments: *mut Object) -> *mut Object;
    pub fn PyObject_Call(
        callable: *mut Object,
        arguments: *mut Object,
        keywords: *mut Object,
    ) -> *mut Object;
    pub fn PyObject_IsInstance(object: *mut Object, class: *mut Object) -> c_int;
    pub fn PyObject_IsTrue(object: *mut Object) -> c_int;
    pub fn PyObject_Type(object: *mut Object) -> *mut Object;
    pub fn PyObject_Str(object: *mut Object) -> *mut Object;
    pub fn PyObject_GetItem(object: *mut Object, key: *mut Object) -> *mut Object;
    pub fn PyObject_RichCompareBool(left: *mut Object, right: *mut Object, op: c_int) -> c_int;
    pub fn PyObject_Length(object: *mut Object) -> isize;
    pub fn PyNumber_Multiply(left: *mut Object, right: *mut Object) -> *mut Object;
    pub fn PyNumber_Add(left: *mut Object, right: *mut Object) -> *mut Object;
    pub fn PyNumber_Subtract(left: *mut Object, right: *mut Object) -> *mut Object;
    pub fn PyNumber_Long(value: *mut Object) -> *mut Object;
    pub fn PySequence_GetItem(object: *mut Object, index: isize) -> *mut Object;
    pub fn PyUnicode_FromStringAndSize(bytes: *const c_char, length: isize) -> *mut Object;
    pub fn PyUnicode_AsUTF8AndSize(object: *mut Object, length: *mut isize) -> *const c_char;
    pub fn PyLong_FromUnsignedLongLong(value: u64) -> *mut Object;
    pub fn PyLong_FromLongLong(value: i64) -> *mut Object;
    pub fn PyLong_AsUnsignedLongLong(value: *mut Object) -> u64;
    pub fn PyLong_AsLongLong(value: *mut Object) -> i64;
    pub fn PyBool_FromLong(value: c_long) -> *mut Object;
    pub fn PyBytes_FromStringAndSize(bytes: *const c_char, length: isize) -> *mut Object;
    pub fn PyBytes_AsStringAndSize(
        object: *mut Object,
        bytes: *mut *mut c_char,
        length: *mut isize,
    ) -> c_int;
    pub fn PyTuple_New(length: isize) -> *mut Object;
    pub fn PyTuple_SetItem(tuple: *mut Object, index: isize, item: *mut Object) -> c_int;
    pub fn PyList_New(length: isize) -> *mut Object;
    pub fn PyList_SetItem(list: *mut Object, index: isize, item: *mut Object) -> c_int;
    pub fn PyDict_New() -> *mut Object;
    pub fn PyDict_SetItemString(dict: *mut Object, key: *const c_char, value: *mut Object)
    -> c_int;
    pub fn PyDict_GetItemString(dict: *mut Object, key: *const c_char) -> *mut Object;
    pub fn PyErr_Occurred() -> *mut Object;
    pub fn PyErr_Fetch(kind: *mut *mut Object, value: *mut *mut Object, trace: *mut *mut Object);
    pub fn PyErr_NormalizeException(
        kind: *mut *mut Object,
        value: *mut *mut Object,
        trace: *mut *mut Object,
    );
    pub fn PyErr_Restore(kind: *mut Object, value: *mut Object, trace: *mut Object);
    pub fn PyErr_SetString(kind: *mut Object, message: *const c_char);
    pub fn PyModule_Create2(definition: *mut ModuleDef, api: c_int) -> *mut Object;
    pub static mut PyExc_ImportError: *mut Object;
    pub static mut PyExc_ModuleNotFoundError: *mut Object;
    pub static mut PyExc_OSError: *mut Object;
    pub static mut PyExc_RuntimeError: *mut Object;
    pub static mut PyExc_Exception: *mut Object;
    pub static mut PyExc_AssertionError: *mut Object;
    pub static mut PyExc_TimeoutError: *mut Object;
    pub static mut PyExc_UnicodeDecodeError: *mut Object;
    pub static mut PyExc_UnicodeEncodeError: *mut Object;
    pub static PyUnicode_Type: u8;
    pub static PyLong_Type: u8;
    pub static PyBytes_Type: u8;
    pub static PyDict_Type: u8;
    pub static PyTuple_Type: u8;
    pub static _Py_NoneStruct: Object;
}
