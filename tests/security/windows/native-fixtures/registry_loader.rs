//! Fixed post-import-failure followup. Never selects caller-supplied paths or operations.
#![no_std]
#![no_main]
mod config;
mod python_abi;
use python_abi::{ModuleBase, ModuleDef, Object};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(
        path: *const u16,
        reserved: *mut core::ffi::c_void,
        flags: u32,
    ) -> *mut core::ffi::c_void;
    fn GetLastError() -> u32;
    fn FreeLibrary(module: *mut core::ffi::c_void) -> i32;
}
static mut DEFINITION: ModuleDef = ModuleDef {
    base: ModuleBase {
        object: Object {
            references: 1,
            kind: core::ptr::null_mut(),
        },
        init: core::ptr::null_mut(),
        index: 0,
        copy: core::ptr::null_mut(),
    },
    name: c"_registry_loader".as_ptr(),
    doc: core::ptr::null(),
    size: -1,
    methods: core::ptr::null_mut(),
    slots: core::ptr::null_mut(),
    traverse: core::ptr::null_mut(),
    clear: core::ptr::null_mut(),
    free: core::ptr::null_mut(),
};
#[unsafe(no_mangle)]
pub extern "C" fn PyInit__registry_loader() -> *mut Object {
    let loaded = unsafe {
        LoadLibraryExW(
            config::REGISTRY_LOADER_PATH.as_ptr(),
            core::ptr::null_mut(),
            0x1100,
        )
    };
    let mut error = 0;
    let mut release_error = 0;
    let mut released = false;
    if loaded.is_null() {
        error = unsafe { GetLastError() };
    } else {
        released = unsafe { FreeLibrary(loaded) } != 0;
        if !released {
            release_error = unsafe { GetLastError() };
        }
    }
    if loaded.is_null() && error == 0 || !loaded.is_null() && !released && release_error == 0 {
        unsafe {
            python_abi::PyErr_SetString(
                python_abi::PyExc_RuntimeError,
                c"fixed loader result is unqualified".as_ptr(),
            )
        };
        return core::ptr::null_mut();
    }
    let module = unsafe { python_abi::PyModule_Create2(&raw mut DEFINITION, 1013) };
    if module.is_null() {
        return module;
    }
    if python_abi::constant(module, b"loaded\0", u32::from(!loaded.is_null())) < 0
        || python_abi::constant(module, b"load_error\0", error) < 0
        || python_abi::constant(module, b"release_error\0", release_error) < 0
        || python_abi::constant(module, b"version\0", 1) < 0
    {
        unsafe { python_abi::Py_DecRef(module) };
        return core::ptr::null_mut();
    }
    module
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
