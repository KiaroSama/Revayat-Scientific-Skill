//! Local compiler-required memory routines. Volatile accesses prevent recursive libc lowering.
use core::ffi::c_void;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let destination = destination.cast::<u8>();
    let source = source.cast::<u8>();
    for index in 0..count {
        unsafe {
            destination
                .add(index)
                .write_volatile(source.add(index).read_volatile())
        };
    }
    destination.cast()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(destination: *mut c_void, value: i32, count: usize) -> *mut c_void {
    let destination = destination.cast::<u8>();
    for index in 0..count {
        unsafe { destination.add(index).write_volatile(value as u8) };
    }
    destination.cast()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    if destination as usize <= source as usize {
        unsafe { memcpy(destination, source, count) };
    } else {
        for index in (0..count).rev() {
            unsafe {
                destination
                    .cast::<u8>()
                    .add(index)
                    .write_volatile(source.cast::<u8>().add(index).read_volatile())
            };
        }
    }
    destination
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(first: *const c_void, second: *const c_void, count: usize) -> i32 {
    let first = first.cast::<u8>();
    let second = second.cast::<u8>();
    for index in 0..count {
        let (first, second) = unsafe {
            (
                first.add(index).read_volatile(),
                second.add(index).read_volatile(),
            )
        };
        if first != second {
            return i32::from(first) - i32::from(second);
        }
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(first: *const c_void, second: *const c_void, count: usize) -> i32 {
    unsafe { memcmp(first, second, count) }
}
