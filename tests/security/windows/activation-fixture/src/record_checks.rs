//! Portable actual record/parser/layout/state assertions, not Win32 evidence.
use std::cell::RefCell;
mod abi {
    use super::*;
    pub type Handle = *mut core::ffi::c_void;
    std::thread_local! { static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }
    pub unsafe fn write_file(
        handle: Handle,
        bytes: *const u8,
        count: u32,
        written: *mut u32,
        overlapped: Handle,
    ) -> i32 {
        assert_eq!(handle as usize, 1);
        assert!(count <= 256 && overlapped.is_null());
        // Only the real portable emit slice reaches this test-only transport sink.
        OUTPUT.with(|output| {
            *output.borrow_mut() =
                unsafe { core::slice::from_raw_parts(bytes, count as usize) }.to_vec();
        });
        unsafe { written.write(count) };
        1
    }
    pub unsafe fn exit_process(code: u32) -> ! {
        std::panic::panic_any(code)
    }
    pub use exit_process as ExitProcess;
    pub use write_file as WriteFile;
    pub fn output() -> Vec<u8> {
        OUTPUT.with(|output| output.borrow().clone())
    }
}
#[path = "native/module_dll.rs"]
mod module;
#[path = "native/emit.rs"]
mod native;
pub(super) fn check() {
    module::check_validation();
    for value in (0..=255u32).chain([0x01020304, 0x01234567, 0x89abcdef, 0xdeadbeef, u32::MAX]) {
        let mut record = native::Record::new();
        assert!(record.bytes().is_empty());
        record.append(b"win32_error=0x");
        record.hexadecimal(value);
        record.append(b"\n");
        assert_eq!(
            record.bytes(),
            format!("win32_error=0x{value:08X}\n").as_bytes()
        );
    }
    let mut record = native::Record::new();
    record.append(&[b'x'; 248]);
    record.hexadecimal(u32::MAX);
    record.append(b"");
    assert_eq!(record.bytes().len(), 256);
    assert_eq!(record.bytes().get(248..), Some(&b"FFFFFFFF"[..]));
    native::emit(1usize as abi::Handle, record.bytes(), 121);
    assert_eq!(abi::output(), record.bytes());
    for oversized in [false, true] {
        let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if oversized {
                native::Record::new().append(&[0; 257]);
            } else {
                record.append(b"x");
            }
        }))
        .unwrap_err();
        assert_eq!(error.downcast_ref::<u32>(), Some(&121));
    }
}
