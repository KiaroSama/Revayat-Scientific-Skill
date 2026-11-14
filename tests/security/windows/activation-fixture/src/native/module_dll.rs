//! Automatic DLL association query. Raw paths and activation-context buffers never leave the DLL.
use super::abi::Handle;
use core::{
    ptr,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};
#[repr(C)]
pub struct Observation {
    size: u32,
    attach: u32,
    query: u32,
    evaluated: u32,
    own_root: u32,
    error: u32,
    returned: u32,
    assemblies: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct Detail {
    flags: u32,
    version: u32,
    assemblies: u32,
    root_type: u32,
    root_chars: u32,
    config_type: u32,
    config_chars: u32,
    dir_type: u32,
    dir_chars: u32,
    root: *const u16,
    config: *const u16,
    dir: *const u16,
}
#[repr(align(8))]
struct Aligned<const N: usize>([u8; N]);
static OWN: AtomicUsize = AtomicUsize::new(0);
static ATTACHES: AtomicU32 = AtomicU32::new(0);
static mut STORAGE: Aligned<65536> = Aligned([0; 65536]);
static mut MODULE_PATH: [u16; 1024] = [0; 1024];
static mut HOST_PATH: [u16; 1024] = [0; 1024];
const _: () = {
    assert!(core::mem::size_of::<Observation>() == 32);
    assert!(core::mem::offset_of!(Observation, error) == 20);
    assert!(core::mem::offset_of!(Observation, assemblies) == 28);
    assert!(core::mem::size_of::<Detail>() == 64);
    assert!(core::mem::offset_of!(Detail, root) == 40);
};
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryActCtxW(
        flags: u32,
        context: Handle,
        instance: Handle,
        class: u32,
        bytes: *mut u8,
        length: usize,
        required: *mut usize,
    ) -> i32;
    fn GetLastError() -> u32;
    fn GetModuleFileNameW(module: Handle, text: *mut u16, length: u32) -> u32;
    fn CompareStringOrdinal(
        first: *const u16,
        first_length: i32,
        second: *const u16,
        second_length: i32,
        ignore_case: i32,
    ) -> i32;
}
// These are the genuine common no-CRT memory implementations, not imported CRT calls.
unsafe extern "C" {
    fn memcpy(
        destination: *mut core::ffi::c_void,
        source: *const core::ffi::c_void,
        count: usize,
    ) -> *mut core::ffi::c_void;
    fn memset(
        destination: *mut core::ffi::c_void,
        value: i32,
        count: usize,
    ) -> *mut core::ffi::c_void;
}
unsafe fn read_unit(source: *const u16) -> u16 {
    let mut value = 0u16;
    unsafe {
        memcpy((&mut value as *mut u16).cast(), source.cast(), 2);
    }
    value
}
unsafe fn write_unit(destination: *mut u16, value: u16) {
    unsafe {
        memcpy(destination.cast(), (&value as *const u16).cast(), 2);
    }
}
unsafe fn read_word(source: *const u32) -> u32 {
    let mut value = 0u32;
    unsafe {
        memcpy((&mut value as *mut u32).cast(), source.cast(), 4);
    }
    value
}
unsafe fn write_word(destination: *mut u32, value: u32) {
    unsafe {
        memcpy(destination.cast(), (&value as *const u32).cast(), 4);
    }
}
// On Windows x64 aligned MOV implements the original acquire/release access.
// Default asm memory effects supply a compiler barrier; reads do not become RMWs.
fn own_load() -> usize {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let value;
        unsafe {
            core::arch::asm!("mov {value}, qword ptr [{source}]", value = out(reg) value, source = in(reg) OWN.as_ptr(), options(nostack, preserves_flags));
        }
        value
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        OWN.load(Ordering::Acquire)
    }
}
fn own_store(value: usize) {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe {
        core::arch::asm!("mov qword ptr [{destination}], {value}", destination = in(reg) OWN.as_ptr(), value = in(reg) value, options(nostack, preserves_flags));
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    OWN.store(value, Ordering::Release);
}
fn attaches_load() -> u32 {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let value;
        unsafe {
            core::arch::asm!("mov {value:e}, dword ptr [{source}]", value = out(reg) value, source = in(reg) ATTACHES.as_ptr(), options(nostack, preserves_flags));
        }
        value
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        ATTACHES.load(Ordering::Acquire)
    }
}
fn text_valid(text: *const u16, capacity: usize, chars: usize) -> bool {
    if chars > 1023
        || chars >= capacity
        || text.is_null()
        || (text as usize) & 1 != 0
        || unsafe { read_unit(text.wrapping_add(chars)) } != 0
    {
        return false;
    }
    let mut index = 0;
    while index < chars {
        let value = unsafe { read_unit(text.wrapping_add(index)) };
        if value == 0 {
            return false;
        }
        if (0xd800..=0xdbff).contains(&value) {
            index = index.wrapping_add(1);
            if index >= chars
                || !(0xdc00..=0xdfff).contains(&unsafe { read_unit(text.wrapping_add(index)) })
            {
                return false;
            }
        } else if (0xdc00..=0xdfff).contains(&value) {
            return false;
        }
        index = index.wrapping_add(1);
    }
    true
}
fn span_text(buffer: *const u8, capacity: usize, pointer: *const u16, chars: u32) -> bool {
    if pointer.is_null() {
        return chars == 0;
    }
    let address = pointer as usize;
    let start = buffer as usize;
    if address & 1 != 0 || address < start || chars > 1023 {
        return false;
    }
    let offset = address.wrapping_sub(start);
    let count = (chars as usize).wrapping_add(1);
    if offset < 64 || offset > capacity || count.wrapping_mul(2) > capacity.wrapping_sub(offset) {
        return false;
    }
    // SAFETY: complete aligned span lies in the live supplied activation buffer.
    text_valid(pointer, count, chars as usize)
}
fn detail_valid(
    buffer: *const u8,
    capacity: usize,
    size: usize,
) -> Option<(Detail, *const u16, u32)> {
    if buffer.is_null() || !(64..=65536).contains(&size) || size > capacity {
        return None;
    }
    // SAFETY: width was checked; unaligned read avoids imposing caller alignment.
    let mut detail = Detail {
        flags: 0,
        version: 0,
        assemblies: 0,
        root_type: 0,
        root_chars: 0,
        config_type: 0,
        config_chars: 0,
        dir_type: 0,
        dir_chars: 0,
        root: ptr::null(),
        config: ptr::null(),
        dir: ptr::null(),
    };
    unsafe {
        memcpy((&mut detail as *mut Detail).cast(), buffer.cast(), 64);
    }
    if detail.flags != 0
        || detail.version > 1
        || detail.assemblies > 16
        || detail.root_type > 4
        || detail.config_type > 4
        || detail.dir_type > 4
        || !span_text(buffer, size, detail.root, detail.root_chars)
        || !span_text(buffer, size, detail.config, detail.config_chars)
        || !span_text(buffer, size, detail.dir, detail.dir_chars)
        || detail.root_chars != 0
            && (detail.version != 1 || detail.assemblies == 0 || detail.root_type != 2)
    {
        return None;
    }
    Some((detail, detail.root, detail.root_chars))
}
fn self_check() -> bool {
    let mut bytes = Aligned([0u8; 128]);
    let text = bytes.0.as_mut_ptr().wrapping_add(64).cast::<u16>();
    let mut detail = Detail {
        flags: 0,
        version: 1,
        assemblies: 1,
        root_type: 2,
        root_chars: 3,
        config_type: 0,
        config_chars: 0,
        dir_type: 0,
        dir_chars: 0,
        root: text,
        config: ptr::null(),
        dir: ptr::null(),
    };
    unsafe {
        write_unit(text, 65);
        write_unit(text.wrapping_add(1), 58);
        write_unit(text.wrapping_add(2), 92);
        write_unit(text.wrapping_add(3), 0);
    }
    fn check(bytes: &mut Aligned<128>, detail: Detail, size: usize) -> bool {
        unsafe {
            memcpy(
                bytes.0.as_mut_ptr().cast(),
                (&detail as *const Detail).cast(),
                64,
            );
        };
        detail_valid(bytes.0.as_ptr(), 128, size).is_some()
    }
    if !check(&mut bytes, detail, 72) {
        return false;
    }
    let Some((_, root, chars)) = detail_valid(bytes.0.as_ptr(), 128, 72) else {
        return false;
    };
    if root != text || chars != 3 {
        return false;
    }
    for changed in &[
        Detail { flags: 1, ..detail },
        Detail {
            version: 2,
            ..detail
        },
        Detail {
            root_type: 3,
            ..detail
        },
        Detail {
            assemblies: 0,
            ..detail
        },
        Detail {
            assemblies: 17,
            ..detail
        },
        Detail {
            root: ptr::null(),
            ..detail
        },
        Detail {
            root: bytes.0.as_ptr().wrapping_add(65).cast(),
            ..detail
        },
        Detail {
            root: bytes.0.as_ptr().wrapping_add(62).cast(),
            ..detail
        },
        Detail {
            root: bytes.0.as_ptr().wrapping_add(72).cast(),
            ..detail
        },
        Detail {
            root: (usize::MAX - 1) as *const u16,
            ..detail
        },
        Detail {
            root_chars: 1024,
            ..detail
        },
        Detail {
            root_chars: u32::MAX,
            ..detail
        },
    ] {
        if check(&mut bytes, *changed, 72) {
            return false;
        }
    }
    unsafe { write_unit(text.wrapping_add(3), 88) };
    if check(&mut bytes, detail, 72) {
        return false;
    }
    unsafe { write_unit(text.wrapping_add(3), 0) };
    for invalid in &[0, 0xd800, 0xdc00] {
        unsafe { write_unit(text.wrapping_add(1), *invalid) };
        if check(&mut bytes, detail, 72) {
            return false;
        }
    }
    unsafe {
        write_unit(text.wrapping_add(1), 0xd800);
        write_unit(text.wrapping_add(2), 0xdc00)
    };
    if !check(&mut bytes, detail, 72) {
        return false;
    }
    unsafe {
        write_unit(text.wrapping_add(1), 58);
        write_unit(text.wrapping_add(2), 92)
    };
    let directory_pointer = bytes.0.as_ptr().wrapping_add(72).cast();
    if check(
        &mut bytes,
        Detail {
            config_chars: 1,
            ..detail
        },
        72,
    ) || check(
        &mut bytes,
        Detail {
            dir: directory_pointer,
            ..detail
        },
        72,
    ) || check(&mut bytes, detail, 63)
        || check(&mut bytes, detail, 65537)
    {
        return false;
    }
    detail.root = ptr::null();
    detail.root_chars = 0;
    detail.root_type = 0;
    detail.version = 0;
    detail.assemblies = 0;
    if !check(&mut bytes, detail, 64) {
        return false;
    }
    let Some((_, root, chars)) = detail_valid(bytes.0.as_ptr(), 128, 64) else {
        return false;
    };
    if !root.is_null() || chars != 0 {
        return false;
    }
    unsafe { write_unit(text, 0) };
    detail.root = text;
    if !check(&mut bytes, detail, 66) {
        return false;
    }
    let Some((_, root, chars)) = detail_valid(bytes.0.as_ptr(), 128, 66) else {
        return false;
    };
    root == text && chars == 0
}
#[unsafe(no_mangle)]
pub extern "system" fn ModuleEntry(module: Handle, reason: u32, _reserved: Handle) -> i32 {
    if reason == 1 {
        own_store(module as usize);
        ATTACHES.fetch_add(1, Ordering::AcqRel);
    }
    1
}
#[cfg(windows)]
fn observe(out: *mut Observation) -> bool {
    let own = own_load() as Handle;
    if out.is_null()
        || (out as usize) & 3 != 0
        || unsafe { read_word(out.cast()) } != 32
        || attaches_load() != 1
        || own.is_null()
        || !self_check()
    {
        return false;
    }
    let storage = ptr::addr_of_mut!(STORAGE).cast::<u8>();
    let module_path = ptr::addr_of_mut!(MODULE_PATH).cast::<u16>();
    let host_path = ptr::addr_of_mut!(HOST_PATH).cast::<u16>();
    let mut required = 0;
    let query = unsafe { QueryActCtxW(8, own, ptr::null_mut(), 2, storage, 65536, &mut required) };
    let error = if query != 0 {
        0
    } else {
        unsafe { GetLastError() }
    };
    if required > 65536 || query == 0 && error == 0 {
        return false;
    }
    unsafe {
        write_word(out.cast::<u8>().wrapping_add(4).cast(), 1);
        write_word(out.cast::<u8>().wrapping_add(20).cast(), error);
        write_word(
            out.cast::<u8>().wrapping_add(8).cast(),
            u32::from(query != 0),
        );
        write_word(out.cast::<u8>().wrapping_add(24).cast(), required as u32);
    }
    let (root, chars) = if query != 0 {
        let Some((detail, root, chars)) = detail_valid(storage, 65536, required) else {
            return false;
        };
        unsafe {
            write_word(out.cast::<u8>().wrapping_add(28).cast(), detail.assemblies);
        }
        (root, chars)
    } else {
        (ptr::null(), 0)
    };
    let host_length = unsafe { GetModuleFileNameW(ptr::null_mut(), host_path, 1024) } as usize;
    let module_length = unsafe { GetModuleFileNameW(own, module_path, 1024) } as usize;
    if host_length == 0
        || host_length >= 1024
        || module_length == 0
        || module_length >= 1024
        || !text_valid(host_path, 1024, host_length)
        || !text_valid(module_path, 1024, module_length)
    {
        return false;
    }
    let mut directory = host_length;
    while directory != 0
        && unsafe { read_unit(host_path.wrapping_add(directory.wrapping_sub(1))) } != 92
    {
        directory = directory.wrapping_sub(1);
    }
    const BASENAME: [u16; 18] = [
        115, 116, 97, 114, 116, 117, 112, 45, 109, 111, 100, 117, 108, 101, 46, 100, 108, 108,
    ];
    if directory == 0
        || directory.wrapping_add(18) != module_length
        || unsafe {
            CompareStringOrdinal(
                host_path,
                directory as i32,
                module_path,
                directory as i32,
                1,
            )
        } != 2
        || unsafe {
            CompareStringOrdinal(
                module_path.wrapping_add(directory),
                18,
                BASENAME.as_ptr(),
                18,
                1,
            )
        } != 2
    {
        return false;
    }
    if query != 0 && chars != 0 {
        let compared = unsafe {
            CompareStringOrdinal(root, chars as i32, module_path, module_length as i32, 1)
        };
        if !(1..=3).contains(&compared) {
            return false;
        }
        unsafe {
            write_word(out.cast::<u8>().wrapping_add(12).cast(), 1);
            write_word(
                out.cast::<u8>().wrapping_add(16).cast(),
                u32::from(compared == 2),
            );
        }
    }
    true
}
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn ObserveModuleActivation(out: *mut Observation) -> i32 {
    let result = observe(out);
    clear_storage();
    i32::from(result)
}
fn clear_storage() {
    unsafe {
        memset(ptr::addr_of_mut!(STORAGE).cast(), 0, 65536);
        memset(ptr::addr_of_mut!(MODULE_PATH).cast(), 0, 2048);
        memset(ptr::addr_of_mut!(HOST_PATH).cast(), 0, 2048);
    }
}

/// Portable actual parser/layout/state checks only. No query, DLL load or association is claimed.
#[cfg(test)]
pub fn check_validation() {
    assert!(self_check());
    assert_eq!(own_load(), 0);
    assert_eq!(attaches_load(), 0);
    assert_eq!(ModuleEntry(17usize as Handle, 0, ptr::null_mut()), 1);
    assert_eq!(attaches_load(), 0);
    assert_eq!(ModuleEntry(17usize as Handle, 1, ptr::null_mut()), 1);
    assert_eq!(own_load(), 17);
    assert_eq!(attaches_load(), 1);
    assert_eq!(ModuleEntry(18usize as Handle, 2, ptr::null_mut()), 1);
    assert_eq!(own_load(), 17);
    assert_eq!(attaches_load(), 1);
    let mut out = Observation {
        size: 32,
        attach: 0,
        query: 0,
        evaluated: 0,
        own_root: 0,
        error: 0,
        returned: 0,
        assemblies: 0,
    };
    unsafe {
        assert_eq!(read_word((&out as *const Observation).cast()), 32);
        write_word(
            (&mut out as *mut Observation)
                .cast::<u8>()
                .wrapping_add(20)
                .cast(),
            57,
        );
    }
    assert_eq!(
        (
            out.size,
            out.attach,
            out.query,
            out.evaluated,
            out.own_root,
            out.error,
            out.returned,
            out.assemblies
        ),
        (32, 0, 0, 0, 0, 57, 0, 0)
    );
    unsafe {
        memset(ptr::addr_of_mut!(STORAGE).cast(), 255, 65536);
        memset(ptr::addr_of_mut!(MODULE_PATH).cast(), 255, 2048);
        memset(ptr::addr_of_mut!(HOST_PATH).cast(), 255, 2048);
    }
    clear_storage();
    unsafe {
        assert!((&*ptr::addr_of!(STORAGE.0)).iter().all(|value| *value == 0));
        assert!(
            (&*ptr::addr_of!(MODULE_PATH))
                .iter()
                .all(|value| *value == 0)
        );
        assert!((&*ptr::addr_of!(HOST_PATH)).iter().all(|value| *value == 0));
    }
}
