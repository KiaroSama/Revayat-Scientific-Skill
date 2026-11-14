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
fn text_valid(text: &[u16], chars: usize) -> bool {
    if chars > 1023 || chars >= text.len() || text[chars] != 0 {
        return false;
    }
    let mut index = 0;
    while index < chars {
        let value = text[index];
        if value == 0 {
            return false;
        }
        if (0xd800..=0xdbff).contains(&value) {
            index += 1;
            if index >= chars || !(0xdc00..=0xdfff).contains(&text[index]) {
                return false;
            }
        } else if (0xdc00..=0xdfff).contains(&value) {
            return false;
        }
        index += 1;
    }
    true
}
fn span_text(buffer: &[u8], pointer: *const u16, chars: u32) -> bool {
    if pointer.is_null() {
        return chars == 0;
    }
    let address = pointer as usize;
    let start = buffer.as_ptr() as usize;
    if address & 1 != 0 || address < start || chars > 1023 {
        return false;
    }
    let offset = address - start;
    let count = chars as usize + 1;
    if offset < 64 || offset > buffer.len() || count * 2 > buffer.len() - offset {
        return false;
    }
    // SAFETY: complete aligned span lies in the live supplied activation buffer.
    text_valid(
        unsafe { core::slice::from_raw_parts(pointer, count) },
        chars as usize,
    )
}
fn detail_valid(buffer: &[u8], size: usize) -> Option<(Detail, *const u16, u32)> {
    if !(64..=65536).contains(&size) || size > buffer.len() {
        return None;
    }
    // SAFETY: width was checked; unaligned read avoids imposing caller alignment.
    let detail = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<Detail>()) };
    let span = &buffer[..size];
    if detail.flags != 0
        || detail.version > 1
        || detail.assemblies > 16
        || detail.root_type > 4
        || detail.config_type > 4
        || detail.dir_type > 4
        || !span_text(span, detail.root, detail.root_chars)
        || !span_text(span, detail.config, detail.config_chars)
        || !span_text(span, detail.dir, detail.dir_chars)
        || detail.root_chars != 0
            && (detail.version != 1 || detail.assemblies == 0 || detail.root_type != 2)
    {
        return None;
    }
    Some((detail, detail.root, detail.root_chars))
}
fn self_check() -> bool {
    let mut bytes = Aligned([0u8; 128]);
    let text = unsafe { bytes.0.as_mut_ptr().add(64).cast::<u16>() };
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
        text.write(65);
        text.add(1).write(58);
        text.add(2).write(92);
        text.add(3).write(0);
    }
    fn check(bytes: &mut Aligned<128>, detail: Detail, size: usize) -> bool {
        unsafe { ptr::write_unaligned(bytes.0.as_mut_ptr().cast::<Detail>(), detail) };
        detail_valid(&bytes.0, size).is_some()
    }
    if !check(&mut bytes, detail, 72) {
        return false;
    }
    let (_, root, chars) = detail_valid(&bytes.0, 72).unwrap();
    if root != text || chars != 3 {
        return false;
    }
    for changed in [
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
            root: unsafe { bytes.0.as_ptr().add(65).cast() },
            ..detail
        },
        Detail {
            root: unsafe { bytes.0.as_ptr().add(62).cast() },
            ..detail
        },
        Detail {
            root: unsafe { bytes.0.as_ptr().add(72).cast() },
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
        if check(&mut bytes, changed, 72) {
            return false;
        }
    }
    unsafe { text.add(3).write(88) };
    if check(&mut bytes, detail, 72) {
        return false;
    }
    unsafe { text.add(3).write(0) };
    for invalid in [0, 0xd800, 0xdc00] {
        unsafe { text.add(1).write(invalid) };
        if check(&mut bytes, detail, 72) {
            return false;
        }
    }
    unsafe {
        text.add(1).write(0xd800);
        text.add(2).write(0xdc00)
    };
    if !check(&mut bytes, detail, 72) {
        return false;
    }
    unsafe {
        text.add(1).write(58);
        text.add(2).write(92)
    };
    let directory_pointer = unsafe { bytes.0.as_ptr().add(72).cast() };
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
    let (_, root, chars) = detail_valid(&bytes.0, 64).unwrap();
    if !root.is_null() || chars != 0 {
        return false;
    }
    unsafe { text.write(0) };
    detail.root = text;
    if !check(&mut bytes, detail, 66) {
        return false;
    }
    let (_, root, chars) = detail_valid(&bytes.0, 66).unwrap();
    root == text && chars == 0
}
#[unsafe(no_mangle)]
pub extern "system" fn ModuleEntry(module: Handle, reason: u32, _reserved: Handle) -> i32 {
    if reason == 1 {
        OWN.store(module as usize, Ordering::Release);
        ATTACHES.fetch_add(1, Ordering::AcqRel);
    }
    1
}
fn observe(out: *mut Observation) -> bool {
    let own = OWN.load(Ordering::Acquire) as Handle;
    if out.is_null()
        || unsafe { (*out).size } != 32
        || ATTACHES.load(Ordering::Acquire) != 1
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
        (*out).attach = 1;
        (*out).error = error;
        (*out).query = u32::from(query != 0);
        (*out).returned = required as u32;
    }
    let (root, chars) = if query != 0 {
        let Some((detail, root, chars)) = detail_valid(
            unsafe { core::slice::from_raw_parts(storage, 65536) },
            required,
        ) else {
            return false;
        };
        unsafe {
            (*out).assemblies = detail.assemblies;
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
        || !text_valid(
            unsafe { core::slice::from_raw_parts(host_path, 1024) },
            host_length,
        )
        || !text_valid(
            unsafe { core::slice::from_raw_parts(module_path, 1024) },
            module_length,
        )
    {
        return false;
    }
    let mut directory = host_length;
    while directory != 0 && unsafe { host_path.add(directory - 1).read() } != 92 {
        directory -= 1;
    }
    const BASENAME: [u16; 18] = [
        115, 116, 97, 114, 116, 117, 112, 45, 109, 111, 100, 117, 108, 101, 46, 100, 108, 108,
    ];
    if directory == 0
        || directory + 18 != module_length
        || unsafe {
            CompareStringOrdinal(
                host_path,
                directory as i32,
                module_path,
                directory as i32,
                1,
            )
        } != 2
        || unsafe { CompareStringOrdinal(module_path.add(directory), 18, BASENAME.as_ptr(), 18, 1) }
            != 2
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
            (*out).evaluated = 1;
            (*out).own_root = u32::from(compared == 2);
        }
    }
    true
}
#[unsafe(no_mangle)]
pub extern "system" fn ObserveModuleActivation(out: *mut Observation) -> i32 {
    let result = observe(out);
    for index in 0..65536 {
        unsafe {
            ptr::addr_of_mut!(STORAGE)
                .cast::<u8>()
                .add(index)
                .write_volatile(0)
        };
    }
    for index in 0..1024 {
        unsafe {
            ptr::addr_of_mut!(MODULE_PATH)
                .cast::<u16>()
                .add(index)
                .write_volatile(0);
            ptr::addr_of_mut!(HOST_PATH)
                .cast::<u16>()
                .add(index)
                .write_volatile(0);
        }
    }
    i32::from(result)
}
