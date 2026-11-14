//! Statically imports the one fixed DLL export, then emits its bounded observation.
use super::{
    abi,
    emit::{Record, emit},
};
#[repr(C)]
pub struct Observation {
    pub size: u32,
    pub attach: u32,
    pub query: u32,
    pub evaluated: u32,
    pub own_root: u32,
    pub error: u32,
    pub returned: u32,
    pub assemblies: u32,
}
const _: () = {
    assert!(core::mem::size_of::<Observation>() == 32);
    assert!(core::mem::offset_of!(Observation, error) == 20);
    assert!(core::mem::offset_of!(Observation, assemblies) == 28);
};
#[link(name = "startup-module")]
unsafe extern "system" {
    fn ObserveModuleActivation(out: *mut Observation) -> i32;
}
pub fn run() -> ! {
    let mut value = Observation {
        size: 32,
        attach: 0,
        query: 0,
        evaluated: 0,
        own_root: 0,
        error: 0,
        returned: 0,
        assemblies: 0,
    };
    if unsafe { ObserveModuleActivation(&mut value) } == 0
        || value.size != 32
        || value.attach != 1
        || value.query > 1
        || value.evaluated > 1
        || value.own_root > 1
        || value.returned > 65536
        || value.assemblies > 16
        || value.query != 0 && (value.error != 0 || value.returned < 64)
        || value.query == 0
            && (value.error == 0
                || value.evaluated != 0
                || value.own_root != 0
                || value.assemblies != 0)
        || value.own_root != 0 && value.evaluated == 0
    {
        unsafe { abi::ExitProcess(121) }
    }
    let mut line = Record::new();
    line.append(b"WINDOWS_MODULE_ACTIVATION attach=1 query_succeeded=");
    line.append(&[b'0' + value.query as u8]);
    line.append(b" root_evaluated=");
    line.append(&[b'0' + value.evaluated as u8]);
    line.append(b" root_is_module=");
    line.append(&[b'0' + value.own_root as u8]);
    line.append(b" win32_error=0x");
    line.hexadecimal(value.error);
    line.append(b" returned_bytes=0x");
    line.hexadecimal(value.returned);
    line.append(b" assembly_count=0x");
    line.hexadecimal(value.assemblies);
    line.append(b"\n");
    emit(
        unsafe { abi::GetStdHandle(-11i32 as u32) },
        line.bytes(),
        121,
    );
    unsafe { abi::ExitProcess(0) }
}
