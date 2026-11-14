//! One typed NT file-creation ABI shared by the SxS owner and private-state fixture.
use super::storage::creation::{self, IoStatus};
use registry_authority::native::{Attributes, Unicode};
use std::{
    ffi::c_void,
    mem::{offset_of, size_of},
};
type Handle = *mut c_void;
// The retained portable request uses integer pointer storage; binding it to the Windows
// structures is valid only at these exact x64 sizes and offsets.
const _: () = {
    assert!(size_of::<Handle>() == 8);
    assert!(size_of::<Unicode>() == 16 && size_of::<creation::UnicodeString>() == 16);
    assert!(
        offset_of!(Unicode, length) == 0
            && offset_of!(Unicode, maximum) == 2
            && offset_of!(Unicode, buffer) == 8
    );
    assert!(size_of::<Attributes>() == 48 && size_of::<creation::Attributes>() == 48);
    assert!(
        offset_of!(Attributes, length) == 0
            && offset_of!(Attributes, root) == 8
            && offset_of!(Attributes, name) == 16
    );
    assert!(
        offset_of!(Attributes, flags) == 24
            && offset_of!(Attributes, descriptor) == 32
            && offset_of!(Attributes, qos) == 40
    );
    assert!(
        size_of::<IoStatus>() == 16
            && offset_of!(IoStatus, value) == 0
            && offset_of!(IoStatus, information) == 8
    );
};
pub(crate) fn bind_attributes(value: creation::Attributes) -> Attributes {
    Attributes {
        length: value.length,
        root: value.root as Handle,
        name: value.name as *const Unicode,
        flags: value.flags,
        descriptor: value.descriptor as Handle,
        qos: value.qos as Handle,
    }
}
#[link(name = "ntdll")]
unsafe extern "system" {
    pub(crate) fn NtCreateFile(
        handle: *mut Handle,
        access: u32,
        attributes: *const Attributes,
        io: *mut IoStatus,
        allocation: *const i64,
        flags: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: Handle,
        ea_length: u32,
    ) -> i32;
}
