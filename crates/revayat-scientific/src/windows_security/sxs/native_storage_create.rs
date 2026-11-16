//! Real NtCreateFile adapter for the same retained request and pending/finalization seam.
use super::*;
use crate::windows_security::sxs::{
    native_file_abi::{NtCreateFile, bind_attributes},
    storage::creation::{self, CreationIo, NativeCreation},
};
struct Native<'a> {
    created: &'a mut bool,
    identity: &'a mut Option<ObjectId>,
}
impl CreationIo for Native<'_> {
    fn query(&mut self, drive: &str, output: &mut [u16; 512]) -> Result<usize> {
        let drive = wide(drive);
        let returned = unsafe { QueryDosDeviceW(drive.as_ptr(), output.as_mut_ptr(), 512) };
        let code = if returned == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        if returned == 0 {
            return Err(diagnostics::native(
                Stage::SxsStorageCreate,
                Numbers {
                    native_error: Some(code),
                    count: Some(returned),
                    ..Default::default()
                },
            ));
        }
        Ok(returned as usize)
    }
    fn create(&mut self, request: &mut NativeCreation) -> Result<i32> {
        let arguments = request.parameters();
        let attributes = bind_attributes(request.attributes());
        let returned = unsafe {
            NtCreateFile(
                request.handle_slot().cast::<Raw>(),
                arguments.access,
                &attributes,
                request.io_slot(),
                arguments.allocation as *const i64,
                arguments.flags,
                arguments.share,
                arguments.disposition,
                arguments.options,
                arguments.ea as Raw,
                arguments.ea_length,
            )
        };
        *self.created = returned == 0;
        Ok(returned)
    }
    fn close(&mut self, handle: usize) -> Result<()> {
        let file = unsafe { File::from_raw_handle(handle as Raw) };
        let identity = identity::object_id(&file);
        if let Ok(id) = &identity {
            *self.identity = Some(*id);
        }
        tokens::finish(
            identity.map(|_| ()),
            close(file).err().into_iter().collect(),
        )
    }
    fn fatal(&mut self) -> Result<()> {
        std::process::abort()
    }
}
pub(super) fn create(
    folder: &str,
    descriptor: &mut [u8],
    created: &mut bool,
    identity: &mut Option<ObjectId>,
) -> Result<()> {
    creation::create_fixed(folder, descriptor, &mut Native { created, identity })
}
