//! x64 debug-event layouts and scoped context-buffer operations.
use super::*;
use crate::windows_security::activation::{CONTEXT_SIZE, threads::ContextIo};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Creation {
    pub file: Handle,
    pub process: Handle,
    pub thread: Handle,
    pub image_base: Handle,
    pub offset: u32,
    pub size: u32,
    pub local_base: Handle,
    pub start: Handle,
    pub image_name: Handle,
    pub unicode: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) union EventData {
    pub creation: Creation,
    pub words: [u64; 20],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Event {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub data: EventData,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct Region {
    pub address: Handle,
    pub allocation: Handle,
    pub allocation_protect: u32,
    pub partition: u16,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(super) fn WaitForDebugEventEx(event: *mut Event, milliseconds: u32) -> i32;
    pub(super) fn ContinueDebugEvent(pid: u32, tid: u32, status: u32) -> i32;
    pub(super) fn DuplicateHandle(
        source: Handle,
        handle: Handle,
        target: Handle,
        result: *mut Handle,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    pub(super) fn GetCurrentProcess() -> Handle;
    pub(super) fn GetThreadContext(thread: Handle, context: Handle) -> i32;
    pub(super) fn SetThreadContext(thread: Handle, context: *const c_void) -> i32;
    pub(super) fn VirtualQueryEx(
        process: Handle,
        address: Handle,
        region: *mut Region,
        size: usize,
    ) -> usize;
    pub(super) fn GetFileInformationByHandle(
        file: Handle,
        information: *mut windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
    ) -> i32;
}
pub(super) fn duplicate(handle: Handle) -> Result<Handle> {
    ensure!(
        !handle.is_null() && handle as usize != usize::MAX,
        "debug source handle is invalid"
    );
    let mut result = null_mut();
    let success = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut result,
            0,
            0,
            2,
        )
    };
    let error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    ensure!(
        success != 0 && !result.is_null(),
        "debug duplicate failed winerror={error:?}"
    );
    Ok(result)
}
pub(super) fn close(handle: Handle) -> Result<()> {
    if handle.is_null() || handle as usize == usize::MAX {
        return Ok(());
    }
    let success = unsafe { CloseHandle(handle) };
    let error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    ensure!(
        success != 0,
        "debug owned-handle close failed winerror={error:?}"
    );
    Ok(())
}
pub(super) struct StandardHandles {
    pub handles: Box<[Handle; 3]>,
    attributes: Vec<usize>,
    initialized: bool,
}
impl StandardHandles {
    pub fn new(capture: bool) -> Result<(Self, Option<debug_capture::Transport>)> {
        let mut owner = Self {
            handles: Box::new([null_mut(); 3]),
            attributes: Vec::new(),
            initialized: false,
        };
        let mut transport = None;
        let result = (|| {
            let security = registry_authority::native::Security {
                length: size_of::<registry_authority::native::Security>() as u32,
                descriptor: null_mut(),
                inherit: 1,
            };
            let nul = "NUL\0".encode_utf16().collect::<Vec<_>>();
            for index in 0..3 {
                let handle = unsafe {
                    registry_authority::native::CreateFileW(
                        nul.as_ptr(),
                        if index == 0 { 0x80000000 } else { 0x40000000 },
                        3,
                        &security,
                        3,
                        0x80,
                        null_mut(),
                    )
                };
                let error = if handle as usize == usize::MAX {
                    Some(unsafe { GetLastError() })
                } else {
                    None
                };
                ensure!(
                    !handle.is_null() && handle as usize != usize::MAX,
                    "debug NUL standard handle failed winerror={error:?}"
                );
                owner.handles[index] = handle;
            }
            if capture {
                transport = Some(debug_capture::Transport::attach(&mut owner)?);
            }
            let mut size = 0;
            let success = unsafe {
                registry_authority::native::InitializeProcThreadAttributeList(
                    null_mut(),
                    1,
                    0,
                    &mut size,
                )
            };
            let error = if success == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            ensure!(
                success == 0 && error == 122 && (1..=65536).contains(&size),
                "debug attribute sizing differs"
            );
            owner.attributes = vec![0; size.div_ceil(size_of::<usize>())];
            let success = unsafe {
                registry_authority::native::InitializeProcThreadAttributeList(
                    owner.attributes.as_mut_ptr().cast(),
                    1,
                    0,
                    &mut size,
                )
            };
            let error = if success == 0 {
                Some(unsafe { GetLastError() })
            } else {
                None
            };
            ensure!(
                success != 0,
                "debug attributes init failed winerror={error:?}"
            );
            owner.initialized = true;
            let success = unsafe {
                registry_authority::native::UpdateProcThreadAttribute(
                    owner.attributes.as_mut_ptr().cast(),
                    0,
                    0x20002,
                    owner.handles.as_mut_ptr().cast(),
                    size_of::<[Handle; 3]>(),
                    null_mut(),
                    null_mut(),
                )
            };
            let error = if success == 0 {
                Some(unsafe { GetLastError() })
            } else {
                None
            };
            ensure!(
                success != 0,
                "debug exact standard handle list failed winerror={error:?}"
            );
            Ok(())
        })();
        if let Err(primary) = result {
            let mut errors = vec![primary];
            if let Err(error) = owner.close() {
                errors.push(error);
            }
            if let Some(value) = &mut transport
                && let Err(error) = value.close()
            {
                errors.push(error);
            }
            return Err(crate::windows_security::activation::Failures { errors }.into());
        }
        Ok((owner, transport))
    }
    pub fn list(&mut self) -> Handle {
        self.attributes.as_mut_ptr().cast()
    }
    pub fn close(&mut self) -> Result<()> {
        if self.initialized {
            unsafe {
                registry_authority::native::DeleteProcThreadAttributeList(
                    self.attributes.as_mut_ptr().cast(),
                )
            };
            self.initialized = false;
        }
        let mut errors = Vec::new();
        for handle in self.handles.iter_mut() {
            if let Err(error) = close(std::mem::replace(handle, null_mut())) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::windows_security::activation::Failures { errors }.into())
        }
    }
}
impl Drop for StandardHandles {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
#[repr(align(16))]
struct Aligned([u8; CONTEXT_SIZE]);
pub(super) struct NativeContext {
    pub started: Instant,
    pub cleanup: bool,
    pub owner: std::thread::ThreadId,
}
impl ContextIo for NativeContext {
    fn read(&mut self, handle: usize) -> Result<Vec<u8>> {
        self.deadline()?;
        let mut buffer = Aligned([0; CONTEXT_SIZE]);
        buffer.0[48..52].copy_from_slice(&0x100013u32.to_le_bytes());
        let success = unsafe { GetThreadContext(handle as Handle, buffer.0.as_mut_ptr().cast()) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        let result = if success == 0 {
            Err(anyhow::anyhow!(
                "read stopped debug context failed winerror={error:?}"
            ))
        } else {
            Ok(buffer.0.to_vec())
        };
        buffer.0.fill(0);
        result
    }
    fn write(&mut self, handle: usize, bytes: &[u8]) -> Result<()> {
        self.deadline()?;
        ensure!(
            bytes.len() == CONTEXT_SIZE && bytes[48..52] == 0x100010u32.to_le_bytes(),
            "debug write must select DEBUG_REGISTERS only"
        );
        let mut buffer = Aligned([0; CONTEXT_SIZE]);
        buffer.0.copy_from_slice(bytes);
        let success = unsafe { SetThreadContext(handle as Handle, buffer.0.as_ptr().cast()) };
        let error = if success == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        buffer.0.fill(0);
        ensure!(
            success != 0,
            "write stopped debug context failed winerror={error:?}"
        );
        Ok(())
    }
    fn close(&mut self, handle: usize) -> Result<()> {
        close(handle as Handle)
    }
    fn deadline(&mut self) -> Result<()> {
        ensure!(
            std::thread::current().id() == self.owner
                && self.started.elapsed() < Duration::from_secs(if self.cleanup { 5 } else { 10 }),
            "debug owner thread or deadline differs"
        );
        Ok(())
    }
}
