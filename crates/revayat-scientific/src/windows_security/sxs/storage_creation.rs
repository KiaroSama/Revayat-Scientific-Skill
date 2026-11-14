//! One synchronous NtCreateFile request with retained aligned outputs and explicit pending abort.
use super::{Completion, creation_completion, native_path};
use crate::windows_security::{activation::Failures, sxs::safe_stage};
use anyhow::{Result, ensure};
use std::cell::RefCell;
#[path = "storage_creation_checks.rs"]
mod checks;
pub use checks::check_validation;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum: u16,
    pub buffer: usize,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Attributes {
    pub length: u32,
    pub root: usize,
    pub name: usize,
    pub flags: u32,
    pub descriptor: usize,
    pub qos: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union IoValue {
    pub status: i32,
    pub pointer: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoStatus {
    pub value: IoValue,
    pub information: usize,
}
impl IoStatus {
    pub fn status(self) -> i32 {
        unsafe { self.value.status }
    }
}
pub struct NativeCreation {
    words: Vec<u64>,
    descriptor_offset: usize,
}
#[derive(Clone, Copy)]
pub struct Parameters {
    pub access: u32,
    pub allocation: usize,
    pub flags: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    pub ea: usize,
    pub ea_length: u32,
}
impl NativeCreation {
    pub fn parameters(&self) -> Parameters {
        Parameters {
            access: 0x120080,
            allocation: 0,
            flags: 0x80,
            share: 0,
            disposition: 2,
            options: 0x21,
            ea: 0,
            ea_length: 0,
        }
    }
    pub fn new(path: &str, descriptor: &[u8]) -> Result<Self> {
        ensure!(
            std::mem::size_of::<usize>() == 8
                && !descriptor.is_empty()
                && descriptor.len() <= 65536,
            "fixed SxS native request shape differs"
        );
        let name = path.encode_utf16().collect::<Vec<_>>();
        let name_bytes = name
            .len()
            .checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("fixed SxS name overflow"))?;
        ensure!(name_bytes <= 512, "fixed SxS native path exceeds bound");
        let descriptor_offset = (40 + name_bytes + 2 + 7) & !7;
        let size = descriptor_offset + descriptor.len();
        let mut request = Self {
            words: vec![0; size.div_ceil(8)],
            descriptor_offset,
        };
        let base = request.words.as_ptr() as usize;
        {
            let bytes = request.bytes_mut();
            bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
            bytes[24..26].copy_from_slice(&(name_bytes as u16).to_le_bytes());
            bytes[26..28].copy_from_slice(&((name_bytes + 2) as u16).to_le_bytes());
            bytes[32..40].copy_from_slice(&(base + 40).to_le_bytes());
            for (index, unit) in name.into_iter().enumerate() {
                bytes[40 + index * 2..42 + index * 2].copy_from_slice(&unit.to_le_bytes());
            }
            bytes[descriptor_offset..descriptor_offset + descriptor.len()]
                .copy_from_slice(descriptor);
        }
        Ok(request)
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.words.len() * 8) }
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.words.len() * 8)
        }
    }
    pub fn attributes(&self) -> Attributes {
        let base = self.words.as_ptr() as usize;
        Attributes {
            length: 48,
            root: 0,
            name: base + 24,
            flags: 0x1040,
            descriptor: base + self.descriptor_offset,
            qos: 0,
        }
    }
    pub fn handle_slot(&mut self) -> *mut usize {
        self.words.as_mut_ptr().cast()
    }
    pub fn io_slot(&mut self) -> *mut IoStatus {
        unsafe { self.words.as_mut_ptr().cast::<u8>().add(8).cast() }
    }
    pub fn handle(&self) -> usize {
        usize::from_le_bytes(self.bytes()[..8].try_into().unwrap())
    }
    pub fn io(&self) -> IoStatus {
        unsafe {
            self.words
                .as_ptr()
                .cast::<u8>()
                .add(8)
                .cast::<IoStatus>()
                .read()
        }
    }
    pub fn within(&self, address: usize, length: usize, alignment: usize) -> bool {
        let base = self.words.as_ptr() as usize;
        alignment != 0
            && address.is_multiple_of(alignment)
            && address >= base
            && address - base <= self.bytes().len()
            && length <= self.bytes().len() - (address - base)
    }
    pub fn clear(&mut self) {
        for word in &mut self.words {
            unsafe {
                std::ptr::write_volatile(word, 0);
            }
        }
    }
}
impl Drop for NativeCreation {
    fn drop(&mut self) {
        self.clear();
    }
}
pub fn require_result(returned: i32, completed: IoStatus, handle: usize) -> Result<()> {
    if returned != 0 {
        return Err(safe_stage(
            anyhow::anyhow!("fixed SxS native creation failed"),
            format!("storage-create ntstatus-{:08X}", returned as u32),
        ));
    }
    ensure!(
        creation_completion(
            returned,
            completed.status(),
            completed.information as u64,
            handle
        )? == Completion::Created,
        "fixed SxS native creation output differs"
    );
    Ok(())
}
pub fn complete(
    returned: i32,
    read: impl FnOnce() -> Result<IoStatus>,
    handle: impl FnOnce() -> Result<usize>,
    fatal: impl FnOnce() -> Result<()>,
    finalize: impl FnOnce(Result<()>) -> Result<()>,
    pending: &mut bool,
) -> Result<()> {
    *pending = returned == 0x103;
    let operation = (|| {
        let completed = if !*pending {
            let completed = read()?;
            *pending = completed.status() == 0x103;
            completed
        } else {
            IoStatus {
                value: IoValue { pointer: 0 },
                information: 0,
            }
        };
        if *pending {
            fatal()?;
            anyhow::bail!("fixed SxS pending termination unexpectedly returned");
        }
        require_result(returned, completed, handle()?)
    })();
    if *pending {
        operation
    } else {
        finalize(operation)
    }
}
pub fn release<'a>(
    operation: Result<()>,
    handle: usize,
    close: impl FnOnce(usize) -> Result<()>,
    releases: Vec<Box<dyn FnMut() -> Result<()> + 'a>>,
) -> Result<()> {
    let mut errors = Vec::new();
    if handle != 0
        && handle != usize::MAX
        && let Err(error) = close(handle)
    {
        errors.push(error);
    }
    for mut release in releases {
        if let Err(error) = release() {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        operation
    } else {
        let mut all = operation.err().into_iter().collect::<Vec<_>>();
        all.extend(errors);
        Err(Failures { errors: all }.into())
    }
}
pub trait CreationIo {
    fn query(&mut self, drive: &str, output: &mut [u16; 512]) -> Result<usize>;
    fn create(&mut self, request: &mut NativeCreation) -> Result<i32>;
    fn close(&mut self, handle: usize) -> Result<()>;
    fn fatal(&mut self) -> Result<()>;
}
pub fn create_fixed(folder: &str, descriptor: &mut [u8], io: &mut impl CreationIo) -> Result<()> {
    let mut request = None;
    let mut attempted = false;
    let mut handed = false;
    let mut pending = false;
    let io = RefCell::new(io);
    let operation = (|| {
        ensure!(
            !descriptor.is_empty() && descriptor.len() <= 65536,
            "fixed SxS creation descriptor bound differs"
        );
        super::validate_folder(folder)?;
        let mut mapping = [0u16; 512];
        let returned = io.borrow_mut().query(&folder[..2], &mut mapping)?;
        ensure!(
            (3..=512).contains(&returned),
            "fixed SxS device query length differs"
        );
        let path = native_path(folder, &mapping[..returned])?;
        request = Some(RefCell::new(NativeCreation::new(&path, descriptor)?));
        let request = request.as_ref().unwrap();
        attempted = true;
        let returned = io.borrow_mut().create(&mut request.borrow_mut())?;
        handed = true;
        complete(
            returned,
            || Ok(request.borrow().io()),
            || Ok(request.borrow().handle()),
            || io.borrow_mut().fatal(),
            |operation| {
                let handle = request.borrow().handle();
                release(
                    operation,
                    handle,
                    |handle| io.borrow_mut().close(handle),
                    vec![
                        Box::new(|| {
                            request.borrow_mut().clear();
                            Ok(())
                        }),
                        Box::new(|| {
                            descriptor.fill(0);
                            Ok(())
                        }),
                    ],
                )
            },
            &mut pending,
        )
    })();
    if attempted
        && !handed
        && request
            .as_ref()
            .is_some_and(|request| request.borrow().io().status() == 0x103)
    {
        let result = io.borrow_mut().fatal();
        if let Some(request) = request.take() {
            std::mem::forget(request);
        }
        return match result {
            Err(error) => Err(error),
            Ok(()) => Err(anyhow::anyhow!(
                "fixed SxS pending termination unexpectedly returned"
            )),
        };
    }
    if pending {
        if let Some(request) = request.take() {
            std::mem::forget(request);
        }
        return operation;
    }
    if !handed {
        let handle = if attempted {
            request
                .as_ref()
                .map_or(0, |request| request.borrow().handle())
        } else {
            0
        };
        release(
            operation,
            handle,
            |handle| io.borrow_mut().close(handle),
            vec![
                Box::new(|| {
                    if let Some(request) = &request {
                        request.borrow_mut().clear();
                    }
                    Ok(())
                }),
                Box::new(|| {
                    descriptor.fill(0);
                    Ok(())
                }),
            ],
        )
    } else {
        operation
    }
}
