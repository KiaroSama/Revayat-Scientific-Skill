//! Host private-directory lifecycle. Authority is deliberate only inside this positive control.
use super::{
    Handle,
    authority::{Descriptor, wide},
    scratch_access::{self as access, Identity, Owned},
};
use crate::windows_security::scratch::{
    self,
    private::{Lifecycle, Removal},
};
use anyhow::{Result, ensure};
use std::{
    cell::RefCell,
    error::Error,
    fmt,
    mem::size_of,
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::Arc,
};
#[derive(Debug)]
struct PortableFailure(scratch::SharedError);
impl fmt::Display for PortableFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl Error for PortableFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn shared<T>(result: Result<T>) -> scratch::OperationResult<T> {
    result.map_err(|error| Arc::from(error.into_boxed_dyn_error()))
}
fn portable<T>(result: scratch::OperationResult<T>) -> Result<T> {
    result.map_err(|error| anyhow::Error::new(PortableFailure(error)))
}
#[repr(C)]
struct Security {
    size: u32,
    descriptor: Handle,
    inherit: i32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateDirectoryW(path: *const u16, security: *const Security) -> i32;
    fn GetFileAttributesW(path: *const u16) -> u32;
    fn SetFileInformationByHandle(
        handle: Handle,
        class: u32,
        data: *const std::ffi::c_void,
        size: u32,
    ) -> i32;
}
struct Binding {
    path: PathBuf,
    host: String,
    package: String,
    root_pin: Owned,
    pin: Owned,
    root_id: Identity,
    id: Identity,
    native_root: String,
}
impl Binding {
    fn root(&self) -> Result<()> {
        ensure!(
            access::identity(self.root_pin.0, true)? == self.root_id
                && access::name(self.root_pin.0)? == self.native_root,
            "private creator root binding differs"
        );
        Ok(())
    }
    fn directory(&self, handle: Handle) -> Result<()> {
        self.root()?;
        ensure!(
            access::identity(handle, true)? == self.id
                && self.id.volume == self.root_id.volume
                && access::name(handle)? == format!("{}private-creator", self.native_root),
            "private creator directory binding differs"
        );
        Ok(())
    }
    fn policy(&self, handle: Handle) -> Result<()> {
        let bytes = access::security(handle, 0x17)?;
        scratch::private::require_policy(
            &bytes,
            &scratch::sid(&self.host)?,
            &scratch::sid(&self.package)?,
        )
    }
    fn empty(&self) -> Result<()> {
        self.directory(self.pin.0)?;
        self.policy(self.pin.0)?;
        ensure!(
            std::fs::read_dir(&self.path)?.next().is_none(),
            "private creator directory is not empty"
        );
        self.directory(self.pin.0)
    }
}
pub(super) struct PrivateCreator {
    lifecycle: Lifecycle,
    binding: Binding,
}
impl PrivateCreator {
    pub fn prepare(root: &str, host: &str, package: &str) -> Result<Self> {
        let folder = scratch::private::folder(root)?;
        let path = PathBuf::from(folder);
        absent(&path)?;
        let mut root_pin = Owned::open(root, 0x80, 3, 0x2200000)?;
        let result = (|| {
            let root_id = access::identity(root_pin.0, true)?;
            let native_root = access::name(root_pin.0)?;
            ensure!(
                scratch::private::native_root(&native_root),
                "private creator native root differs"
            );
            let mut descriptor = Descriptor::new(&format!(
                "O:{host}G:{host}D:P(A;;FA;;;{host})(A;;FA;;;{package})S:(ML;OICI;NW;;;LW)"
            ))?;
            let text = wide(&path);
            let security = Security {
                size: size_of::<Security>() as u32,
                descriptor: descriptor.0,
                inherit: 0,
            };
            let result = if unsafe { CreateDirectoryW(text.as_ptr(), &security) } != 0 {
                Ok(())
            } else {
                Err(access::native_error("create private creator directory"))
            };
            access::combine(result, descriptor.close())?;
            let mut pin = Owned::open(&path, 0x20081, 3, 0x2200000)?;
            let result = (|| {
                let id = access::identity(pin.0, true)?;
                let binding = Binding {
                    path,
                    host: host.into(),
                    package: package.into(),
                    root_pin: Owned(std::mem::replace(&mut root_pin.0, null_mut())),
                    pin: Owned(std::mem::replace(&mut pin.0, null_mut())),
                    root_id,
                    id,
                    native_root,
                };
                let mut owner = Self {
                    lifecycle: Lifecycle::default(),
                    binding,
                };
                let binding = &owner.binding;
                portable(owner.lifecycle.prepare(|| shared(binding.empty())))?;
                Ok(owner)
            })();
            access::combine(result, pin.close())
        })();
        access::combine(result, root_pin.close())
    }
    pub fn seal(&mut self) -> Result<()> {
        let binding = &self.binding;
        portable(self.lifecycle.seal(|| shared(binding.empty())))
    }
    /// Called only for the fixed ordinary preflight before its suspended primary resumes.
    pub fn use_suspended(&mut self, process: Handle) -> Result<()> {
        let binding = &self.binding;
        portable(self.lifecycle.use_control(|| {
            shared((|| {
                binding.empty()?;
                ensure!(
                    access::process_sid(process, 1)? == scratch::sid(&binding.host)?
                        && access::process_sid(process, 31)? == scratch::sid(&binding.package)?,
                    "private creator suspended token binding differs"
                );
                Ok(())
            })())
        }))
    }
    /// The enclosing native completion owner supplies its actual cleanup result.
    pub fn end_observation(&mut self, clean: bool) {
        self.lifecycle.end(clean);
    }
    pub fn remove_before_admission(&mut self) -> Result<()> {
        let binding = RefCell::new(&mut self.binding);
        portable(self.lifecycle.remove(|| {
            scratch::private::remove_bound(Removal {
                check: &mut || shared(binding.borrow().empty()),
                close_pin: &mut || shared(binding.borrow_mut().pin.close()),
                open: &mut || {
                    let path = binding.borrow().path.clone();
                    let handle = shared(Owned::open(path, 0x30081, 3, 0x2200000))?;
                    let raw = handle.0 as usize;
                    std::mem::forget(handle);
                    Ok(raw)
                },
                bind: &mut |raw| {
                    shared((|| {
                        let binding = binding.borrow();
                        binding.directory(raw as Handle)?;
                        binding.policy(raw as Handle)?;
                        ensure!(
                            std::fs::read_dir(&binding.path)?.next().is_none(),
                            "private creator removal directory is not empty"
                        );
                        binding.directory(raw as Handle)
                    })())
                },
                dispose: &mut |raw| shared(mark_delete(raw as Handle)),
                close: &mut |raw| shared(Owned(raw as Handle).close()),
                absent: &mut || shared(absent(&binding.borrow().path)),
            })?;
            shared(binding.borrow_mut().root_pin.close())
        }))
    }
    pub fn release(&mut self) -> Result<()> {
        let binding = &mut self.binding;
        portable(self.lifecycle.release(|| {
            shared(access::combine(
                binding.pin.close(),
                binding.root_pin.close(),
            ))
        }))
    }
}
impl Drop for PrivateCreator {
    fn drop(&mut self) {
        if self.release().is_err() {
            let pin = std::mem::replace(&mut self.binding.pin.0, null_mut());
            let root = std::mem::replace(&mut self.binding.root_pin.0, null_mut());
            std::mem::forget(Owned(pin));
            std::mem::forget(Owned(root));
        }
    }
}
pub(super) fn mark_delete(handle: Handle) -> Result<()> {
    let remove = 1u8;
    ensure!(
        unsafe { SetFileInformationByHandle(handle, 4, (&remove as *const u8).cast(), 1) } != 0,
        "bound scratch disposition failed"
    );
    Ok(())
}
fn absent(path: &Path) -> Result<()> {
    let text = wide(path);
    let attributes = unsafe { GetFileAttributesW(text.as_ptr()) };
    let error = std::io::Error::last_os_error().raw_os_error();
    ensure!(
        attributes == u32::MAX && error == Some(2),
        "private creator path is not proven absent"
    );
    Ok(())
}
pub(super) fn prepare_junction(root: &str) -> Result<()> {
    super::scratch_layout::drive_root(root)?;
    let path = Path::new(root).join("prepared-junction");
    std::fs::create_dir(&path)?;
    let mut handle = Owned::open(&path, 0x40000000, 0, 0x2200000)?;
    let result = (|| {
        let target = format!("{root}junction-target");
        let substitute = format!("\\??\\{target}").encode_utf16().collect::<Vec<_>>();
        let print = target.encode_utf16().collect::<Vec<_>>();
        let sub_bytes = substitute.len() * 2;
        let print_bytes = print.len() * 2;
        let mut data = Vec::new();
        data.extend(0xa0000003u32.to_le_bytes());
        data.extend(((8 + sub_bytes + 2 + print_bytes + 2) as u16).to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.extend((sub_bytes as u16).to_le_bytes());
        data.extend(((sub_bytes + 2) as u16).to_le_bytes());
        data.extend((print_bytes as u16).to_le_bytes());
        for unit in substitute
            .into_iter()
            .chain(Some(0))
            .chain(print)
            .chain(Some(0))
        {
            data.extend(unit.to_le_bytes());
        }
        access::ioctl(handle.0, 0x900a4, &data, &mut [])?;
        Ok(())
    })();
    access::combine(result, handle.close())
}
