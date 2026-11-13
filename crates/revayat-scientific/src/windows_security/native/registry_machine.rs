//! One fixed SideBySide DACL lease. Only an outer owned-tree proof can retire its durable intent.
//! A held named mutex prevents concurrent cooperating leases; read/compare/write is not atomic CAS.
use super::{Handle, NativeRunOwner};
use crate::{
    identity::{self, ObjectId},
    runtime::ReapedProcessTree,
    windows_security::{
        plain_path,
        policy::{
            descriptor_equal,
            registry_lease::{RegistryIo, RegistryLease, require_absent, require_plain_attributes},
        },
    },
};
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, IntoRawHandle},
    },
    path::PathBuf,
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};
const KEY: &str = registry_authority::protocol::KEY;
const MUTEX: &str = r"Local\Scientific.Security.SideBySide.CausalLease";
const RECEIPT: &str = "registry-policy.receipt";
static RECOVERY_BLOCKED: AtomicBool = AtomicBool::new(false);
static SUPPORTED_ACTIVE: AtomicBool = AtomicBool::new(false);
#[repr(C)]
struct Name {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: Handle,
    name: *const Name,
    flags: u32,
    descriptor: Handle,
    qos: Handle,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenKey(key: *mut Handle, access: u32, attributes: *const Attributes) -> i32;
    fn NtQueryKey(
        key: Handle,
        kind: u32,
        data: *mut c_void,
        capacity: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtQuerySecurityObject(
        key: Handle,
        info: u32,
        data: *mut c_void,
        capacity: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtSetSecurityObject(key: Handle, info: u32, descriptor: *const c_void) -> i32;
    fn NtClose(key: Handle) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateMutexW(attributes: Handle, initial: i32, name: *const u16) -> Handle;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn SetFileInformationByHandle(
        handle: Handle,
        class: u32,
        data: *const c_void,
        bytes: u32,
    ) -> i32;
}
fn valid(handle: Handle) -> bool {
    !handle.is_null()
        && handle as isize > 0
        && !(0x80000000..=0x800000ff).contains(&(handle as usize))
}
fn combine<T>(result: Result<T>, cleanup: Result<()>) -> Result<T> {
    crate::runtime::with_cleanup(result, cleanup)
}
fn close_file(file: File) -> Result<()> {
    let handle = file.into_raw_handle();
    // SAFETY: ownership has transferred out of File; this numeric handle is attempted only once.
    let status = unsafe { CloseHandle(handle) };
    let code = if status == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    ensure!(
        status != 0,
        "registry lease file close failed winerror={code}"
    );
    Ok(())
}
fn package_bytes(text: &str) -> Result<Vec<u8>> {
    crate::windows_security::package_sid(text)?;
    let fields = text
        .strip_prefix("S-1-15-")
        .unwrap()
        .split('-')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut bytes = vec![1, fields.len() as u8, 0, 0, 0, 0, 0, 15];
    for field in fields {
        bytes.extend(field.to_le_bytes());
    }
    Ok(bytes)
}
struct NativeIo {
    key: Handle,
    mutex: Handle,
    state: PathBuf,
    state_id: ObjectId,
    anchor: Option<File>,
    receipt_id: Option<ObjectId>,
    closed: bool,
    supported: bool,
}
impl NativeIo {
    fn new(owner: &NativeRunOwner) -> Result<Self> {
        crate::windows_security::activation::native::require_host()?;
        owner.view.require()?;
        ensure!(
            !RECOVERY_BLOCKED.load(Ordering::SeqCst) && !SUPPORTED_ACTIVE.load(Ordering::SeqCst),
            "registry lease recovery is blocked or supported policy already active"
        );
        let state = owner.state_path().to_owned();
        let state_id = owner.state_identity();
        ensure!(
            state.is_absolute()
                && state.ancestors().count() < 64
                && state.file_name().and_then(|s| s.to_str())
                    == Some(format!("security-windows-{}", owner.run_id()).as_str()),
            "registry lease state binding differs"
        );
        plain_path(&state)?;
        let anchor = OpenOptions::new()
            .access_mode(0x20080)
            .share_mode(3)
            .custom_flags(0x02200000)
            .open(&state)?;
        let retained = (|| {
            ensure!(
                identity::object_id(&anchor)? == state_id,
                "registry lease state object changed"
            );
            Ok(())
        })();
        if let Err(primary) = retained {
            return combine(Err(primary), close_file(anchor));
        }
        let mut io = Self {
            key: null_mut(),
            mutex: null_mut(),
            state,
            state_id,
            anchor: Some(anchor),
            receipt_id: None,
            closed: false,
            supported: false,
        };
        let opened = (|| {
            let mutex: Vec<u16> = MUTEX.encode_utf16().chain(Some(0)).collect();
            // SAFETY: fixed live NUL-terminated name; default non-inheritable security attributes.
            io.mutex = unsafe { CreateMutexW(null_mut(), 0, mutex.as_ptr()) };
            let code = unsafe { GetLastError() };
            ensure!(
                valid(io.mutex) && code != 183,
                "registry policy lease is unavailable winerror={code}"
            );
            ensure!(
                size_of::<Name>() == 16 && size_of::<Attributes>() == 48,
                "registry lease requires x64 ABI"
            );
            let text: Vec<u16> = KEY.encode_utf16().chain(Some(0)).collect();
            let name = Name {
                length: 140,
                maximum: 142,
                buffer: text.as_ptr(),
            };
            let attributes = Attributes {
                length: 48,
                root: null_mut(),
                name: &name,
                flags: 0x1040,
                descriptor: null_mut(),
                qos: null_mut(),
            };
            // SAFETY: all counted native name/object-attribute backing storage is live for the call.
            let status = unsafe { NtOpenKey(&mut io.key, 0x60000, &attributes) };
            ensure!(
                status >= 0 && valid(io.key),
                "open fixed registry policy key failed status={:08X}",
                status as u32
            );
            let mut identity = [0u8; 4096];
            let mut returned = 0;
            // SAFETY: retained key and exact writable query capacity; returned controls all reads.
            let status =
                unsafe { NtQueryKey(io.key, 3, identity.as_mut_ptr().cast(), 4096, &mut returned) };
            ensure!(
                status >= 0
                    && (144..=4096).contains(&returned)
                    && u32::from_le_bytes(identity[..4].try_into()?) == 140,
                "fixed registry lease key identity query failed"
            );
            let name = identity[4..144]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect::<Vec<_>>();
            ensure!(
                String::from_utf16(&name)?.eq_ignore_ascii_case(KEY),
                "fixed registry lease key identity differs"
            );
            Ok(())
        })();
        if let Err(primary) = opened {
            return combine(Err(primary), io.close());
        }
        Ok(io)
    }
    fn require_state(&self) -> Result<()> {
        plain_path(&self.state)?;
        ensure!(
            identity::path_object_id(&self.state)? == self.state_id
                && self
                    .anchor
                    .as_ref()
                    .is_some_and(|file| identity::object_id(file).ok() == Some(self.state_id)),
            "registry lease lost its held state binding"
        );
        Ok(())
    }
    fn read_receipt(&mut self) -> Result<Vec<u8>> {
        self.require_state()?;
        let path = self.state.join(RECEIPT);
        plain_path(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(&path)?;
        let result = (|| {
            require_plain_attributes(file.metadata()?.file_attributes())?;
            let length = file.metadata()?.len();
            ensure!(
                (1..=196608).contains(&length),
                "registry lease receipt exceeds bound"
            );
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(196609)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == length,
                "registry lease receipt changed during read"
            );
            self.receipt_id = Some(identity::object_id(&file)?);
            Ok(bytes)
        })();
        combine(result, close_file(file))
    }
}
impl RegistryIo for NativeIo {
    fn persist(&mut self, receipt: &[u8]) -> Result<()> {
        self.require_state()?;
        let path = self.state.join(RECEIPT);
        plain_path(&path)?;
        require_absent(|| fs::symlink_metadata(&path).map(|metadata| metadata.file_attributes()))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x00200000)
            .open(&path)?;
        let result = (|| {
            require_plain_attributes(file.metadata()?.file_attributes())?;
            file.write_all(receipt)?;
            file.flush()?;
            file.sync_all()?;
            file.seek(SeekFrom::Start(0))?;
            let mut actual = Vec::new();
            Read::by_ref(&mut file)
                .take(196609)
                .read_to_end(&mut actual)?;
            require_plain_attributes(file.metadata()?.file_attributes())?;
            ensure!(
                actual == receipt,
                "registry lease durable intent readback differs"
            );
            actual.fill(0);
            self.receipt_id = Some(identity::object_id(&file)?);
            Ok(())
        })();
        combine(result, close_file(file))
    }
    fn read(&mut self) -> Result<Vec<u8>> {
        ensure!(
            !self.closed && valid(self.key),
            "registry policy key is closed"
        );
        let mut bytes = vec![0u8; 65536];
        let mut returned = 0;
        // SAFETY: one retained identity-checked key and the exact bounded descriptor output capacity.
        let status = unsafe {
            NtQuerySecurityObject(
                self.key,
                0x17,
                bytes.as_mut_ptr().cast(),
                65536,
                &mut returned,
            )
        };
        if status < 0 || !(20..=65536).contains(&returned) {
            bytes.fill(0);
            anyhow::bail!(
                "read fixed registry policy failed status={:08X}",
                status as u32
            );
        }
        bytes.truncate(returned as usize);
        descriptor_equal(&bytes, &bytes)?;
        Ok(bytes)
    }
    fn write_dacl(&mut self, descriptor: &[u8]) -> Result<()> {
        ensure!(
            !self.closed && valid(self.key),
            "registry policy key is closed"
        );
        descriptor_equal(descriptor, descriptor)?;
        // SAFETY: descriptor parser established its full owned span; information=4 changes DACL only.
        let status = unsafe { NtSetSecurityObject(self.key, 4, descriptor.as_ptr().cast()) };
        ensure!(
            status >= 0,
            "write fixed registry policy failed status={:08X}",
            status as u32
        );
        Ok(())
    }
    fn bind_supported(&mut self) -> Result<()> {
        ensure!(
            !self.closed
                && !self.supported
                && SUPPORTED_ACTIVE
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok(),
            "supported registry policy already active"
        );
        self.supported = true;
        Ok(())
    }
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let key = std::mem::replace(&mut self.key, null_mut());
        let mutex = std::mem::replace(&mut self.mutex, null_mut());
        if self.supported {
            SUPPORTED_ACTIVE.store(false, Ordering::SeqCst);
            self.supported = false;
        }
        let mut errors = Vec::new();
        if valid(key) {
            let status = unsafe { NtClose(key) };
            if status < 0 {
                errors.push(anyhow::anyhow!(
                    "registry key close failed status={:08X}",
                    status as u32
                ));
            }
        }
        if valid(mutex) {
            let status = unsafe { CloseHandle(mutex) };
            let code = if status == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if status == 0 {
                errors.push(anyhow::anyhow!(
                    "registry mutex close failed winerror={code}"
                ));
            }
        }
        if let Some(anchor) = self.anchor.take()
            && let Err(error) = close_file(anchor)
        {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::windows_security::activation::Failures { errors }.into())
        }
    }
    fn remove_receipt(&mut self, expected: &[u8]) -> Result<()> {
        plain_path(&self.state)?;
        ensure!(
            identity::path_object_id(&self.state)? == self.state_id,
            "registry recovery state identity changed"
        );
        let path = self.state.join(RECEIPT);
        plain_path(&path)?;
        let mut file = OpenOptions::new()
            .access_mode(0x110081)
            .share_mode(0)
            .custom_flags(0x00200000)
            .open(&path)?;
        let result = (|| {
            require_plain_attributes(file.metadata()?.file_attributes())?;
            ensure!(
                Some(identity::object_id(&file)?) == self.receipt_id,
                "registry lease receipt object was replaced"
            );
            let mut actual = Vec::new();
            Read::by_ref(&mut file)
                .take(196609)
                .read_to_end(&mut actual)?;
            ensure!(
                actual == expected,
                "registry lease receipt bytes were replaced"
            );
            actual.fill(0);
            let dispose = 1i32;
            // SAFETY: this exact receipt handle has DELETE access and no sharing;
            // identity and bytes were verified while it remained held. Disposition
            // deletes this object at close without a second path-based lookup.
            let status = unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    4,
                    (&dispose as *const i32).cast(),
                    4,
                )
            };
            let code = if status == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            ensure!(
                status != 0,
                "registry receipt disposition failed winerror={code}"
            );
            Ok(())
        })();
        combine(result, close_file(file))
    }
}
impl Drop for NativeIo {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Call only from the explicit disposable-host registry bootstrap, never an owned-fixture test.
pub struct MachineLease {
    lease: RegistryLease<NativeIo>,
    binding: String,
}
#[path = "registry_surface.rs"]
mod surface;
pub use surface::read_surface;
impl MachineLease {
    pub fn begin(owner: &NativeRunOwner) -> Result<Self> {
        let package = package_bytes(owner.view.package_sid())?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("registry lease nonce unavailable"))?;
        let nonce = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let io = NativeIo::new(owner)?;
        let lease = RegistryLease::begin(io, owner.run_id(), &package, &nonce)?;
        Ok(Self {
            lease,
            binding: owner.recovery_binding().into(),
        })
    }
    pub fn finish(&mut self, proof: &ReapedProcessTree) -> Result<()> {
        proof.require_binding(&self.binding)?;
        self.lease.finish(true)
    }
    pub fn defer(&mut self) -> Result<()> {
        RECOVERY_BLOCKED.store(true, Ordering::SeqCst);
        self.lease.defer()
    }
    pub fn bind_supported(&mut self) -> Result<()> {
        self.lease.bind_supported()
    }
    pub fn recover(owner: &NativeRunOwner, proof: &ReapedProcessTree) -> Result<()> {
        proof.require_binding(owner.recovery_binding())?;
        owner.view.require()?;
        ensure!(
            !RECOVERY_BLOCKED.load(Ordering::SeqCst),
            "registry policy recovery is explicitly deferred"
        );
        let path = owner.state_path().join(RECEIPT);
        plain_path(&path)?;
        if !path.try_exists()? {
            return Ok(());
        }
        let package = package_bytes(owner.view.package_sid())?;
        let mut io = NativeIo::new(owner)?;
        let receipt = match io.read_receipt() {
            Ok(bytes) => bytes,
            Err(primary) => return combine(Err(primary), io.close()),
        };
        RegistryLease::recover(io, owner.run_id(), &package, &receipt, true)
    }
}
