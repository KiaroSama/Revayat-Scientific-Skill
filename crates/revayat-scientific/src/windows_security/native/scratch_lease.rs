//! Exact volume-DACL mutation with a protected v5 receipt before possible writes.
use super::{
    Handle, WindowsJob,
    authority::{
        LeaseBinding, LeaseKind, NativeProfileBinding, RestoreAuthorization, SuspendedWorker,
    },
    scratch_access::{self as access, Owned},
    scratch_disk::{Created, Intent, Mount, Ready, ScratchVolume},
    scratch_layout,
};
use crate::windows_security::scratch::{
    self,
    policy::{VolumeReceipt, receipt_name},
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{os::windows::io::AsRawHandle, path::Path, ptr::null_mut};
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySecurityObject(
        handle: Handle,
        fields: u32,
        data: *mut std::ffi::c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtSetSecurityObject(handle: Handle, fields: u32, data: *const std::ffi::c_void) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn IsProcessInJob(process: Handle, job: Handle, inside: *mut i32) -> i32;
    fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
    fn QueryInformationJobObject(
        job: Handle,
        class: i32,
        data: Handle,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}
fn read(handle: Handle) -> Result<Vec<u8>> {
    let mut data = vec![0u8; 65536];
    let mut returned = 0;
    let status = unsafe {
        NtQuerySecurityObject(handle, 0x17, data.as_mut_ptr().cast(), 65536, &mut returned)
    };
    if status == 0x103 {
        std::process::abort();
    }
    ensure!(
        status == 0 && (20..=65536).contains(&returned),
        "scratch volume policy query failed ntstatus=0x{:08X}",
        status as u32
    );
    data.truncate(returned as usize);
    crate::windows_security::policy::descriptor_equal(&data, &data)?;
    Ok(data)
}
fn write(handle: Handle, data: &[u8]) -> Result<()> {
    ensure!(
        (20..=65536).contains(&data.len()),
        "scratch volume policy write exceeds bound"
    );
    let status = unsafe { NtSetSecurityObject(handle, 4, data.as_ptr().cast()) };
    if status == 0x103 {
        std::process::abort();
    }
    ensure!(
        status == 0,
        "scratch volume policy write failed ntstatus=0x{:08X}",
        status as u32
    );
    Ok(())
}
fn same(a: &[u8], b: &[u8]) -> Result<()> {
    ensure!(
        crate::windows_security::policy::descriptor_equal(a, b)?,
        "scratch volume policy differs"
    );
    Ok(())
}
fn suspended(job: &WindowsJob, process: Handle) -> Result<()> {
    let mut value: super::Accounting = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    let mut inside = 0;
    ensure!(
        !process.is_null()
            && !job.handle.is_null()
            && unsafe { IsProcessInJob(process, job.handle, &mut inside) } != 0
            && inside == 1
            && unsafe { WaitForSingleObject(process, 0) } == 258,
        "scratch lease process/job binding differs"
    );
    ensure!(
        unsafe {
            QueryInformationJobObject(
                job.handle,
                1,
                (&mut value as *mut super::Accounting).cast(),
                std::mem::size_of::<super::Accounting>() as u32,
                &mut returned,
            )
        } != 0
            && returned as usize == std::mem::size_of::<super::Accounting>()
            && value.active == 1
            && value.total == 1,
        "scratch lease requires the one owned suspended primary"
    );
    Ok(())
}
struct ReceiptPin {
    handle: Owned,
    identity: access::Identity,
    uncertain: bool,
}
impl ReceiptPin {
    fn open(state: &Path, host: &str, record: &str, expected: &[u8]) -> Result<Self> {
        let path = access::record_path(state, record)?;
        crate::windows_security::plain_path(&path)?;
        let mut handle = Owned::open(path, 0x80020080, 5, 0x200000)?;
        let result = (|| {
            access::require_private(handle.0, host)?;
            let id = access::identity(handle.0, false)?;
            ensure!(
                access::read_handle(handle.0)? == expected
                    && access::identity(handle.0, false)? == id,
                "scratch pinned receipt identity/bytes changed during read"
            );
            Ok(Self {
                handle: Owned(std::mem::replace(&mut handle.0, null_mut())),
                identity: id,
                uncertain: false,
            })
        })();
        access::combine(result, handle.close())
    }
    fn require(&self, state: &Path, host: &str, record: &str, expected: &[u8]) -> Result<()> {
        ensure!(
            !self.uncertain && !self.handle.0.is_null(),
            "scratch receipt pin is uncertain or closed"
        );
        access::require_private(self.handle.0, host)?;
        ensure!(
            access::identity(self.handle.0, false)? == self.identity
                && access::read_handle(self.handle.0)? == expected,
            "scratch pinned receipt identity/bytes changed"
        );
        let path = access::record_path(state, record)?;
        crate::windows_security::plain_path(&path)?;
        let mut current = Owned::open(path, 0x20080, 5, 0x200000)?;
        let result = (|| {
            access::require_private(current.0, host)?;
            ensure!(
                access::identity(current.0, false)? == self.identity,
                "scratch receipt pathname refers to a different object"
            );
            Ok(())
        })();
        access::combine(result, current.close())
    }
    fn retire(&mut self, state: &Path, host: &str, record: &str, expected: &[u8]) -> Result<()> {
        let result = (|| {
            self.require(state, host, record, expected)?;
            access::remove_record_identity(state, host, record, expected, Some(self.identity))
        })();
        access::combine(result, self.close())?;
        ensure!(
            !access::record_path(state, record)?.try_exists()?,
            "scratch receipt remained after bound retirement"
        );
        Ok(())
    }
    fn close(&mut self) -> Result<()> {
        if self.handle.0.is_null() {
            ensure!(!self.uncertain, "scratch receipt close remains uncertain");
            return Ok(());
        }
        let result = self.handle.close();
        self.uncertain |= result.is_err();
        result
    }
}
impl Drop for ReceiptPin {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Running supported lease. Suspended diagnostic comparisons have a separate lifetime.
pub(in crate::windows_security::native) struct VolumeLease<'profile> {
    profile: &'profile NativeProfileBinding<'profile>,
    state: std::path::PathBuf,
    intent: Intent,
    created: Created,
    ready: Ready,
    receipt: VolumeReceipt,
    bytes: Option<Vec<u8>>,
    pin: Option<ReceiptPin>,
    binding: Option<LeaseBinding>,
    resource: Option<String>,
    handle: Owned,
    image: Owned,
    root: Owned,
    virtual_disk: Owned,
    attempted: bool,
    possible: bool,
    closed: bool,
    uncertain: bool,
}
impl<'profile> VolumeLease<'profile> {
    pub(in crate::windows_security::native) fn begin(
        volume: &ScratchVolume,
        profile: &'profile NativeProfileBinding<'profile>,
        worker: &SuspendedWorker<'_>,
    ) -> Result<Self> {
        worker.require_profile(profile)?;
        profile.require()?;
        volume.require()?;
        ensure!(
            profile.view().run_id() == volume.intent.run
                && profile.view().package_sid() == volume.package_sid()
                && profile.view().state_identity() == volume.intent.state,
            "scratch lease profile/run binding differs"
        );
        let process = worker.process().as_raw_handle();
        suspended(worker.job(), process)?;
        ensure!(
            access::process_sid(process, 31)? == scratch::sid(volume.package_sid())?
                && access::process_sid(process, 1)? == scratch::sid(&volume.intent.host)?,
            "scratch lease child token binding differs"
        );
        no_conflicts(&volume.state, &volume.intent.host)?;
        let receipt = VolumeReceipt {
            run: volume.intent.run.clone(),
            package: volume.intent.package.clone(),
            supported: true,
            root: volume.drive_root().into(),
            disk: volume.ready.mount.binding.disk,
            partition: volume.ready.mount.binding.partition,
            image: scratch::FileIdentity {
                volume: volume.created.image.volume,
                high: volume.created.image.high,
                low: volume.created.image.low,
            },
            before: Vec::new(),
            after: Vec::new(),
        };
        let mut lease = Self {
            profile,
            state: volume.state.clone(),
            intent: volume.intent.clone(),
            created: volume.created.clone(),
            ready: volume.ready.clone(),
            receipt,
            bytes: None,
            pin: None,
            binding: None,
            resource: None,
            handle: Owned(null_mut()),
            image: Owned(null_mut()),
            root: Owned(null_mut()),
            virtual_disk: Owned(null_mut()),
            attempted: false,
            possible: false,
            closed: false,
            uncertain: false,
        };
        let result = (|| {
            lease.image = volume.image.duplicate()?;
            lease.root = volume.root.duplicate()?;
            lease.virtual_disk = volume.virtual_disk.duplicate()?;
            lease.handle = Owned::open(
                volume.ready.mount.binding.volume.trim_end_matches('\\'),
                0x60000,
                3,
                0,
            )?;
            lease.receipt.before = read(lease.handle.0)?;
            lease.receipt.after =
                scratch::policy::volume_trial(&lease.receipt.before, volume.package_sid())?;
            lease.require_objects()
        })();
        if let Err(primary) = result {
            return access::combine(Err(primary), lease.defer());
        }
        Ok(lease)
    }
    pub(in crate::windows_security::native) fn install(
        &mut self,
        worker: &SuspendedWorker<'_>,
    ) -> Result<()> {
        ensure!(
            !self.closed && !self.attempted && !self.possible,
            "scratch lease install already attempted"
        );
        worker.require_profile(self.profile)?;
        suspended(worker.job(), worker.process().as_raw_handle())?;
        self.require_objects()?;
        self.attempted = true;
        let bytes = self.receipt.encode()?.into_bytes();
        let record = receipt_name(true);
        access::write_record(&self.state, &self.intent.host, record, &bytes)?;
        self.bytes = Some(bytes);
        self.pin = Some(ReceiptPin::open(
            &self.state,
            &self.intent.host,
            record,
            self.bytes.as_ref().unwrap(),
        )?);
        let resource = self.resource_digest()?;
        // The factory saves the required FINAL quota epoch/plan and this exact durable resource.
        self.binding = Some(worker.reserve_lease(LeaseKind::Volume, &resource)?);
        self.resource = Some(resource);
        self.require_receipt()?;
        same(&read(self.handle.0)?, &self.receipt.before)?;
        self.possible = true;
        write(self.handle.0, &self.receipt.after)?;
        same(&read(self.handle.0)?, &self.receipt.after)
    }
    pub(in crate::windows_security::native) fn require_resume(
        &self,
        worker: &SuspendedWorker<'_>,
    ) -> Result<()> {
        worker.require_profile(self.profile)?;
        suspended(worker.job(), worker.process().as_raw_handle())?;
        ensure!(
            !self.closed && self.possible && self.binding.is_some(),
            "supported scratch lease is not ready"
        );
        self.require_objects()?;
        self.require_receipt()?;
        same(&read(self.handle.0)?, &self.receipt.after)
    }
    fn require_objects(&self) -> Result<()> {
        self.profile.require()?;
        ensure!(
            self.profile.view().run_id() == self.intent.run
                && self.profile.view().state_identity() == self.intent.state
                && self.profile.view().package_sid() == self.intent.package,
            "scratch lease held profile binding changed"
        );
        crate::windows_security::plain_path(&self.state.join("scratch.vhdx"))?;
        access::require_private(self.image.0, &self.intent.host)?;
        ensure!(
            access::identity(self.image.0, false)? == self.created.image,
            "scratch lease image object changed"
        );
        super::scratch_disk::require_virtual(self.virtual_disk.0, &self.intent)?;
        let path = super::scratch_disk::attached_path(self.virtual_disk.0)?
            .ok_or_else(|| anyhow::anyhow!("scratch lease volume is detached"))?;
        let (mut raw, number) = scratch_layout::disk(&path)?;
        let result = (|| {
            ensure!(
                number == self.ready.mount.binding.disk,
                "scratch lease physical disk changed"
            );
            scratch_layout::require_disk_binding(raw.0, &self.ready.mount.binding)?;
            let mut metadata = scratch_layout::volume(&self.ready.mount.binding)?;
            metadata.close()?;
            ensure!(
                scratch_layout::mounted(&self.ready.mount.root)?.as_deref()
                    == Some(&self.ready.mount.binding.volume)
                    && access::identity(self.root.0, true)? == self.ready.root_id
                    && access::name(self.root.0)? == self.ready.native_root,
                "scratch lease root/volume binding changed"
            );
            let (serial, total) = super::scratch_disk::filesystem(&self.ready.mount.root)?;
            ensure!(
                serial == self.ready.serial && total == self.ready.bytes,
                "scratch lease filesystem binding changed"
            );
            super::scratch_disk::require_root_seal(self.root.0, &self.intent)
        })();
        access::combine(result, raw.close())
    }
    fn resource_digest(&self) -> Result<String> {
        #[derive(serde::Serialize)]
        struct Resource<'a> {
            version: u8,
            kind: &'static str,
            intent: &'a Intent,
            image: &'a Created,
            ready: &'a Ready,
            receipt_name: &'static str,
            receipt_identity: access::Identity,
            receipt_sha256: String,
        }
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("scratch receipt pin is absent"))?;
        let bytes = self
            .bytes
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("scratch durable receipt bytes are absent"))?;
        let resource = Resource {
            version: 1,
            kind: "supported-volume",
            intent: &self.intent,
            image: &self.created,
            ready: &self.ready,
            receipt_name: receipt_name(true),
            receipt_identity: pin.identity,
            receipt_sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&resource)?)
        ))
    }
    fn require_receipt(&self) -> Result<()> {
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("scratch receipt pin is absent"))?;
        let bytes = self
            .bytes
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("scratch receipt bytes are absent"))?;
        pin.require(&self.state, &self.intent.host, receipt_name(true), bytes)?;
        ensure!(
            self.resource.as_deref() == Some(self.resource_digest()?.as_str()),
            "scratch lease resource digest changed"
        );
        Ok(())
    }
    pub(in crate::windows_security::native) fn restore_authorized(
        &mut self,
        volume: &mut ScratchVolume,
        auth: &RestoreAuthorization<'_>,
    ) -> Result<()> {
        ensure!(
            !self.closed && self.attempted && self.possible,
            "scratch lease is not pending restoration"
        );
        auth.require_profile(self.profile)?;
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("scratch lease reservation is absent"))?;
        auth.require_lease(binding)?;
        let bound = (|| {
            volume.require_identity()?;
            ensure!(
                serde_json::to_vec(&volume.intent)? == serde_json::to_vec(&self.intent)?
                    && serde_json::to_vec(&volume.created)? == serde_json::to_vec(&self.created)?
                    && serde_json::to_vec(&volume.ready)? == serde_json::to_vec(&self.ready)?,
                "scratch private retirement refers to a different volume"
            );
            Ok(())
        })();
        let identity_qualified = bound.is_ok();
        let result = (|| {
            bound?;
            self.require_objects()?;
            self.require_receipt()?;
            let current = read(self.handle.0)?;
            if !crate::windows_security::policy::descriptor_equal(&current, &self.receipt.before)? {
                same(&current, &self.receipt.after)?;
                write(self.handle.0, &self.receipt.before)?;
            }
            same(&read(self.handle.0)?, &self.receipt.before)
        })();
        let mut errors = result.err().into_iter().collect::<Vec<_>>();
        self.closed = true;
        self.close_handles(&mut errors);
        if identity_qualified
            && let Err(error) =
                volume.retire_private_authorized(self.profile, self.binding.as_ref().unwrap(), auth)
        {
            errors.push(error);
        }
        if errors.is_empty() {
            let bytes = self.bytes.as_deref().unwrap();
            if let Err(error) = self.pin.as_mut().unwrap().retire(
                &self.state,
                &self.intent.host,
                receipt_name(true),
                bytes,
            ) {
                errors.push(error);
            }
        } else if let Some(pin) = &mut self.pin
            && let Err(error) = pin.close()
        {
            errors.push(error);
        }
        self.uncertain |= !errors.is_empty();
        if !errors.is_empty() {
            return Err(crate::windows_security::activation::Failures { errors }.into());
        }
        // Discharge only after actual readback, retirement, absence and every independent close.
        let result = auth.complete_lease(self.binding.as_ref().unwrap());
        self.uncertain |= result.is_err();
        result
    }
    fn close_handles(&mut self, errors: &mut Vec<anyhow::Error>) {
        for result in [
            self.handle.close(),
            self.root.close(),
            self.image.close(),
            self.virtual_disk.close(),
        ] {
            if let Err(error) = result {
                errors.push(error);
            }
        }
    }
    /// A defer operation closes local handles but leaves the protected recovery receipt intact.
    pub(in crate::windows_security::native) fn defer(&mut self) -> Result<()> {
        if self.closed {
            ensure!(!self.uncertain, "scratch lease cleanup remains uncertain");
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        self.close_handles(&mut errors);
        if let Some(pin) = &mut self.pin
            && let Err(error) = pin.close()
        {
            errors.push(error);
        }
        self.uncertain |= !errors.is_empty();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::windows_security::activation::Failures { errors }.into())
        }
    }
}
impl Drop for VolumeLease<'_> {
    fn drop(&mut self) {
        let _ = self.defer();
    }
}
fn no_conflicts(state: &Path, host: &str) -> Result<()> {
    ensure!(
        !state.join("scratch-volume-policy.receipt").try_exists()?,
        "legacy scratch volume receipt is unsupported"
    );
    ensure!(
        access::read_record(state, host, receipt_name(false))?.is_none()
            && access::read_record(state, host, receipt_name(true))?.is_none(),
        "scratch volume already has a recovery receipt"
    );
    Ok(())
}
/// Only the sibling outer-recovery routine invokes this after validating ReapedProcessTree.
pub(super) fn recover(
    state: &Path,
    intent: &Intent,
    created: &Created,
    mount: &Mount,
) -> Result<()> {
    ensure!(
        !state.join("scratch-volume-policy.receipt").try_exists()?,
        "legacy scratch volume receipt is unsupported"
    );
    let diagnostic = access::read_record(state, &intent.host, receipt_name(false))?;
    let supported = access::read_record(state, &intent.host, receipt_name(true))?;
    ensure!(
        !(diagnostic.is_some() && supported.is_some()),
        "scratch recovery receipts conflict"
    );
    let Some((bytes, supported)) = diagnostic
        .map(|bytes| (bytes, false))
        .or_else(|| supported.map(|bytes| (bytes, true)))
    else {
        return Ok(());
    };
    let receipt = VolumeReceipt::decode(&bytes, &intent.run, &intent.package, supported)?;
    ensure!(
        receipt.root == mount.root
            && receipt.disk == mount.binding.disk
            && receipt.partition == mount.binding.partition
            && receipt.image
                == scratch::FileIdentity {
                    volume: created.image.volume,
                    high: created.image.high,
                    low: created.image.low
                },
        "scratch recovery receipt object binding differs"
    );
    let mut metadata = scratch_layout::volume(&mount.binding)?;
    metadata.close()?;
    let mut handle = Owned::open(mount.binding.volume.trim_end_matches('\\'), 0x60000, 3, 0)?;
    let result = (|| {
        let current = read(handle.0)?;
        if crate::windows_security::policy::descriptor_equal(&current, &receipt.before)? {
            return Ok(());
        }
        same(&current, &receipt.after)?;
        write(handle.0, &receipt.before)?;
        same(&read(handle.0)?, &receipt.before)
    })();
    access::combine(result, handle.close())?;
    access::remove_record(state, &intent.host, receipt_name(supported), &bytes)
}
