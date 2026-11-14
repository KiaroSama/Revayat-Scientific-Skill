//! One fixed, durable, outer-recovered scratch VHDX. Drop never authorizes detach.
use super::{
    NativeRunView,
    scratch_access::{self as access, Identity, Owned},
    scratch_layout::{self as layout, VolumeBinding},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    mem::size_of,
    path::{Path, PathBuf},
    ptr::null_mut,
};
use windows::{
    Win32::{Foundation::HANDLE, Security::PSECURITY_DESCRIPTOR, Storage::Vhd::*},
    core::{GUID, PCWSTR, PWSTR},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub version: u8,
    pub run: String,
    pub package: String,
    pub host: String,
    pub state: crate::identity::ObjectId,
    pub vhd: String,
    pub gpt: String,
    pub partition: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Created {
    pub image: Identity,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Mount {
    pub binding: VolumeBinding,
    pub root: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ready {
    pub mount: Mount,
    pub root_id: Identity,
    pub native_root: String,
    pub serial: u32,
    pub bytes: u64,
}
pub struct ScratchVolume {
    pub(super) state: PathBuf,
    pub(super) intent: Intent,
    pub(super) created: Created,
    pub(super) ready: Ready,
    pub(super) virtual_disk: Owned,
    pub(super) image: Owned,
    pub(super) raw: Owned,
    pub(super) root: Owned,
    state_pin: Owned,
    pub(super) private: Option<super::scratch_private::PrivateCreator>,
    closed: bool,
    uncertain: bool,
}
fn storage() -> VIRTUAL_STORAGE_TYPE {
    VIRTUAL_STORAGE_TYPE {
        DeviceId: 3,
        VendorId: GUID::from_u128(0xec984aec_a0f9_47e9_901f_71415a66345b),
    }
}
pub(super) fn require_virtual(handle: super::Handle, intent: &Intent) -> Result<()> {
    for version in [
        GET_VIRTUAL_DISK_INFO_SIZE,
        GET_VIRTUAL_DISK_INFO_IDENTIFIER,
        GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE,
        GET_VIRTUAL_DISK_INFO_VIRTUAL_STORAGE_TYPE,
    ] {
        let mut info = GET_VIRTUAL_DISK_INFO {
            Version: version,
            ..Default::default()
        };
        let mut size = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
        let mut used = 0;
        let status = unsafe {
            GetVirtualDiskInformation(HANDLE(handle), &mut size, &mut info, Some(&mut used))
        };
        ensure!(
            status.0 == 0 && used >= 4 && used <= size_of::<GET_VIRTUAL_DISK_INFO>() as u32,
            "scratch virtual disk information failed winerror={}",
            status.0
        );
        let valid = unsafe {
            if version == GET_VIRTUAL_DISK_INFO_SIZE {
                info.Anonymous.Size.VirtualSize == layout::CAPACITY
            } else if version == GET_VIRTUAL_DISK_INFO_IDENTIFIER {
                info.Anonymous.Identifier == layout::guid(&intent.vhd)?
            } else if version == GET_VIRTUAL_DISK_INFO_PROVIDER_SUBTYPE {
                info.Anonymous.ProviderSubtype == 2
            } else {
                info.Anonymous.VirtualStorageType.DeviceId == 3
                    && info.Anonymous.VirtualStorageType.VendorId == storage().VendorId
            }
        };
        ensure!(valid, "scratch VHDX identity/type/fixed capacity differs");
    }
    Ok(())
}
pub(super) fn attached_path(handle: super::Handle) -> Result<Option<String>> {
    let mut info = GET_VIRTUAL_DISK_INFO {
        Version: GET_VIRTUAL_DISK_INFO_IS_LOADED,
        ..Default::default()
    };
    let mut size = size_of::<GET_VIRTUAL_DISK_INFO>() as u32;
    let status = unsafe { GetVirtualDiskInformation(HANDLE(handle), &mut size, &mut info, None) };
    ensure!(
        status.0 == 0,
        "scratch attachment state query failed winerror={}",
        status.0
    );
    if !unsafe { info.Anonymous.IsLoaded }.as_bool() {
        return Ok(None);
    }
    let mut output = [0u16; 512];
    let mut size = (output.len() * 2) as u32;
    let status = unsafe {
        GetVirtualDiskPhysicalPath(HANDLE(handle), &mut size, PWSTR(output.as_mut_ptr()))
    };
    ensure!(
        status.0 == 0 && size <= 1024,
        "scratch physical path query failed winerror={}",
        status.0
    );
    let end = output
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| anyhow::anyhow!("scratch physical path is unterminated"))?;
    Ok(Some(String::from_utf16(&output[..end])?))
}
pub(super) fn open_virtual(path: &Path, intent: &Intent) -> Result<Owned> {
    crate::windows_security::plain_path(path)?;
    let path = super::authority::wide(path);
    let parameters = OPEN_VIRTUAL_DISK_PARAMETERS {
        Version: OPEN_VIRTUAL_DISK_VERSION_2,
        Anonymous: OPEN_VIRTUAL_DISK_PARAMETERS_0 {
            Version2: OPEN_VIRTUAL_DISK_PARAMETERS_0_1 {
                GetInfoOnly: false.into(),
                ReadOnly: false.into(),
                ResiliencyGuid: GUID::zeroed(),
            },
        },
    };
    let mut handle = HANDLE::default();
    let status = unsafe {
        OpenVirtualDisk(
            &storage(),
            PCWSTR(path.as_ptr()),
            VIRTUAL_DISK_ACCESS_NONE,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            Some(&parameters),
            &mut handle,
        )
    };
    ensure!(
        status.0 == 0,
        "open owned scratch VHDX failed winerror={}",
        status.0
    );
    let mut handle = Owned::checked(handle.0)?;
    let result = require_virtual(handle.0, intent);
    if let Err(primary) = result {
        return access::combine(Err(primary), handle.close());
    }
    Ok(handle)
}
pub(super) fn require_image(
    path: &Path,
    held: super::Handle,
    id: Identity,
    host: &str,
) -> Result<()> {
    crate::windows_security::plain_path(path)?;
    access::require_private(held, host)?;
    ensure!(
        access::identity(held, false)? == id,
        "scratch held image identity changed"
    );
    let mut current = Owned::open(path, 0x20080, 3, 0x200000)
        .context("scratch_image phase=path-bind desired=0x00020080 share=0x00000003")?;
    let result = (|| {
        access::require_private(current.0, host)?;
        ensure!(
            access::identity(current.0, false)? == id,
            "scratch image pathname identity changed"
        );
        Ok(())
    })();
    access::combine(result, current.close())
}
impl ScratchVolume {
    pub fn prepare(view: &NativeRunView) -> Result<Self> {
        let mut privilege = access::ManageVolume::acquire()?;
        let result = Self::prepare_inner(view);
        access::combine(result, privilege.close())
    }
    fn prepare_inner(view: &NativeRunView) -> Result<Self> {
        view.require()?;
        let host = crate::windows_security::sxs::current_user_sid()?;
        let intent = Intent {
            version: 1,
            run: view.run_id().into(),
            package: view.package_sid().into(),
            host: host.clone(),
            state: view.state_identity(),
            vhd: format!("{:?}", GUID::new()?),
            gpt: format!("{:?}", GUID::new()?),
            partition: format!("{:?}", GUID::new()?),
        };
        let state = view.state_path().to_owned();
        let mut state_pin = Owned::open(&state, 0x80, 3, 0x2200000)
            .context("scratch_prepare phase=state-pin desired=0x00000080 share=0x00000003")?;
        ensure!(
            access::object_id(state_pin.0)? == intent.state,
            "scratch state pin belongs to a different run"
        );
        let image_path = state.join("scratch.vhdx");
        ensure!(!image_path.try_exists()?, "scratch image already exists");
        // Expected VHD/GPT identities are flushed before the first file/device side effect.
        access::write_json(&state, &host, "scratch-disk.intent", &intent)?;
        view.require()?;
        let path = super::authority::wide(&image_path);
        let mut descriptor = super::authority::Descriptor::new(&access::private_sddl(&host))?;
        let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                    UniqueId: layout::guid(&intent.vhd)?,
                    MaximumSize: layout::CAPACITY,
                    ..Default::default()
                },
            },
        };
        let mut handle = HANDLE::default();
        let status = unsafe {
            CreateVirtualDisk(
                &storage(),
                PCWSTR(path.as_ptr()),
                VIRTUAL_DISK_ACCESS_NONE,
                Some(PSECURITY_DESCRIPTOR(descriptor.0)),
                CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION,
                0,
                &parameters,
                None,
                &mut handle,
            )
        };
        let created = if status.0 == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "create fixed scratch VHDX failed winerror={}",
                status.0
            ))
        };
        let descriptor_cleanup = descriptor.close();
        let mut virtual_disk = if handle.is_invalid() {
            Owned(null_mut())
        } else {
            Owned(handle.0)
        };
        if let Err(primary) = access::combine(created, descriptor_cleanup) {
            return access::combine(Err(primary), virtual_disk.close());
        }
        let result = (|| {
            // Frozen New-VHD completes and closes its creation provider before Capture opens
            // the no-delete metadata pin. An attachment provider is a distinct bound reopen.
            let qualified = require_virtual(virtual_disk.0, &intent)
                .context("scratch_prepare phase=creation-provider-identity");
            access::combine(
                qualified,
                virtual_disk
                    .close()
                    .context("scratch_prepare phase=creation-provider-close"),
            )?;
            let mut image = Owned::open(&image_path, 0x20080, 3, 0x200000)
                .context("scratch_prepare phase=image-pin desired=0x00020080 share=0x00000003 creation_provider_closed=True")?;
            let result = (|| {
                access::require_private(image.0, &host)?;
                let created = Created {
                    image: access::identity(image.0, false)?,
                };
                access::write_json(&state, &host, "scratch-disk.created", &created)?;
                virtual_disk = open_virtual(&image_path, &intent)
                    .context("scratch_prepare phase=attachment-provider-open metadata_pin=True")?;
                require_image(&image_path, image.0, created.image, &host)?;
                access::write_record(&state, &host, "scratch-disk.attach-intent", b"attach\n")?;
                let parameters = ATTACH_VIRTUAL_DISK_PARAMETERS {
                    Version: ATTACH_VIRTUAL_DISK_VERSION_1,
                    ..Default::default()
                };
                let status = unsafe {
                    AttachVirtualDisk(
                        HANDLE(virtual_disk.0),
                        None,
                        ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER
                            | ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME,
                        0,
                        Some(&parameters),
                        None,
                    )
                };
                ensure!(
                    status.0 == 0,
                    "attach owned scratch VHDX failed winerror={}",
                    status.0
                );
                require_virtual(virtual_disk.0, &intent)
                    .context("scratch_prepare phase=attached-provider-identity")?;
                require_image(&image_path, image.0, created.image, &host)?;
                let path = attached_path(virtual_disk.0)?
                    .ok_or_else(|| anyhow::anyhow!("scratch VHDX did not attach"))?;
                let (mut raw, number) = layout::disk(&path)?;
                let result = (|| {
                    access::write_record(&state, &host, "scratch-disk.layout-intent", b"gpt\n")?;
                    let binding = layout::initialize(
                        raw.0,
                        number,
                        layout::guid(&intent.gpt)?,
                        layout::guid(&intent.partition)?,
                    )?;
                    access::write_json(&state, &host, "scratch-disk.volume", &binding)?;
                    layout::format(&binding, &state)?;
                    let root = layout::choose_drive()?;
                    let mount = Mount { binding, root };
                    access::write_json(&state, &host, "scratch-disk.mount-intent", &mount)?;
                    layout::mount(&mount.binding, &mount.root)?;
                    let mut root = Owned::open(&mount.root, 0x20080, 3, 0x2200000)
                        .context("scratch_prepare phase=mounted-root-pin desired=0x00020080 share=0x00000003")?;
                    let result = (|| {
                        let root_id = access::identity(root.0, true)?;
                        let native_root = access::name(root.0)?;
                        ensure!(
                            crate::windows_security::scratch::private::native_root(&native_root),
                            "scratch NT root shape differs"
                        );
                        filesystem(&mount.root)?;
                        let quota = super::scratch_quota::Quota::new(&mount.root)?;
                        quota.defaults()?;
                        quota.owner(&host)?;
                        quota.owner(view.package_sid())?;
                        quota.enforce()?;
                        drop(quota);
                        let (serial, bytes) = filesystem(&mount.root)?;
                        let private = super::scratch_private::PrivateCreator::prepare(
                            &mount.root,
                            &host,
                            view.package_sid(),
                        )?;
                        let ready = Ready {
                            mount,
                            root_id,
                            native_root,
                            serial,
                            bytes,
                        };
                        let mut volume = Self {
                            state: state.clone(),
                            intent: intent.clone(),
                            created,
                            ready,
                            virtual_disk: Owned(std::mem::replace(&mut virtual_disk.0, null_mut())),
                            image: Owned(std::mem::replace(&mut image.0, null_mut())),
                            raw: Owned(std::mem::replace(&mut raw.0, null_mut())),
                            root: Owned(std::mem::replace(&mut root.0, null_mut())),
                            private: Some(private),
                            state_pin: Owned(std::mem::replace(&mut state_pin.0, null_mut())),
                            closed: false,
                            uncertain: false,
                        };
                        let result = (|| {
                            volume.seal()?;
                            volume.private.as_mut().unwrap().seal()?;
                            volume.prepare_folders()?;
                            access::write_json(&state, &host, "scratch-disk.ready", &volume.ready)?;
                            volume.require()?;
                            Ok(())
                        })();
                        if let Err(primary) = result {
                            return access::combine(Err(primary), volume.close());
                        }
                        Ok(volume)
                    })();
                    access::combine(result, root.close())
                })();
                access::combine(result, raw.close())
            })();
            access::combine(result, image.close())
        })();
        access::combine(result, virtual_disk.close())
    }
    pub fn drive_root(&self) -> &str {
        &self.ready.mount.root
    }
    pub fn native_root(&self) -> &str {
        &self.ready.native_root
    }
    pub fn package_sid(&self) -> &str {
        &self.intent.package
    }
    pub fn identity_binding(&self) -> String {
        format!(
            "{}:{:016X}:{:016X}:{:016X}:{}:{}:{}",
            self.intent.run,
            self.created.image.volume,
            self.created.image.high,
            self.created.image.low,
            self.ready.mount.binding.volume,
            self.ready.mount.binding.disk,
            self.ready.mount.binding.partition
        )
    }
    pub fn require(&self) -> Result<()> {
        self.require_identity()?;
        self.require_seal()
    }
    pub(in crate::windows_security::native) fn require_identity(&self) -> Result<()> {
        ensure!(!self.closed, "scratch volume is closed");
        ensure!(
            access::object_id(self.state_pin.0)? == self.intent.state
                && crate::identity::path_object_id(&self.state)? == self.intent.state,
            "scratch state directory binding changed"
        );
        crate::windows_security::plain_path(&self.state.join("scratch.vhdx"))?;
        access::require_private(self.image.0, &self.intent.host)?;
        ensure!(
            access::identity(self.image.0, false)? == self.created.image,
            "scratch VHDX image identity changed"
        );
        require_virtual(self.virtual_disk.0, &self.intent)?;
        let path = attached_path(self.virtual_disk.0)?
            .ok_or_else(|| anyhow::anyhow!("scratch VHDX is detached"))?;
        let (mut disk, number) = layout::disk(&path)?;
        let result = (|| {
            ensure!(
                number == self.ready.mount.binding.disk,
                "scratch physical disk changed"
            );
            layout::require_disk_binding(disk.0, &self.ready.mount.binding)?;
            let mut volume = layout::volume(&self.ready.mount.binding)?;
            volume.close()?;
            ensure!(
                layout::mounted(self.drive_root())?.as_deref()
                    == Some(&self.ready.mount.binding.volume)
                    && access::identity(self.root.0, true)? == self.ready.root_id
                    && access::name(self.root.0)? == self.ready.native_root,
                "scratch drive/root identity changed"
            );
            let (serial, bytes) = filesystem(self.drive_root())?;
            ensure!(
                serial == self.ready.serial && bytes == self.ready.bytes,
                "scratch NTFS volume identity/capacity changed"
            );
            Ok(())
        })();
        access::combine(result, disk.close())
    }
    pub(in crate::windows_security::native) fn private_use(
        &mut self,
        worker: &super::authority::SuspendedWorker<'_>,
        profile: &super::authority::NativeProfileBinding<'_>,
    ) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        worker.require_profile(profile)?;
        self.require()?;
        ensure!(
            profile.view().state_identity() == self.intent.state
                && profile.view().run_id() == self.intent.run
                && profile.view().package_sid() == self.intent.package,
            "private creator profile/volume binding differs"
        );
        self.private
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("private creator fixture is unavailable"))?
            .use_suspended(worker.process().as_raw_handle())
    }
    pub(super) fn retire_private_authorized(
        &mut self,
        profile: &super::authority::NativeProfileBinding<'_>,
        binding: &super::authority::LeaseBinding,
        auth: &super::authority::RestoreAuthorization<'_>,
    ) -> Result<()> {
        auth.require_profile(profile)?;
        auth.require_lease(binding)?;
        self.require_identity()?;
        ensure!(
            profile.view().state_identity() == self.intent.state
                && profile.view().run_id() == self.intent.run
                && profile.view().package_sid() == self.intent.package,
            "private creator retirement profile/volume differs"
        );
        let private = self
            .private
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("private creator fixture is unavailable"))?;
        private.end_observation(true);
        private.remove_before_admission()
    }
    pub fn quota_owner(&mut self, sid: &str) -> Result<()> {
        self.require()?;
        let quota = super::scratch_quota::Quota::new(self.drive_root())?;
        quota.owner(sid)?;
        quota.require()?;
        drop(quota);
        self.require()
    }
    fn seal(&self) -> Result<()> {
        let root = Path::new(self.drive_root());
        access::set_security(root, "S:(ML;OICI;NW;;;LW)", 0x10)?;
        access::set_security(root, &root_policy(&self.intent), 0x80000005)?;
        self.require_seal()
    }
    fn require_seal(&self) -> Result<()> {
        require_root_seal(self.root.0, &self.intent)
    }
    fn prepare_folders(&self) -> Result<()> {
        for item in ["home", "home/cache", "temp", "junction-target"] {
            std::fs::create_dir(Path::new(self.drive_root()).join(item))?;
        }
        super::scratch_private::prepare_junction(self.drive_root())
    }
    /// Closes only process-local handles. The permanent attachment is outer-recovery owned.
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            ensure!(!self.uncertain, "scratch handle cleanup remains uncertain");
            return Ok(());
        }
        self.closed = true;
        let mut errors = Vec::new();
        if let Some(mut private) = self.private.take()
            && let Err(error) = private.release()
        {
            errors.push(error);
        }
        for result in [
            self.root.close(),
            self.raw.close(),
            self.image.close(),
            self.virtual_disk.close(),
            self.state_pin.close(),
        ] {
            if let Err(error) = result {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            self.uncertain = true;
            Err(crate::windows_security::activation::Failures { errors }.into())
        }
    }
}
impl Drop for ScratchVolume {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
pub(super) fn filesystem(root: &str) -> Result<(u32, u64)> {
    use windows::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetVolumeInformationW};
    let root = super::authority::wide(root);
    let (mut serial, mut flags, mut total) = (0, 0, 0);
    let mut fs = [0u16; 32];
    unsafe {
        GetVolumeInformationW(
            PCWSTR(root.as_ptr()),
            None,
            Some(&mut serial),
            None,
            Some(&mut flags),
            Some(&mut fs),
        )
    }?;
    ensure!(
        fs[..5] == [78, 84, 70, 83, 0] && flags & 0x68 == 0x68,
        "scratch filesystem is not NTFS with persistent ACL/quota/sparse support"
    );
    unsafe { GetDiskFreeSpaceExW(PCWSTR(root.as_ptr()), None, Some(&mut total), None) }?;
    ensure!(
        total > 0 && total <= layout::CAPACITY,
        "scratch filesystem capacity exceeds fixed bound"
    );
    Ok((serial, total))
}

fn root_policy(intent: &Intent) -> String {
    format!(
        "O:{}D:P(D;OICI;0x000C0000;;;{})(D;OICI;0x000C0000;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{})(A;OICI;0x001301BF;;;{})S:(ML;OICI;NW;;;LW)",
        intent.host, intent.package, intent.host, intent.package
    )
}

pub(super) fn require_root_seal(root: super::Handle, intent: &Intent) -> Result<()> {
    let actual = access::security(root, 0x17)?;
    let mut expected = super::authority::Descriptor::new(&root_policy(intent))?;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityDescriptorLength(value: super::Handle) -> u32;
    }
    let result = (|| {
        let size = unsafe { GetSecurityDescriptorLength(expected.0) } as usize;
        ensure!(
            (20..=65536).contains(&size),
            "scratch root descriptor bound differs"
        );
        let expected = unsafe { std::slice::from_raw_parts(expected.0.cast::<u8>(), size) };
        let actual = crate::windows_security::policy::Descriptor::parse(&actual)?;
        let expected = crate::windows_security::policy::Descriptor::parse(expected)?;
        ensure!(
            actual.owner == expected.owner
                && actual.group.is_some()
                && actual.control & 0x1004 == 0x1004
                && actual.dacl == expected.dacl
                && actual.sacl == expected.sacl,
            "scratch writable root policy differs"
        );
        Ok(())
    })();
    access::combine(result, expected.close())
}
