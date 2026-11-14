//! GPT creation and exact virtual-disk/partition/volume association.
use super::scratch_access::{self as access, Owned, bytes, ioctl, query};
use crate::windows_security::activation::diagnostics::{self, Numbers, Stage};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    mem::{offset_of, size_of},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            DeleteVolumeMountPointW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
            GetLogicalDrives, GetVolumeNameForVolumeMountPointW, SetVolumeMountPointW,
        },
        System::Ioctl::*,
    },
    core::GUID,
};
#[path = "scratch_raw.rs"]
mod raw;

pub(super) const CAPACITY: u64 = 134217728;
const MIB: i64 = 1048576;
const BASIC: GUID = GUID::from_u128(0xebd0a0a2_b9e5_4433_87c0_68b6b72699c7);
const MSR: GUID = GUID::from_u128(0xe3c9e316_0b5c_4db8_817d_f92df00215ae);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VolumeBinding {
    pub disk: u32,
    pub partition: u32,
    pub offset: i64,
    pub length: i64,
    pub gpt: String,
    pub partition_id: String,
    pub volume: String,
}
pub(super) fn guid(text: &str) -> Result<GUID> {
    let value = GUID::try_from(text)?;
    ensure!(
        value != GUID::zeroed() && text == format!("{value:?}"),
        "scratch GUID is not canonical"
    );
    Ok(value)
}
pub(super) fn volume_name(text: &str) -> Result<()> {
    ensure!(
        text.len() == 49 && text.starts_with("\\\\?\\Volume{") && text.ends_with("}\\"),
        "scratch volume name shape differs"
    );
    GUID::try_from(&text[11..47])?;
    Ok(())
}
pub(super) fn drive_root(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() == 3 && (b'D'..=b'Z').contains(&bytes[0]) && &bytes[1..] == b":\\",
        "scratch drive root shape differs"
    );
    Ok(())
}
fn text(buffer: &[u16]) -> Result<String> {
    let end = buffer
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| anyhow::anyhow!("scratch volume name is unterminated"))?;
    ensure!(end > 0, "scratch volume name is empty");
    Ok(String::from_utf16(&buffer[..end])?)
}
pub(super) fn number(handle: super::Handle) -> Result<STORAGE_DEVICE_NUMBER> {
    let value: STORAGE_DEVICE_NUMBER = query(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER)?;
    ensure!(value.DeviceType == 7, "scratch storage device type differs");
    Ok(value)
}
pub(super) fn disk(path: &str) -> Result<(Owned, u32)> {
    let suffix = path
        .strip_prefix("\\\\.\\PhysicalDrive")
        .ok_or_else(|| anyhow::anyhow!("scratch physical device path differs"))?;
    ensure!(
        !suffix.is_empty() && suffix.len() <= 10 && suffix.bytes().all(|b| b.is_ascii_digit()),
        "scratch physical disk suffix differs"
    );
    let expected: u32 = suffix.parse()?;
    let handle = Owned::open(path, 0xc0000000, 3, 0)?;
    let actual = number(handle.0)?;
    let length: GET_LENGTH_INFORMATION = query(handle.0, IOCTL_DISK_GET_LENGTH_INFO)?;
    if actual.DeviceNumber != expected
        || actual.PartitionNumber != 0
        || length.Length != CAPACITY as i64
    {
        return Err(diagnostics::annotate(
            anyhow::anyhow!("scratch raw disk identity/capacity differs"),
            Stage::ScratchDiskIdentity,
            Numbers {
                result: Some(actual.DeviceNumber),
                properties: Some(actual.PartitionNumber),
                count: Some(expected),
                bytes: u32::try_from(length.Length).ok(),
                ..Default::default()
            },
        ));
    }
    Ok((handle, expected))
}
fn layout(
    handle: super::Handle,
) -> Result<(DRIVE_LAYOUT_INFORMATION_EX, Vec<PARTITION_INFORMATION_EX>)> {
    let mut aligned = vec![0u64; 4096];
    let buffer = unsafe {
        std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), aligned.len() * 8)
    };
    let returned = ioctl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], buffer)?;
    let offset = offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    ensure!(returned >= offset, "scratch disk layout header is short");
    let header =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<DRIVE_LAYOUT_INFORMATION_EX>()) };
    let count = header.PartitionCount as usize;
    ensure!(
        count <= 128 && offset + count * size_of::<PARTITION_INFORMATION_EX>() <= returned,
        "scratch disk partition extent differs"
    );
    let entries = (0..count)
        .map(|index| unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(offset + index * size_of::<PARTITION_INFORMATION_EX>())
                    .cast(),
            )
        })
        .collect();
    Ok((header, entries))
}
fn own_partition(
    handle: super::Handle,
    gpt: GUID,
    partition: GUID,
) -> Result<PARTITION_INFORMATION_EX> {
    let (header, entries) = layout(handle)?;
    ensure!(
        header.PartitionStyle == 1 && unsafe { header.Anonymous.Gpt }.DiskId == gpt,
        "scratch GPT identity differs"
    );
    let mut found = None;
    for entry in entries {
        if entry.PartitionStyle == PARTITION_STYLE_GPT
            && unsafe { entry.Anonymous.Gpt }.PartitionId == partition
        {
            ensure!(found.is_none(), "scratch partition GUID is ambiguous");
            found = Some(entry);
        }
    }
    let entry = found.ok_or_else(|| anyhow::anyhow!("scratch data partition is absent"))?;
    ensure!(
        entry.PartitionNumber > 0
            && entry.StartingOffset >= MIB
            && entry.PartitionLength > 0
            && entry
                .StartingOffset
                .checked_add(entry.PartitionLength)
                .is_some_and(|end| end <= CAPACITY as i64)
            && unsafe { entry.Anonymous.Gpt }.PartitionType == BASIC,
        "scratch data partition shape differs"
    );
    Ok(entry)
}
pub(super) fn require_disk_binding(handle: super::Handle, binding: &VolumeBinding) -> Result<()> {
    let entry = own_partition(handle, guid(&binding.gpt)?, guid(&binding.partition_id)?)?;
    ensure!(
        entry.PartitionNumber == binding.partition
            && entry.StartingOffset == binding.offset
            && entry.PartitionLength == binding.length,
        "scratch physical partition changed"
    );
    Ok(())
}
pub(super) fn initialize(
    handle: super::Handle,
    disk_number: u32,
    gpt: GUID,
    partition_id: GUID,
) -> Result<VolumeBinding> {
    raw::require(handle, disk_number)?;
    let create = CREATE_DISK {
        PartitionStyle: PARTITION_STYLE_GPT,
        Anonymous: CREATE_DISK_0 {
            Gpt: CREATE_DISK_GPT {
                DiskId: gpt,
                MaxPartitionCount: 128,
            },
        },
    };
    ioctl(handle, IOCTL_DISK_CREATE_DISK, bytes(&create), &mut [])?;
    ioctl(handle, IOCTL_DISK_UPDATE_PROPERTIES, &[], &mut [])?;
    // IOCTL_DISK_CREATE_DISK initializes an empty GPT on raw Win32 handles; accept
    // either an empty GPT (synthesizing MSR explicitly) or an OS-created single MSR.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut header, entries) = loop {
        let (header, entries) = layout(handle)?;
        if header.PartitionStyle == 1 && unsafe { header.Anonymous.Gpt }.DiskId == gpt {
            break (header, entries);
        }
        ensure!(
            Instant::now() < deadline,
            "scratch GPT header arrival exceeded deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let info = unsafe { header.Anonymous.Gpt };
    let end = info
        .StartingUsableOffset
        .checked_add(info.UsableLength)
        .ok_or_else(|| anyhow::anyhow!("scratch GPT capacity overflow"))?;
    let msr = if entries.is_empty() {
        let msr_start = info
            .StartingUsableOffset
            .max(MIB)
            .checked_add(MIB - 1)
            .ok_or_else(|| anyhow::anyhow!("scratch MSR alignment overflow"))?
            / MIB
            * MIB;
        let mut msr = PARTITION_INFORMATION_EX {
            PartitionStyle: PARTITION_STYLE_GPT,
            StartingOffset: msr_start,
            PartitionLength: 16 * MIB,
            PartitionNumber: 1,
            RewritePartition: true,
            ..Default::default()
        };
        msr.Anonymous.Gpt = PARTITION_INFORMATION_GPT {
            PartitionType: MSR,
            PartitionId: GUID::new()?,
            ..Default::default()
        };
        msr
    } else {
        let valid_msr = entries.len() == 1
            && entries[0].PartitionStyle == PARTITION_STYLE_GPT
            && unsafe { entries[0].Anonymous.Gpt }.PartitionType == MSR;
        ensure!(
            valid_msr,
            "new scratch GPT contains an unexpected partition"
        );
        entries[0]
    };
    let start = msr
        .StartingOffset
        .checked_add(msr.PartitionLength)
        .ok_or_else(|| anyhow::anyhow!("scratch MSR extent overflow"))?
        .max(info.StartingUsableOffset)
        .max(MIB);
    let start = start
        .checked_add(MIB - 1)
        .ok_or_else(|| anyhow::anyhow!("scratch partition alignment overflow"))?
        / MIB
        * MIB;
    let length = end / MIB * MIB - start;
    ensure!(
        length > 0 && end <= CAPACITY as i64,
        "scratch usable GPT capacity differs"
    );
    let mut entry = PARTITION_INFORMATION_EX {
        PartitionStyle: PARTITION_STYLE_GPT,
        StartingOffset: start,
        PartitionLength: length,
        PartitionNumber: msr
            .PartitionNumber
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("scratch partition number overflow"))?,
        RewritePartition: true,
        ..Default::default()
    };
    entry.Anonymous.Gpt = PARTITION_INFORMATION_GPT {
        PartitionType: BASIC,
        PartitionId: partition_id,
        ..Default::default()
    };
    header.PartitionCount = 2;
    let offset = offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    let size = offset + 2 * size_of::<PARTITION_INFORMATION_EX>();
    let mut aligned = vec![0u64; size.div_ceil(8)];
    let data = unsafe { std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), size) };
    data[..offset].copy_from_slice(&bytes(&header)[..offset]);
    data[offset..offset + size_of::<PARTITION_INFORMATION_EX>()].copy_from_slice(bytes(&msr));
    data[offset + size_of::<PARTITION_INFORMATION_EX>()..].copy_from_slice(bytes(&entry));
    ioctl(handle, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, data, &mut [])?;
    ioctl(handle, IOCTL_DISK_UPDATE_PROPERTIES, &[], &mut [])?;
    let actual = own_partition(handle, gpt, partition_id)?;
    ensure!(
        actual.StartingOffset == start && actual.PartitionLength == length,
        "scratch GPT data partition readback differs"
    );
    let volume = find_volume(disk_number, actual.PartitionNumber, partition_id)?;
    Ok(VolumeBinding {
        disk: disk_number,
        partition: actual.PartitionNumber,
        offset: start,
        length,
        gpt: format!("{gpt:?}"),
        partition_id: format!("{partition_id:?}"),
        volume,
    })
}
pub(super) fn volume(binding: &VolumeBinding) -> Result<Owned> {
    volume_name(&binding.volume)?;
    let handle = Owned::open(binding.volume.trim_end_matches('\\'), 0x20000, 3, 0)?;
    let actual = number(handle.0)?;
    let partition: PARTITION_INFORMATION_EX = query(handle.0, IOCTL_DISK_GET_PARTITION_INFO_EX)?;
    ensure!(
        actual.DeviceNumber == binding.disk
            && actual.PartitionNumber == binding.partition
            && partition.PartitionStyle == PARTITION_STYLE_GPT
            && partition.PartitionNumber == binding.partition
            && partition.StartingOffset == binding.offset
            && partition.PartitionLength == binding.length
            && unsafe { partition.Anonymous.Gpt }.PartitionId == guid(&binding.partition_id)?,
        "scratch volume/partition binding differs"
    );
    let extents: VOLUME_DISK_EXTENTS = query(handle.0, 0x560000)?;
    let extent = extents.Extents[0];
    ensure!(
        extents.NumberOfDiskExtents == 1
            && extent.DiskNumber == binding.disk
            && extent.StartingOffset == binding.offset
            && extent.ExtentLength == binding.length,
        "scratch volume disk extents differ"
    );
    Ok(handle)
}
struct VolumeSearch(Option<HANDLE>);
impl VolumeSearch {
    fn close(&mut self) -> Result<()> {
        self.0.take().map_or(Ok(()), |handle| {
            unsafe { FindVolumeClose(handle) }.map_err(Into::into)
        })
    }
}
impl Drop for VolumeSearch {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn find_volume(disk: u32, partition: u32, partition_id: GUID) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut buffer = [0u16; 512];
        let raw = unsafe { FindFirstVolumeW(&mut buffer) }?;
        let mut search = VolumeSearch(Some(raw));
        let scan = (|| {
            let mut found = None;
            for _ in 0..256 {
                let candidate = text(&buffer)?;
                volume_name(&candidate)?;
                if let Ok(mut handle) = Owned::open(candidate.trim_end_matches('\\'), 0, 3, 0) {
                    let result = (|| {
                        let number = number(handle.0)?;
                        if number.DeviceNumber == disk && number.PartitionNumber == partition {
                            let info: PARTITION_INFORMATION_EX =
                                query(handle.0, IOCTL_DISK_GET_PARTITION_INFO_EX)?;
                            ensure!(
                                info.PartitionStyle == PARTITION_STYLE_GPT
                                    && unsafe { info.Anonymous.Gpt }.PartitionId == partition_id,
                                "scratch volume partition GUID differs"
                            );
                            ensure!(found.is_none(), "scratch volume association is ambiguous");
                            found = Some(candidate);
                        }
                        Ok(())
                    })();
                    access::combine(result, handle.close())?;
                }
                match unsafe { FindNextVolumeW(raw, &mut buffer) } {
                    Ok(()) => {}
                    // A match is usable only after the complete ambiguity scan.
                    Err(error) if error.code().0 as u32 == 0x80070012 => return Ok(found),
                    Err(error) => return Err(error.into()),
                }
            }
            anyhow::bail!("scratch volume enumeration exceeded fixed budget")
        })();
        let found = access::combine(scan, search.close())?;
        if let Some(found) = found {
            return Ok(found);
        }
        ensure!(
            Instant::now() < deadline,
            "scratch volume arrival exceeded deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub(super) fn mounted(root: &str) -> Result<Option<String>> {
    drive_root(root)?;
    let root = super::authority::wide(root);
    let mut output = [0u16; 512];
    match unsafe {
        GetVolumeNameForVolumeMountPointW(windows::core::PCWSTR(root.as_ptr()), &mut output)
    } {
        Ok(()) => Ok(Some(text(&output)?)),
        Err(error) if matches!(error.code().0 as u32, 0x80070002 | 0x80070003 | 0x80070015) => {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}
pub(super) fn choose_drive() -> Result<String> {
    let mask = unsafe { GetLogicalDrives() };
    ensure!(mask != 0, "scratch drive enumeration failed");
    for letter in b'D'..=b'Z' {
        let root = format!("{}:\\", char::from(letter));
        if mask & (1 << (letter - b'A')) == 0 && mounted(&root)?.is_none() {
            return Ok(root);
        }
    }
    anyhow::bail!("no unused scratch drive root is available")
}
pub(super) fn mount(binding: &VolumeBinding, root: &str) -> Result<()> {
    drive_root(root)?;
    ensure!(
        mounted(root)?.is_none(),
        "scratch drive root is already assigned"
    );
    let mut handle = volume(binding)?;
    let result = (|| {
        let root = super::authority::wide(root);
        let target = super::authority::wide(&binding.volume);
        unsafe {
            SetVolumeMountPointW(
                windows::core::PCWSTR(root.as_ptr()),
                windows::core::PCWSTR(target.as_ptr()),
            )
        }?;
        Ok(())
    })();
    access::combine(result, handle.close())?;
    ensure!(
        mounted(root)?.as_deref() == Some(&binding.volume),
        "scratch mount readback differs"
    );
    Ok(())
}
pub(super) fn unmount(binding: &VolumeBinding, root: &str) -> Result<()> {
    if let Some(actual) = mounted(root)? {
        ensure!(
            actual == binding.volume,
            "scratch mount now refers to a foreign volume"
        );
        let mut handle = volume(binding)?;
        let text = super::authority::wide(root);
        let result = unsafe { DeleteVolumeMountPointW(windows::core::PCWSTR(text.as_ptr())) }
            .map_err(Into::into);
        access::combine(result, handle.close())?;
        ensure!(
            mounted(root)?.is_none(),
            "scratch mount removal readback differs"
        );
    }
    Ok(())
}

pub(super) fn format(binding: &VolumeBinding, state: &Path) -> Result<()> {
    let mut handle = volume(binding)?;
    handle.close()?;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut directory = [0u16; 512];
    let size = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), 512) } as usize;
    ensure!(size > 0 && size < 512, "system directory exceeds bound");
    let directory = PathBuf::from(String::from_utf16(&directory[..size])?);
    let tool = directory.join("format.com");
    crate::windows_security::plain_path(&tool)?;
    let mut pin = Owned::open(&tool, 0x80, 1, 0x200000)?;
    let id = access::identity(pin.0, false)?;
    let mut spec = crate::runtime::CommandSpec::new(&tool).args([
        binding.volume.trim_end_matches('\\'),
        "/FS:NTFS",
        "/Q",
        "/Y",
        "/X",
        "/V:RVYSCRATCH",
    ]);
    spec.cwd = Some(state.to_owned());
    spec.timeout = Duration::from_secs(60);
    spec.max_output = 65536;
    let result = (|| {
        let output = crate::runtime::run_with_input(&spec, b"Y\r\n")?;
        ensure!(
            output.code == 0,
            "fixed NTFS formatter failed exit={}",
            output.code
        );
        ensure!(
            access::identity(pin.0, false)? == id,
            "fixed formatter image identity changed"
        );
        let mut handle = volume(binding)?;
        handle.close()
    })();
    access::combine(result, pin.close())
}
