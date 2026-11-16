//! SID-bound NTFS hard-quota persistence; no localized account-name parsing.
use anyhow::{Result, ensure};
use windows::{
    Win32::{
        Security::PSID,
        Storage::FileSystem::{DISKQUOTA_USERNAME_RESOLVE_NONE, IDiskQuotaControl, IDiskQuotaUser},
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
    },
    core::{GUID, HRESULT, Interface, PCWSTR},
};
const LIMIT: i64 = 16777216;
fn exact(result: HRESULT, operation: &'static str) -> Result<()> {
    ensure!(
        result.0 == 0,
        "scratch quota {operation} failed hresult=0x{:08X}",
        result.0 as u32
    );
    Ok(())
}
struct Apartment;
impl Apartment {
    fn new() -> Result<Self> {
        let status = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        ensure!(
            matches!(status.0, 0 | 1),
            "scratch quota COM initialization failed hresult=0x{:08X}",
            status.0 as u32
        );
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}
pub(super) struct Quota {
    control: IDiskQuotaControl,
    _apartment: Apartment,
}
impl Quota {
    pub fn new(root: &str) -> Result<Self> {
        super::scratch_layout::drive_root(root)?;
        let apartment = Apartment::new()?;
        let class = GUID::from_u128(0x7988b571_ec89_11cf_9c00_00aa00a14f56);
        let control: IDiskQuotaControl =
            unsafe { CoCreateInstance(&class, None, CLSCTX_INPROC_SERVER) }?;
        let root = super::authority::wide(root);
        exact(
            unsafe {
                (control.vtable().Initialize)(control.as_raw(), PCWSTR(root.as_ptr()), true.into())
            },
            "initialize",
        )?;
        Ok(Self {
            control,
            _apartment: apartment,
        })
    }
    pub fn defaults(&self) -> Result<()> {
        let v = self.control.vtable();
        let raw = self.control.as_raw();
        exact(
            unsafe { (v.SetDefaultQuotaThreshold)(raw, LIMIT) },
            "set default threshold",
        )?;
        exact(
            unsafe { (v.SetDefaultQuotaLimit)(raw, LIMIT) },
            "set default limit",
        )?;
        let (mut threshold, mut limit) = (0, 0);
        exact(
            unsafe { (v.GetDefaultQuotaThreshold)(raw, &mut threshold) },
            "read default threshold",
        )?;
        exact(
            unsafe { (v.GetDefaultQuotaLimit)(raw, &mut limit) },
            "read default limit",
        )?;
        ensure!(
            threshold == LIMIT && limit == LIMIT,
            "scratch default quota bounds differ"
        );
        Ok(())
    }
    pub fn owner(&self, sid: &str) -> Result<()> {
        let mut bytes = crate::windows_security::scratch::sid(sid)?;
        let expected = bytes.clone();
        let mut output = std::ptr::null_mut();
        let raw = self.control.as_raw();
        exact(
            unsafe {
                (self.control.vtable().FindUserSid)(
                    raw,
                    PSID(bytes.as_mut_ptr().cast()),
                    DISKQUOTA_USERNAME_RESOLVE_NONE,
                    &mut output,
                )
            },
            "find SID",
        )?;
        ensure!(!output.is_null(), "scratch quota returned no SID record");
        let user = unsafe { IDiskQuotaUser::from_raw(output) };
        let v = user.vtable();
        let raw = user.as_raw();
        exact(
            unsafe { (v.SetQuotaThreshold)(raw, LIMIT, true.into()) },
            "persist SID threshold",
        )?;
        exact(
            unsafe { (v.SetQuotaLimit)(raw, LIMIT, true.into()) },
            "persist SID limit",
        )?;
        exact(unsafe { (v.Invalidate)(raw) }, "invalidate SID cache")?;
        let (mut threshold, mut limit, mut length) = (0, 0, 0);
        exact(
            unsafe { (v.GetQuotaThreshold)(raw, &mut threshold) },
            "read SID threshold",
        )?;
        exact(
            unsafe { (v.GetQuotaLimit)(raw, &mut limit) },
            "read SID limit",
        )?;
        exact(
            unsafe { (v.GetSidLength)(raw, &mut length) },
            "read SID length",
        )?;
        ensure!(
            length as usize == expected.len() && threshold == LIMIT && limit == LIMIT,
            "scratch SID quota identity/bounds differ"
        );
        bytes.fill(0);
        exact(
            unsafe { (v.GetSid)(raw, bytes.as_mut_ptr(), length) },
            "read SID",
        )?;
        ensure!(
            bytes == expected,
            "scratch quota record belongs to another SID"
        );
        Ok(())
    }
    pub fn enforce(&self) -> Result<()> {
        exact(
            unsafe { (self.control.vtable().SetQuotaState)(self.control.as_raw(), 2) },
            "enforce",
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let mut state = 0;
            exact(
                unsafe { (self.control.vtable().GetQuotaState)(self.control.as_raw(), &mut state) },
                "read enforcement",
            )?;
            ensure!(
                state & 3 == 2 && state & !0x303 == 0,
                "scratch quota enforcement mode differs"
            );
            if state & 0x300 == 0 {
                return Ok(());
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "scratch quota initialization exceeded deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    pub fn require(&self) -> Result<()> {
        let mut state = 0;
        exact(
            unsafe { (self.control.vtable().GetQuotaState)(self.control.as_raw(), &mut state) },
            "read readiness",
        )?;
        ensure!(state == 2, "scratch quota is not fully enforced");
        Ok(())
    }
}
