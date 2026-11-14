//! The same local MSFT_Disk classification used by Get-Disk, joined to the held disk.
use super::{CAPACITY, access, layout, number, query};
use crate::windows_security::{
    activation::diagnostics::{self, Numbers, Stage},
    scratch::raw_state::{self, Disk, Layout},
};
use anyhow::{Context, Result, ensure};
use windows::{
    Win32::System::{
        Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
        },
        Ioctl::{GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO},
        Variant::{VARIANT, VT_BSTR, VT_I4, VariantClear},
        Wmi::{
            CIM_UINT16, CIM_UINT32, CIM_UINT64, IEnumWbemClassObject, IWbemClassObject,
            IWbemLocator, WBEM_FLAG_CONNECT_USE_MAX_WAIT, WBEM_FLAG_FORWARD_ONLY,
            WBEM_FLAG_RETURN_IMMEDIATELY, WbemLocator,
        },
    },
    core::{BSTR, IUnknown, Interface, PCWSTR, w},
};

struct Apartment;
impl Apartment {
    fn new() -> Result<Self> {
        let status = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if !matches!(status.0, 0 | 1) {
            return Err(windows::core::Error::from_hresult(status).into());
        }
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}
fn blanket(object: &IUnknown) -> Result<()> {
    // Configure each actual proxy explicitly; do not change process-wide COM security.
    unsafe {
        CoSetProxyBlanket(
            object,
            10, // RPC_C_AUTHN_WINNT
            0,  // RPC_C_AUTHZ_NONE
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }?;
    Ok(())
}
#[derive(Clone, Copy)]
#[repr(u32)]
enum Property {
    Number = 1,
    Size = 2,
    Style = 3,
    Partitions = 4,
}
fn property(object: &IWbemClassObject, property: Property) -> Result<u64> {
    let (name, expected) = match property {
        Property::Number => (w!("Number"), CIM_UINT32),
        Property::Size => (w!("Size"), CIM_UINT64),
        Property::Style => (w!("PartitionStyle"), CIM_UINT16),
        Property::Partitions => (w!("NumberOfPartitions"), CIM_UINT32),
    };
    let mut value = VARIANT::default();
    let mut kind = 0;
    let result = (|| {
        unsafe { object.Get(name, 0, &mut value, Some(&mut kind), None) }
            .map_err(|error| diagnostics::operation(error.into(), Stage::ScratchRawLayout))?;
        let fields = unsafe { &value.Anonymous.Anonymous };
        let decoded = (|| {
            ensure!(
                kind == expected.0,
                "scratch provider CIM property type differs"
            );
            if matches!(property, Property::Size) {
                ensure!(
                    fields.vt == VT_BSTR,
                    "scratch provider capacity variant differs"
                );
                raw_state::unsigned(unsafe { &fields.Anonymous.bstrVal })
            } else {
                ensure!(
                    fields.vt == VT_I4,
                    "scratch provider integer variant differs"
                );
                let number = unsafe { fields.Anonymous.lVal } as u32;
                ensure!(
                    !matches!(property, Property::Style) || number <= u32::from(u16::MAX),
                    "scratch provider partition style exceeds type"
                );
                Ok(u64::from(number))
            }
        })();
        decoded.map_err(|error| {
            diagnostics::annotate(
                error,
                Stage::ScratchRawLayout,
                Numbers {
                    properties: Some(property as u32),
                    result: Some(kind as u32),
                    count: Some(u32::from(fields.vt.0)),
                    ..Default::default()
                },
            )
        })
    })();
    // Clear even a partially returned/invalid value, retaining both errors independently.
    access::combine(
        result,
        unsafe { VariantClear(&mut value) }
            .map_err(|error| diagnostics::operation(error.into(), Stage::ScratchRawLayout)),
    )
}
fn next(enumerator: &IEnumWbemClassObject, required: bool) -> Result<Option<IWbemClassObject>> {
    let mut objects = [None];
    let mut count = 0;
    let status = unsafe { enumerator.Next(10000, &mut objects, &mut count) };
    if (required && status.0 == 0 && count == 1 && objects[0].is_some())
        || (!required && status.0 == 1 && count == 0 && objects[0].is_none())
    {
        return Ok(objects[0].take());
    }
    let error = if status.is_err() {
        windows::core::Error::from_hresult(status).into()
    } else {
        anyhow::anyhow!("scratch provider result cardinality or bounded enumeration differs")
    };
    Err(diagnostics::annotate(
        error,
        Stage::ScratchRawLayout,
        Numbers {
            result: Some(status.0 as u32),
            count: Some(count),
            properties: Some(u32::from(required)),
            ..Default::default()
        },
    ))
}
fn provider(number: u32) -> Result<Disk> {
    let _apartment = Apartment::new()?;
    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }?;
    let empty = BSTR::new();
    let services = unsafe {
        locator.ConnectServer(
            &BSTR::from("ROOT\\Microsoft\\Windows\\Storage"),
            &empty,
            &empty,
            &empty,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
            &empty,
            None,
        )
    }?;
    blanket(&services.cast()?)?;
    let query = BSTR::from(format!(
        "SELECT Number, Size, PartitionStyle, NumberOfPartitions FROM MSFT_Disk WHERE Number = {number}"
    ));
    let enumerator = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }?;
    blanket(&enumerator.cast()?)?;
    let object = next(&enumerator, true)?.context("scratch provider disk result missing")?;
    let disk = Disk {
        number: u32::try_from(property(&object, Property::Number)?)?,
        bytes: property(&object, Property::Size)?,
        style: u16::try_from(property(&object, Property::Style)?)?,
        partitions: u32::try_from(property(&object, Property::Partitions)?)?,
    };
    ensure!(
        next(&enumerator, false)?.is_none(),
        "scratch provider disk result ambiguous"
    );
    Ok(disk)
    // All property variants and object/enumerator/service/locator refs release before COM.
}

pub(super) fn require(handle: super::super::Handle, expected: u32) -> Result<()> {
    let result = (|| {
        let provider = provider(expected)?;
        // Recheck the SAME held physical disk after the provider query, before any mutation.
        let actual = number(handle)?;
        let length: GET_LENGTH_INFORMATION = query(handle, IOCTL_DISK_GET_LENGTH_INFO)?;
        ensure!(
            actual.DeviceNumber == expected
                && actual.PartitionNumber == 0
                && length.Length == CAPACITY as i64,
            "scratch physical identity changed during provider query"
        );
        let (header, entries) = layout(handle)?;
        raw_state::require(
            provider,
            expected,
            CAPACITY,
            Layout {
                style: header.PartitionStyle,
                count: header.PartitionCount,
                entries: entries.len(),
            },
        )
        .map_err(|error| {
            diagnostics::annotate(
                error,
                Stage::ScratchRawLayout,
                Numbers {
                    result: Some(u32::from(provider.style)),
                    properties: Some(header.PartitionStyle),
                    count: Some(provider.partitions),
                    bytes: u32::try_from(provider.bytes).ok(),
                    ..Default::default()
                },
            )
        })
    })();
    result.map_err(|error| diagnostics::operation(error, Stage::ScratchRawLayout))
}
