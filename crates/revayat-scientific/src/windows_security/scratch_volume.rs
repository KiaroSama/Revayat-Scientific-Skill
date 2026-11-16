//! Nine fixed handle-only volume requests and bounded, returned-span metadata qualification.
use super::{OperationResult, SharedError, access::NativeRequest, attempt, failure, finish};
use anyhow::{Result, ensure};
use std::{error::Error, fmt, sync::Arc};

pub const MASKS: [u32; 9] = crate::windows_security::policy::SCRATCH_MASKS;
pub const DENIED: i32 = 0xc0000022u32 as i32;
pub fn bare(root: &str) -> Result<&str> {
    ensure!(
        super::private::native_root(root),
        "invalid fixed scratch native volume root"
    );
    root.strip_suffix('\\')
        .ok_or_else(|| anyhow::anyhow!("scratch native volume terminator absent"))
}
pub fn requests(root: &str) -> Result<Vec<NativeRequest>> {
    let path = bare(root)?;
    Ok(MASKS
        .iter()
        .map(|mask| {
            let mut request = NativeRequest::new(path, "lpac", "volume");
            request.target = "volume".into();
            request.requested = *mask;
            request.options = 0x200000;
            request
        })
        .collect())
}
pub fn status_allowed(mask: u32, host: bool, status: i32) -> bool {
    if mask == 0 {
        status == DENIED
    } else {
        status == 0 || !host && status == DENIED
    }
}
pub fn census(requests: &[NativeRequest]) -> String {
    requests
        .iter()
        .map(|request| {
            if request.output.is_some()
                && !request.pending
                && request.opened == (request.returned == 0)
                && matches!(request.returned, 0 | DENIED)
            {
                format!("{:08X}", request.returned as u32)
            } else {
                "unknown".into()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub host: bool,
    pub requested: u32,
    pub status: i32,
    pub io_status: i32,
    pub information: u64,
    pub stage: u32,
    pub query_kind: i32,
    pub query_status: i32,
    pub returned: u32,
    pub attributes: u32,
    pub granted: u32,
    pub queried: bool,
    pub basic_known: bool,
    pub name_equal: i32,
    pub(super) census: Option<String>,
}
impl Evidence {
    pub fn new(request: &NativeRequest, host: bool) -> Self {
        Self {
            host,
            requested: request.requested,
            status: request.returned,
            io_status: request.io_status,
            information: request.information,
            stage: 1,
            query_kind: -1,
            query_status: 0,
            returned: 0,
            attributes: 0,
            granted: 0,
            queried: false,
            basic_known: false,
            name_equal: -1,
            census: None,
        }
    }
    fn require(&self, value: bool) -> OperationResult<()> {
        if value {
            Ok(())
        } else {
            Err(Arc::new(self.clone()))
        }
    }
}
impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed scratch volume handle evidence is unqualified stage={} host={} desired=0x{:08X} ntstatus=0x{:08X} io_status=0x{:08X} information=0x{:016X} query_kind={} queried={} query_status=0x{:08X} returned={} basic_known={} attributes=0x{:08X} granted=0x{:08X} name_equal={}",
            self.stage,
            super::truth(self.host),
            self.requested,
            self.status as u32,
            self.io_status as u32,
            self.information,
            self.query_kind,
            super::truth(self.queried),
            self.query_status as u32,
            self.returned,
            super::truth(self.basic_known),
            self.attributes,
            self.granted,
            self.name_equal
        )?;
        if let Some(census) = &self.census {
            write!(f, " open_statuses={census}")?;
        }
        Ok(())
    }
}
impl Error for Evidence {}

pub fn granted(data: &[u8], returned: usize) -> Result<u32> {
    ensure!(
        returned == 56 && returned <= data.len(),
        "invalid scratch object basic returned span"
    );
    ensure!(
        u32::from_le_bytes(data[..4].try_into()?) == 0,
        "scratch object attributes differ"
    );
    Ok(u32::from_le_bytes(data[4..8].try_into()?))
}
pub fn object_name(data: &[u8], returned: usize) -> Result<String> {
    ensure!(
        (16..=1024).contains(&returned) && returned <= data.len(),
        "invalid scratch object name returned span"
    );
    let length = u16::from_le_bytes(data[..2].try_into()?) as usize;
    let maximum = u16::from_le_bytes(data[2..4].try_into()?) as usize;
    let pointer = u64::from_le_bytes(data[8..16].try_into()?);
    let start = data.as_ptr() as u64;
    ensure!(
        length > 0
            && length <= 256
            && length.is_multiple_of(2)
            && maximum >= length
            && maximum.is_multiple_of(2)
            && pointer >= start + 16
            && pointer - start <= returned as u64
            && maximum as u64 <= returned as u64 - (pointer - start),
        "scratch object name pointer or extent differs"
    );
    let offset = (pointer - start) as usize;
    let units = data[offset..offset + length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    Ok(String::from_utf16(&units)?)
}
#[derive(Clone, Copy, Debug)]
pub struct QueryResult {
    pub status: i32,
    pub returned: u32,
}
pub type QueryCall<'a> =
    dyn FnMut(usize, u32, &mut [u8; 1024], u32) -> OperationResult<QueryResult> + 'a;

fn query(
    handle: usize,
    kind: u32,
    evidence: &mut Evidence,
    call: &mut QueryCall<'_>,
) -> OperationResult<Box<[u8; 1024]>> {
    let mut data = Box::new([0; 1024]);
    evidence.stage = if kind == 0 { 3 } else { 6 };
    evidence.query_kind = kind as i32;
    evidence.queried = false;
    let result = call(handle, kind, &mut data, if kind == 0 { 56 } else { 1024 })?;
    // NtQueryObject has no asynchronous owner here; never free possible pending output storage.
    if result.status == super::access::PENDING {
        std::process::abort();
    }
    evidence.queried = true;
    evidence.query_status = result.status;
    evidence.returned = result.returned;
    evidence.require(result.status == 0 && result.returned <= 1024)?;
    evidence.stage = if kind == 0 { 4 } else { 7 };
    Ok(data)
}
pub fn inspect(
    handle: usize,
    desired: u32,
    root: &str,
    mut deadline: impl FnMut() -> OperationResult<()>,
    evidence: &mut Evidence,
    call: &mut QueryCall<'_>,
) -> OperationResult<u32> {
    deadline()?;
    let data = query(handle, 0, evidence, call)?;
    evidence.require(evidence.returned == 56)?;
    evidence.attributes = u32::from_le_bytes(data[..4].try_into().unwrap());
    evidence.granted = u32::from_le_bytes(data[4..8].try_into().unwrap());
    evidence.basic_known = true;
    let granted = granted(data.as_ref(), evidence.returned as usize)
        .map_err(|_| Arc::new(evidence.clone()) as SharedError)?;
    deadline()?;
    evidence.stage = 5;
    evidence.require(granted == desired)?;
    let name = query(handle, 1, evidence, call)?;
    let name = object_name(name.as_ref(), evidence.returned as usize)
        .map_err(|_| Arc::new(evidence.clone()) as SharedError)?;
    evidence.stage = 8;
    let expected = bare(root).map_err(|_| failure("fixed scratch volume root is unqualified"))?;
    evidence.name_equal = i32::from(name == expected);
    evidence.require(evidence.name_equal == 1)?;
    deadline()?;
    Ok(granted)
}
pub fn release(
    requests: &mut [NativeRequest],
    errors: &mut Vec<SharedError>,
    mut close: impl FnMut(usize) -> OperationResult<()>,
) {
    for request in requests {
        attempt(errors, || request.release(|_| Ok(()), &mut close));
    }
}
pub fn qualify(
    requests: &mut [NativeRequest],
    root: &str,
    host: bool,
    mut inspect: impl FnMut(usize, u32, &mut Evidence) -> OperationResult<u32>,
    mut close: impl FnMut(usize) -> OperationResult<()>,
) -> OperationResult<Vec<i32>> {
    let mut values = vec![0; MASKS.len() * 5];
    let result = (|| {
        super::need(requests.len() == MASKS.len())?;
        let path =
            bare(root).map_err(|_| failure("fixed scratch native volume root is unqualified"))?;
        for (index, request) in requests.iter().enumerate() {
            let mut evidence = Evidence::new(request, host);
            evidence.census = Some(census(requests));
            evidence.require(
                request.path == path
                    && request.requested == MASKS[index]
                    && !request.pending
                    && request.output.is_some()
                    && request.opened == (request.returned == 0),
            )?;
            evidence.stage = 2;
            evidence.require(status_allowed(request.requested, host, request.returned))?;
            values[index] = request.returned;
            values[MASKS.len() * 2 + index] = request.io_status;
            values[MASKS.len() * 3 + index] = request.information as u32 as i32;
            values[MASKS.len() * 4 + index] = (request.information >> 32) as u32 as i32;
            if request.opened {
                let granted = inspect(
                    request.output.as_ref().unwrap().handle,
                    request.requested,
                    &mut evidence,
                )?;
                evidence.stage = 5;
                evidence.granted = granted;
                evidence.require(granted == request.requested)?;
                values[MASKS.len() + index] = granted as i32;
            }
        }
        Ok(())
    })();
    let mut errors = Vec::new();
    release(requests, &mut errors, &mut close);
    finish(result.map(|()| values), errors)
}
pub fn combine(root: i32, temp: i32, volume: &[i32]) -> Result<Vec<i32>> {
    ensure!(
        volume.len() == MASKS.len() * 5,
        "invalid scratch volume differential shape"
    );
    let mut values = vec![root, temp];
    values.extend(volume);
    Ok(values)
}
pub fn frame(phase: &str, index: usize, status: i32, granted: i32) -> Result<String> {
    ensure!(
        matches!(phase, "baseline" | "modified" | "restored")
            && index < MASKS.len()
            && status_allowed(MASKS[index], false, status)
            && if status == 0 {
                granted as u32 == MASKS[index]
            } else {
                granted == 0
            },
        "invalid scratch volume frame"
    );
    Ok(format!(
        "WINDOWS_SCRATCH_VOLUME phase={phase} desired=0x{:08X} ntstatus=0x{:08X} granted=0x{:08X} native_request_supported={} metadata_qualified={} descriptor_restored=True handles_closed=True authority_qualified=False admission=False",
        MASKS[index],
        status as u32,
        granted as u32,
        super::truth(MASKS[index] != 0),
        super::truth(MASKS[index] != 0)
    ))
}
pub fn frames(phase: &str, result: &[i32]) -> Result<Vec<String>> {
    ensure!(
        result.len() == 2 + MASKS.len() * 5,
        "invalid scratch volume frame vector"
    );
    (0..MASKS.len())
        .map(|index| {
            let information = u64::from(result[2 + MASKS.len() * 3 + index] as u32)
                | (u64::from(result[2 + MASKS.len() * 4 + index] as u32) << 32);
            Ok(format!(
                "{} io_status=0x{:08X} information=0x{information:016X}",
                frame(
                    phase,
                    index,
                    result[2 + index],
                    result[2 + MASKS.len() + index]
                )?,
                result[2 + MASKS.len() * 2 + index] as u32
            ))
        })
        .collect()
}
