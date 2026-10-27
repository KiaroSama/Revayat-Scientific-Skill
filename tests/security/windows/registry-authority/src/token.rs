use crate::native::*;
use crate::protocol::{Result, need, token_fields};
use std::ptr::{null, null_mut};

#[repr(C)]
#[derive(Clone, Copy)]
struct AttributeHeader {
    version: u16,
    reserved: u16,
    count: u32,
    entries: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Attribute {
    length: u16,
    maximum: u16,
    name: usize,
    kind: u16,
    reserved: u16,
    flags: u32,
    count: u32,
    values: usize,
}

fn span(
    base: usize,
    length: usize,
    pointer: usize,
    bytes: usize,
    alignment: usize,
) -> Result<usize> {
    need(
        pointer >= base && pointer.is_multiple_of(alignment),
        "token",
    )?;
    let offset = pointer - base;
    need(offset <= length && bytes <= length - offset, "token")?;
    Ok(offset)
}

fn lpac(token: Raw) -> Result<()> {
    need(
        size_of::<AttributeHeader>() == 16 && size_of::<Attribute>() == 40,
        "token",
    )?;
    let name = wide("WIN://NOALLAPPPKG");
    let query = Unicode {
        length: ((name.len() - 1) * 2) as u16,
        maximum: ((name.len() - 1) * 2) as u16,
        buffer: name.as_ptr(),
    };
    let mut data = [0u64; 64];
    let mut returned = 0;
    // SAFETY: fixed aligned writable buffer and live byte-counted query; pointers are bounded below.
    let status = unsafe {
        NtQuerySecurityAttributesToken(
            token,
            &query,
            1,
            data.as_mut_ptr().cast(),
            512,
            &mut returned,
        )
    };
    need(status == 0 && (16..=512).contains(&returned), "token")?;
    let base = data.as_ptr() as usize;
    let length = returned as usize;
    // SAFETY: header fits the returned initialized buffer and has matching eight-byte alignment.
    let header = unsafe { data.as_ptr().cast::<AttributeHeader>().read() };
    need(
        header.version == 1 && header.reserved == 0 && header.count == 1,
        "token",
    )?;
    span(base, length, header.entries, 40, 8)?;
    // SAFETY: the complete attribute span and alignment were checked inside the live buffer.
    let attribute = unsafe { (header.entries as *const Attribute).read() };
    need(
        attribute.kind == 2
            && attribute.reserved == 0
            && attribute.count == 1
            && attribute.flags & 0x10 == 0,
        "token",
    )?;
    need(
        attribute.length == query.length
            && attribute.maximum >= query.length
            && attribute.maximum.is_multiple_of(2),
        "token",
    )?;
    span(base, length, attribute.name, attribute.maximum as usize, 2)?;
    span(base, length, attribute.values, 8, 8)?;
    // SAFETY: both spans were checked against actual returned bytes, with required alignment.
    unsafe {
        let actual =
            std::slice::from_raw_parts(attribute.name as *const u16, attribute.length as usize / 2);
        need(
            actual == &name[..name.len() - 1] && (attribute.values as *const u64).read() == 1,
            "token",
        )?;
    }
    Ok(())
}

fn data(token: Raw, class: i32) -> Result<(Vec<u64>, usize)> {
    let mut returned = 0;
    // SAFETY: first call only obtains length; second writes into sufficiently sized aligned storage.
    unsafe {
        let initial = GetTokenInformation(token, class, null_mut(), 0, &mut returned);
        let error = GetLastError();
        need(
            initial == 0 && error == 122 && (4..=65536).contains(&returned),
            "token",
        )?;
        let capacity = returned;
        let mut bytes = vec![0u64; (capacity as usize).div_ceil(8)];
        need(
            GetTokenInformation(
                token,
                class,
                bytes.as_mut_ptr().cast(),
                capacity,
                &mut returned,
            ) != 0,
            "token",
        )?;
        need(returned >= 4 && returned <= capacity, "token")?;
        Ok((bytes, returned as usize))
    }
}

fn u32_at(data: &[u64], offset: usize) -> u32 {
    // SAFETY: callers bound each field within initialized data; read_unaligned handles packed fields.
    unsafe {
        data.as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<u32>()
            .read_unaligned()
    }
}

pub fn controls() -> Result<()> {
    let mut raw = null_mut();
    // SAFETY: pseudo process handle is borrowed and output token is immediately owned.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) };
    let token = Handle::new(raw, false);
    need(opened != 0 && token.valid(), "token")?;
    let mut fields = [0u32; 3];
    for (index, class) in [8, 20, 21].iter().enumerate() {
        let mut returned = 0;
        // SAFETY: scalar token classes have exact four-byte writable storage.
        let success = unsafe {
            GetTokenInformation(
                token.raw,
                *class,
                (&mut fields[index] as *mut u32).cast(),
                4,
                &mut returned,
            )
        };
        need(success != 0 && returned == 4, "token")?;
    }
    need(token_fields(fields[0], fields[1], fields[2]), "token")?;
    lpac(token.raw)?;
    let (app, length) = data(token.raw, 29)?;
    need(length == 4 && u32_at(&app, 0) == 1, "token")?;
    let (capabilities, _) = data(token.raw, 30)?;
    need(u32_at(&capabilities, 0) == 0, "token")?;
    let mut traverse = 0u64;
    let name = wide("SeChangeNotifyPrivilege");
    // SAFETY: live NUL-terminated name and exact LUID-sized writable output.
    need(
        unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut traverse) } != 0,
        "token",
    )?;
    let (privileges, length) = data(token.raw, 3)?;
    let count = u32_at(&privileges, 0) as usize;
    need(count <= 128 && 4 + count * 12 <= length, "token")?;
    for index in 0..count {
        let offset = 4 + index * 12;
        let luid = u64::from(u32_at(&privileges, offset))
            | (u64::from(u32_at(&privileges, offset + 4)) << 32);
        need(luid == traverse, "token")?;
    }
    let (groups, length) = data(token.raw, 2)?;
    let count = u32_at(&groups, 0) as usize;
    need(count <= 256 && 8 + count * 16 <= length, "token")?;
    let base = groups.as_ptr() as usize;
    for index in 0..count {
        let offset = 8 + index * 16;
        // SAFETY: each SID_AND_ATTRIBUTES fits inside the returned, aligned group buffer.
        let pointer = unsafe {
            groups
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<usize>()
                .read()
        };
        span(base, length, pointer, 8, 4)?;
        // SAFETY: fixed SID header is bounded; validate subauthority length before inspecting any SID data.
        let header = unsafe { std::slice::from_raw_parts(pointer as *const u8, 8) };
        need(header[0] == 1 && header[1] <= 15, "token")?;
        let size = 8 + header[1] as usize * 4;
        span(base, length, pointer, size, 4)?;
        // SAFETY: complete SID data fits the same live token buffer.
        let sid = unsafe { std::slice::from_raw_parts(pointer as *const u8, size) };
        if sid == [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0] {
            let attributes = u32_at(&groups, offset + 8);
            need(
                attributes & (8 | 4 | 2) == 0 && attributes & 16 != 0,
                "token",
            )?;
        }
    }
    Ok(())
}
