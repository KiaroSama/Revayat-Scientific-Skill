use crate::native::*;
use crate::protocol::{
    Failure, Result, restriction_need, restriction_value, token_fields, token_need,
};
use std::ptr::null_mut;

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
    kind: &'static str,
) -> Result<usize> {
    token_need(pointer >= base && pointer.is_multiple_of(alignment), kind)?;
    let offset = pointer - base;
    token_need(offset <= length && bytes <= length - offset, kind)?;
    Ok(offset)
}

fn lpac(token: Raw) -> Result<()> {
    token_need(
        size_of::<AttributeHeader>() == 16 && size_of::<Attribute>() == 40,
        "control-lpac-abi",
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
    token_need(
        status == 0 && (16..=512).contains(&returned),
        "control-lpac-query",
    )?;
    let base = data.as_ptr() as usize;
    let length = returned as usize;
    // SAFETY: header fits the returned initialized buffer and has matching eight-byte alignment.
    let header = unsafe { data.as_ptr().cast::<AttributeHeader>().read() };
    token_need(
        header.version == 1 && header.reserved == 0 && header.count == 1,
        "control-lpac-header",
    )?;
    span(base, length, header.entries, 40, 8, "control-lpac-entry")?;
    // SAFETY: the complete attribute span and alignment were checked inside the live buffer.
    let attribute = unsafe { (header.entries as *const Attribute).read() };
    token_need(
        attribute.kind == 2
            && attribute.reserved == 0
            && attribute.count == 1
            && attribute.flags & 0x10 == 0,
        "control-lpac-type",
    )?;
    token_need(
        attribute.length == query.length
            && attribute.maximum >= query.length
            && attribute.maximum.is_multiple_of(2),
        "control-lpac-name-length",
    )?;
    span(
        base,
        length,
        attribute.name,
        attribute.maximum as usize,
        2,
        "control-lpac-name-span",
    )?;
    span(
        base,
        length,
        attribute.values,
        8,
        8,
        "control-lpac-value-span",
    )?;
    // SAFETY: both spans were checked against actual returned bytes, with required alignment.
    unsafe {
        let actual =
            std::slice::from_raw_parts(attribute.name as *const u16, attribute.length as usize / 2);
        token_need(
            actual == &name[..name.len() - 1] && (attribute.values as *const u64).read() == 1,
            "control-lpac-value",
        )?;
    }
    Ok(())
}

fn data(token: Raw, class: i32) -> Result<(Vec<u64>, usize)> {
    let stages = match class {
        29 => ["control-app-size", "control-app-read", "control-app-bounds"],
        30 => [
            "control-caps-size",
            "control-caps-read",
            "control-caps-bounds",
        ],
        3 => [
            "control-priv-size",
            "control-priv-read",
            "control-priv-bounds",
        ],
        2 => [
            "control-groups-size",
            "control-groups-read",
            "control-groups-bounds",
        ],
        _ => return Err(Failure::new("token", "control")),
    };
    let mut returned = 0;
    // SAFETY: first call only obtains length; second writes into sufficiently sized aligned storage.
    unsafe {
        let initial = GetTokenInformation(token, class, null_mut(), 0, &mut returned);
        let error = GetLastError();
        token_need(
            initial == 0 && error == 122 && (4..=65536).contains(&returned),
            stages[0],
        )?;
        let capacity = returned;
        let mut bytes = vec![0u64; (capacity as usize).div_ceil(8)];
        token_need(
            GetTokenInformation(
                token,
                class,
                bytes.as_mut_ptr().cast(),
                capacity,
                &mut returned,
            ) != 0,
            stages[1],
        )?;
        token_need(returned >= 4 && returned <= capacity, stages[2])?;
        Ok((bytes, returned as usize))
    }
}

// Windows defines SE_CHANGE_NOTIFY_PRIVILEGE as LUID { LowPart: 23, HighPart: 0 }.
const SE_CHANGE_NOTIFY_PRIVILEGE: u64 = 23;

fn privileges(data: &[u64], length: usize) -> Result<()> {
    token_need(
        length >= 4 && length <= std::mem::size_of_val(data),
        "control-priv-bounds",
    )?;
    let count = u32_at(data, 0) as usize;
    token_need(
        count <= 128 && 4 + count * 12 <= length,
        "control-priv-count",
    )?;
    for index in 0..count {
        let offset = 4 + index * 12;
        let luid = u64::from(u32_at(data, offset)) | (u64::from(u32_at(data, offset + 4)) << 32);
        token_need(luid == SE_CHANGE_NOTIFY_PRIVILEGE, "control-priv-value")?;
    }
    Ok(())
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
    token_need(opened != 0 && token.valid(), "control-open")?;
    let mut fields = [0u32; 3];
    for (index, class) in [8, 20, 21].iter().enumerate() {
        let mut returned = 0;
        // SAFETY: aligned four-byte capacity; class 21 consumes only its qualified returned span.
        let success = unsafe {
            GetTokenInformation(
                token.raw,
                *class,
                (&mut fields[index] as *mut u32).cast(),
                4,
                &mut returned,
            )
        };
        if *class == 21 {
            // SAFETY: called immediately and only when the preceding query returned FALSE.
            restriction_need(success, returned, || unsafe { GetLastError() })?;
            fields[index] = restriction_value(&fields[index].to_le_bytes()[..returned as usize])?;
        } else {
            token_need(
                success != 0 && returned == 4,
                ["control-type-query", "control-elevation-query"][index],
            )?;
        }
    }
    token_need(
        token_fields(fields[0], fields[1], fields[2]),
        "control-primary-fields",
    )?;
    lpac(token.raw)?;
    let (app, length) = data(token.raw, 29)?;
    token_need(length == 4 && u32_at(&app, 0) == 1, "control-app-value")?;
    let (capabilities, _) = data(token.raw, 30)?;
    token_need(u32_at(&capabilities, 0) == 0, "control-caps-value")?;
    let (privilege_data, length) = data(token.raw, 3)?;
    privileges(&privilege_data, length)?;
    let (groups, length) = data(token.raw, 2)?;
    let count = u32_at(&groups, 0) as usize;
    token_need(
        count <= 256 && 8 + count * 16 <= length,
        "control-groups-count",
    )?;
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
        span(base, length, pointer, 8, 4, "control-sid-head-span")?;
        // SAFETY: fixed SID header is bounded; validate subauthority length before inspecting any SID data.
        let header = unsafe { std::slice::from_raw_parts(pointer as *const u8, 8) };
        token_need(header[0] == 1 && header[1] <= 15, "control-sid-header")?;
        let size = 8 + header[1] as usize * 4;
        span(base, length, pointer, size, 4, "control-sid-span")?;
        // SAFETY: complete SID data fits the same live token buffer.
        let sid = unsafe { std::slice::from_raw_parts(pointer as *const u8, size) };
        if sid == [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0] {
            let attributes = u32_at(&groups, offset + 8);
            token_need(
                attributes & (8 | 4 | 2) == 0 && attributes & 16 != 0,
                "control-admin",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_inventory_requires_the_complete_traversal_luid() {
        let inventory = |entries: &[(u32, u32, u32)]| {
            let length = 4 + entries.len() * 12;
            let mut data = vec![0u64; length.div_ceil(8)];
            let mut put = |offset: usize, value: u32| {
                data[offset / 8] |= u64::from(value) << ((offset % 8) * 8);
            };
            put(0, entries.len() as u32);
            for (index, &(low, high, attributes)) in entries.iter().enumerate() {
                put(4 + index * 12, low);
                put(8 + index * 12, high);
                put(12 + index * 12, attributes);
            }
            (data, length)
        };
        let check = |entries: &[(u32, u32, u32)], expected: Option<&str>| {
            let (data, length) = inventory(entries);
            let result = privileges(&data, length);
            match expected {
                None => assert!(result.is_ok()),
                Some(kind) => assert_eq!(
                    result.expect_err("inventory must be refused").events,
                    vec![("token", kind)]
                ),
            }
        };
        check(&[], None);
        for attributes in [0, 2, u32::MAX] {
            check(&[(23, 0, attributes)], None);
        }
        for (low, high) in [
            (0, 0),
            (22, 0),
            (24, 0),
            (u32::MAX, 0),
            (23, 1),
            (23, 0x80000000),
            (23, u32::MAX),
        ] {
            check(&[(low, high, 0)], Some("control-priv-value"));
        }
        check(&[(23, 0, 2), (24, 0, 0)], Some("control-priv-value"));
        check(&[(24, 0, 0), (23, 0, 2)], Some("control-priv-value"));
        for (data, length, kind) in [
            (vec![], 0, "control-priv-bounds"),
            (vec![0], 3, "control-priv-bounds"),
            (vec![0], 9, "control-priv-bounds"),
            (vec![129], 4, "control-priv-count"),
            (vec![1, 0], 15, "control-priv-count"),
        ] {
            assert_eq!(
                privileges(&data, length)
                    .expect_err("malformed inventory")
                    .events,
                vec![("token", kind)]
            );
        }
    }

    #[test]
    fn token_spans_keep_bounds_alignment_and_first_failure() {
        assert_eq!(
            span(0x1000, 128, 0x1010, 40, 8, "control-lpac-entry").expect("span"),
            16
        );
        for (pointer, bytes, alignment) in [
            (0x0FF8, 8, 8),
            (0x1011, 8, 8),
            (0x1080, 8, 8),
            (0x1010, 120, 8),
        ] {
            let error = span(0x1000, 128, pointer, bytes, alignment, "control-lpac-entry")
                .expect_err("invalid span");
            assert_eq!(error.events, vec![("token", "control-lpac-entry")]);
        }
        let mut later = false;
        let result = (|| {
            token_need(false, "control-open")?;
            later = true;
            token_need(false, "control-lpac-header")
        })();
        assert!(!later);
        assert_eq!(
            result.expect_err("first refusal").events,
            vec![("token", "control-open")]
        );
    }
}
