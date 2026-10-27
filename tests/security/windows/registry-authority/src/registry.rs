use crate::native::*;
use crate::protocol::{DENIED, Failure, KEY, READ, Result, basic, denied, identity, need};
use std::ptr::null_mut;
use std::time::{Duration, Instant};

fn deadline(start: Instant) -> Result<()> {
    if start.elapsed() < Duration::from_secs(8) {
        Ok(())
    } else {
        Err(Failure::new("inventory", "timeout"))
    }
}

fn open(name: &str, access: u32, root: Raw, start: Instant) -> Result<(u32, Handle)> {
    deadline(start)?;
    let text = wide(name);
    need(
        !name.contains('\0') && text.len() > 1 && text.len() <= 513,
        "root",
    )?;
    let name = Unicode {
        length: ((text.len() - 1) * 2) as u16,
        maximum: (text.len() * 2) as u16,
        buffer: text.as_ptr(),
    };
    let attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root,
        name: &name,
        flags: 0x1040,
        descriptor: null_mut(),
        qos: null_mut(),
    };
    let mut raw = null_mut();
    // SAFETY: live native string/attributes, borrowed root; returned handle immediately owned.
    let status = unsafe { NtOpenKeyEx(&mut raw, access, &attributes, 0) } as u32;
    Ok((status, Handle::new(raw, true)))
}

fn qualify(handle: &Handle, expected: &str) -> Result<()> {
    need(handle.valid(), "identity")?;
    let mut basic_data = [0u64; 7];
    let mut returned = 0;
    // SAFETY: exact 56-byte aligned output and valid owned key handle.
    let status = unsafe {
        NtQueryObject(
            handle.raw,
            0,
            basic_data.as_mut_ptr().cast(),
            56,
            &mut returned,
        )
    };
    need(
        basic(
            status as u32,
            returned,
            basic_data[0] as u32,
            (basic_data[0] >> 32) as u32,
        ),
        "identity",
    )?;
    let mut data = [0u64; 512];
    // SAFETY: aligned writable 4096-byte native buffer; validate actual returned bytes before parsing.
    let status =
        unsafe { NtQueryKey(handle.raw, 3, data.as_mut_ptr().cast(), 4096, &mut returned) };
    // SAFETY: the initialized array owns exactly4096 bytes and remains live for this borrowed view.
    let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), 4096) };
    let result = identity(
        status as u32,
        returned as usize,
        bytes,
        expected.encode_utf16().count() * 2,
    );
    data.fill(0);
    need(same_name(&result?, expected)?, "identity")
}

fn counts(handle: &Handle) -> Result<(u32, u32, u64)> {
    let (mut keys, mut values, mut modified) = (0, 0, 0);
    // SAFETY: valid key and exact writable outputs; unused optional outputs are null.
    let status = unsafe {
        RegQueryInfoKeyW(
            handle.raw,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut keys,
            null_mut(),
            null_mut(),
            &mut values,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut modified,
        )
    };
    need(status == 0 && keys <= 256 && values <= 32, "inventory")?;
    Ok((keys, values, modified))
}

pub fn controls() -> Result<(u32, u32)> {
    need(
        size_of::<Raw>() == 8 && size_of::<Unicode>() == 16 && size_of::<Attributes>() == 48,
        "start",
    )?;
    detached()?;
    crate::token::controls()?;
    let start = Instant::now();
    let (status, root) = open(KEY, READ, null_mut(), start)?;
    need(status == 0, "root")?;
    qualify(&root, KEY)?;
    for access in [2, 4, 0x10000, 0x40000, 0x80000] {
        let (status, handle) = open(KEY, access, null_mut(), start)?;
        need(denied(status, handle.raw as usize), "mutation")?;
    }
    let before = counts(&root)?;
    let mut names: Vec<String> = Vec::new();
    let mut accessible = 0;
    for index in 0..=256 {
        deadline(start)?;
        let mut name = [0u16; 512];
        let mut length = 512;
        // SAFETY: fixed writable UTF-16 buffer and valid owned root; no value contents read.
        let status = unsafe {
            RegEnumKeyExW(
                root.raw,
                index,
                name.as_mut_ptr(),
                &mut length,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status == 259 {
            need(index == before.0, "inventory")?;
            break;
        }
        need(
            status == 0 && index < 256 && length > 0 && length < 512,
            "inventory",
        )?;
        need(
            name[length as usize] == 0 && !name[..length as usize].contains(&0),
            "inventory",
        )?;
        let text = String::from_utf16(&name[..length as usize])
            .map_err(|_| Failure::new("inventory", "decode"))?;
        name.fill(0);
        need(!text.contains(['\\', '/']), "inventory")?;
        for prior in &names {
            need(!same_name(prior, &text)?, "inventory")?;
        }
        let (status, child) = open(&text, READ, root.raw, start)?;
        need(status == 0 || status == DENIED, "inventory")?;
        if status == 0 {
            qualify(&child, &format!("{KEY}\\{text}"))?;
            accessible += 1;
        } else {
            need(child.raw.is_null(), "inventory")?;
        }
        names.push(text);
    }
    need(
        counts(&root)? == before && names.len() == before.0 as usize,
        "inventory",
    )?;
    crate::token::controls()?;
    deadline(start)?;
    Ok((names.len() as u32, accessible))
}
