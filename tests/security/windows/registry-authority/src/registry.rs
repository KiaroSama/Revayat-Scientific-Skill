use crate::native::*;
use crate::protocol::{Failure, KEY, READ, Result, basic, denied, identity, need};
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
    if name.contains('\0') || text.len() <= 1 || text.len() > 513 {
        return Err(Failure::new("root", "control-name"));
    }
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

pub fn machine_baseline() -> Result<String> {
    need(
        [
            "REVAYAT_AUTHORITY_FIXTURE",
            "REVAYAT_AUTHORITY_FOREIGN",
            "REVAYAT_AUTHORITY_NETWORK",
        ]
        .iter()
        .all(|name| std::env::var_os(name).is_none()),
        "start",
    )?;
    detached()?;
    crate::token::controls()?;
    let started = Instant::now();
    let (status, mut key) = open(KEY, READ, null_mut(), started)?;
    let record = crate::protocol::machine_baseline_record(status, key.raw as usize);
    let cleanup = key.close();
    let record = match (record, cleanup) {
        (Ok(record), Ok(())) => record,
        (Err(mut primary), Err(_)) => {
            primary.events.push(("close", "cleanup"));
            return Err(primary);
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    crate::token::controls()?;
    deadline(started)?;
    Ok(record)
}

pub fn controls() -> Result<(u32, u32)> {
    let fixture = std::env::var("REVAYAT_AUTHORITY_FIXTURE").ok();
    let foreign = std::env::var_os("REVAYAT_AUTHORITY_FOREIGN");
    let network = std::env::var("REVAYAT_AUTHORITY_NETWORK").ok();
    need(fixture.is_some() == foreign.is_some(), "start")?;
    need(fixture.is_some() == network.is_some(), "start")?;
    if let Some(name) = &fixture {
        need(crate::protocol::fixture_name(name), "start")?;
    }
    let key = fixture.as_deref().unwrap_or(KEY);
    need(
        size_of::<Raw>() == 8 && size_of::<Unicode>() == 16 && size_of::<Attributes>() == 48,
        "start",
    )?;
    detached()?;
    crate::token::controls()?;
    let start = Instant::now();
    let (status, root) = open(key, READ, null_mut(), start)?;
    crate::protocol::root_open(status, root.raw as usize)?;
    qualify(&root, key)?;
    for access in [2, 4, 0x10000, 0x40000, 0x80000] {
        let (status, handle) = open(key, access, null_mut(), start)?;
        need(denied(status, handle.raw as usize), "mutation")?;
    }
    let before = counts(&root)?;
    let mut names: Vec<String> = Vec::new();
    let accessible = 0;
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
        for access in [1, 8, 0x10, 0x20000] {
            let (status, child) = open(&format!("{key}\\{text}"), access, null_mut(), start)?;
            need(denied(status, child.raw as usize), "inventory")?;
        }
        let (status, child) = open(&text, READ, root.raw, start)?;
        need(denied(status, child.raw as usize), "inventory")?;
        names.push(text);
    }
    need(
        counts(&root)? == before && names.len() == before.0 as usize,
        "inventory",
    )?;
    crate::token::controls()?;
    if let Some(path) = foreign {
        foreign_denied(&path)?;
        scratch_control()?;
        network_denied(
            network
                .as_deref()
                .ok_or_else(|| Failure::new("start", "control"))?,
        )?;
    }
    deadline(start)?;
    Ok((names.len() as u32, accessible))
}

fn network_denied(value: &str) -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
    use std::time::Duration;
    let ports = value
        .split(',')
        .map(|part| {
            part.parse::<u16>()
                .ok()
                .filter(|number| *number > 0 && part == number.to_string())
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Failure::new("mutation", "control"))?;
    need(ports.len() == 4, "mutation")?;
    let hosts = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    for (host, port) in hosts.into_iter().zip(&ports[..2]) {
        match TcpStream::connect_timeout(&SocketAddr::new(host, *port), Duration::from_secs(1)) {
            Err(error) if error.raw_os_error() == Some(10013) => {}
            _ => return Err(Failure::new("mutation", "control")),
        }
    }
    for (host, port) in hosts.into_iter().zip(&ports[2..]) {
        let bind = match host {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        match UdpSocket::bind(SocketAddr::new(bind, 0)) {
            Err(error) if error.raw_os_error() == Some(10013) => {}
            Ok(socket) => {
                match socket.send_to(b"native LPAC denial control", SocketAddr::new(host, *port)) {
                    Err(error) if error.raw_os_error() == Some(10013) => {}
                    _ => return Err(Failure::new("mutation", "control")),
                }
            }
            _ => return Err(Failure::new("mutation", "control")),
        }
    }
    Ok(())
}

fn scratch_control() -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::OpenOptionsExt;
    let path = std::env::current_dir()
        .map_err(|_| Failure::new("mutation", "native"))?
        .join("native-create-only-control");
    // Create-only, no sharing, no reparse following, delete the exact owned
    // object on close. A collision is fatal and never causes pathname cleanup.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(0xc0010000)
        .share_mode(0)
        .custom_flags(0x04200000)
        .open(&path)
        .map_err(|_| Failure::new("mutation", "native"))?;
    let expected = b"native owned scratch control\0\r\n";
    file.write_all(expected)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|_| Failure::new("mutation", "native"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Failure::new("mutation", "native"))?;
    let mut actual = [0u8; 32];
    let count = file
        .read(&mut actual)
        .map_err(|_| Failure::new("mutation", "native"))?;
    need(
        count == expected.len() && actual[..count] == expected[..],
        "mutation",
    )?;
    actual.fill(0);
    use std::os::windows::io::IntoRawHandle;
    let mut owned = Handle::new(file.into_raw_handle(), false);
    owned.close()?;
    need(
        matches!(std::fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound),
        "mutation",
    )
}

fn foreign_denied(path: &std::ffi::OsStr) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let path = path.encode_wide().chain(Some(0)).collect::<Vec<_>>();
    need(
        path.len() > 1 && path.len() < 32768 && !path[..path.len() - 1].contains(&0),
        "mutation",
    )?;
    for access in [0x8000_0000u32, 0x4000_0000] {
        // SAFETY: fixed host-provisioned private sentinel, no content is read or written.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                access,
                3,
                std::ptr::null(),
                3,
                0x200000,
                null_mut(),
            )
        };
        let error = if raw as isize == -1 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        let mut owner = Handle::new(raw, false);
        need(raw as isize == -1 && error == Some(5), "mutation")?;
        owner.close()?;
    }
    Ok(())
}
