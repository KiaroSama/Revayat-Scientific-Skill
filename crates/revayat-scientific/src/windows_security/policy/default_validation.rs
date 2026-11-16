//! Original child/default-security validator matrices, executed against shared operations.
use super::*;
use std::cell::{Cell, RefCell};

fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
    for part in parts {
        bytes.extend(part.to_le_bytes());
    }
    bytes
}
fn entry(kind: u8, mask: u32, identity: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = allow_ace(identity, mask)?;
    bytes[0] = kind;
    Ok(bytes)
}
pub fn check_child_validation() -> Result<()> {
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let other = sid(15, &[2, 3]);
    for (input, expected) in [
        (0x80000000, 0x20001),
        (0x20000000, 0x120000),
        (0xa0000000, 0x120001),
        (0xa0000002, 0x120003),
        (0xb0000000, 0x1f0003),
    ] {
        let entries = [entry(1, input, &other)?, entry(0, input, &other)?];
        let original = encode_acl(2, &entries)?;
        let before = original.clone();
        let inserted = child_with_user(&original, &user)?;
        let delta = plain_child(&inserted)?;
        let mapped_bytes = child_event_policy(&original)?;
        let mapped = plain_child(&mapped_bytes)?;
        need(
            original == before
                && delta.aces.len() == 3
                && delta.aces[0].bytes == entries[0]
                && delta.aces[2].bytes == entries[1]
                && delta.aces[1].mask()? == 0x10000000
                && delta.aces[1].sid()? == user,
            "policy",
            None,
        )?;
        for (index, ace) in mapped.aces.iter().enumerate() {
            need(
                ace.mask()? == expected
                    && ace.kind == entries[index][0]
                    && ace.flags == 0
                    && ace.sid()? == other,
                "policy",
                None,
            )?;
        }
    }
    let entries = [
        entry(1, 2, &sid(5, &[32, 546]))?,
        entry(0, 0x10000000, &other)?,
    ];
    let original = encode_acl(2, &entries)?;
    let inserted = child_with_user(&original, &user)?;
    let mapped = child_event_policy(&inserted)?;
    let mapped = plain_child(&mapped)?;
    need(
        mapped.aces[0].mask()? == 2 && mapped.aces[1].mask()? == 0x1f0003,
        "policy",
        None,
    )?;
    let mut padded = original.clone();
    padded.extend([0; 4]);
    let length = padded.len() as u16;
    padded[2..4].copy_from_slice(&length.to_le_bytes());
    need(
        child_acl_equal(&original, &padded)?
            && !child_acl_equal(&original, &inserted)?
            && child_with_user(&inserted, &user).is_err(),
        "policy",
        None,
    )?;
    let mut rejected = vec![Vec::new(), vec![0; 7]];
    for (offset, value) in [(1, 1), (9, 2), (15, 0x40), (15, 0x04), (17, 16)] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        rejected.push(bytes);
    }
    rejected.push(encode_acl(2, &[entries[1].clone(), entries[0].clone()])?);
    for bytes in rejected {
        need(plain_child(&bytes).is_err(), "policy", None)?;
    }
    need(
        within(100, 16, 100, 16, 1)
            && !within(100, 16, 99, 1, 1)
            && !within(100, 16, 108, 9, 1)
            && !within(u64::MAX - 8, 8, 1, 1, 1),
        "policy",
        None,
    )
}
pub fn check_control_validation() -> Result<()> {
    let first = need(false, "control", None).unwrap_err().to_string();
    let second = need(false, "control", None).unwrap_err().to_string();
    need(first != second && regex::Regex::new(r"^child default-DACL contract failed component=control source_check=[1-9][0-9]{0,3}$")?.is_match(&first), "control", None)?;
    need(
        opened(0, 2, 1, 0)? && !opened(0xc0000022, 0, 1, 0)?,
        "control",
        None,
    )?;
    for (status, output, created, directory) in [
        (0, 0, 1, 0),
        (0, 1, 1, 0),
        (0xc0000022, 2, 1, 0),
        (1, 0, 1, 0),
        (0, 2, 1, 2),
        (0, 3, 1, 1),
    ] {
        need(
            opened(status, output, created, directory).is_err(),
            "control",
            None,
        )?;
    }
    let package = "S-1-15-2-3";
    let relative = "AppContainerNamedObjects\\S-1-15-2-3";
    let qualified = "Sessions\\1\\AppContainerNamedObjects\\S-1-15-2-3";
    let path = format!("\\{qualified}");
    let suffix = "a".repeat(32);
    for accepted in [relative, qualified, path.as_str()] {
        need(
            object_name(accepted, accepted.len() as u32 + 1, &suffix, package, 1)?
                == format!("{path}\\ScientificDefaultDacl-{suffix}"),
            "control",
            None,
        )?;
    }
    need(
        object_name(relative, 40, &suffix, package, 0)?
            == format!("\\Sessions\\0\\{relative}\\ScientificDefaultDacl-{suffix}"),
        "control",
        None,
    )?;
    for rejected in [
        format!("\\{relative}"),
        format!("\\{path}"),
        format!("{path}\\"),
        format!("{relative}\\extra"),
        format!("{relative}0"),
        format!("Sessions\\2\\{relative}"),
        format!("Sessions\\01\\{relative}"),
        format!("Sessions\\+1\\{relative}"),
        format!("Global\\{relative}"),
        "AppContainerNamedObjects\\..".into(),
        "relative".into(),
        "\\private\nsentinel".into(),
    ] {
        let error = object_name(&rejected, 40, &suffix, package, 1)
            .unwrap_err()
            .to_string();
        need(
            !error.contains(package) && !error.contains(&suffix),
            "control",
            None,
        )?;
    }
    for (returned, suffix) in [
        (0, suffix.as_str()),
        (2049, suffix.as_str()),
        (40, "a"),
        (40, "gggggggggggggggggggggggggggggggg"),
    ] {
        need(
            object_name(relative, returned, suffix, package, 1).is_err(),
            "control",
            None,
        )?;
    }
    let mut buffer = vec![255; 4096];
    for (pair, unit) in buffer
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip("\\private\\fixed\0".encode_utf16())
    {
        pair.copy_from_slice(&unit.to_le_bytes());
    }
    need(
        decode_path(&buffer, 14)? == "\\private\\fixed"
            && decode_path(&buffer, 15)? == "\\private\\fixed",
        "control",
        None,
    )?;
    for (bytes, returned) in [
        (vec![0; 4096], 1),
        (vec![255; 4096], 1),
        (buffer.clone(), 0),
        (buffer.clone(), 2049),
    ] {
        need(decode_path(&bytes, returned).is_err(), "control", None)?;
    }
    let user = sid(5, &[21, 1, 2, 3, 500]);
    let other = sid(15, &[2, 3]);
    let directory = directory_descriptor(&user, &other)?;
    require_directory_policy(&directory, &user, &other)?;
    let policy = Descriptor::parse(&directory)?;
    need(
        policy.owner == Some(user.as_slice())
            && policy.group == Some(user.as_slice())
            && policy.control & 0x1000 != 0
            && policy.dacl
                == Some(
                    encode_acl(2, &[entry(0, 0x20006, &user)?, entry(0, 0x20006, &other)?])?
                        .as_slice(),
                ),
        "control",
        None,
    )?;
    for mode in 0..10 {
        let mut bad = directory.clone();
        let dacl_offset = 20 + user.len();
        match mode {
            0 => {
                bad[4..8]
                    .copy_from_slice(&(dacl_offset as u32 + 24 + user.len() as u32).to_le_bytes());
            }
            1 => {
                bad[3] &= !0x10;
            }
            2 => {
                bad[16..20].fill(0);
            }
            _ => {
                let mut entries = vec![entry(0, 0x20006, &user)?, entry(0, 0x20006, &other)?];
                match mode {
                    3 => {
                        entries.pop();
                    }
                    4 => entries.push(entry(0, 0x20006, &user)?),
                    5 => entries.swap(0, 1),
                    6 => entries[0][1] = 1,
                    7 => entries[1][4..8].copy_from_slice(&0x20007u32.to_le_bytes()),
                    8 => entries[1] = entry(0, 0x20006, &sid(1, &[0]))?,
                    9 => entries[1][1] = 16,
                    _ => unreachable!(),
                }
                bad.truncate(dacl_offset);
                bad.extend(encode_acl(2, &entries)?);
            }
        }
        need(
            require_directory_policy(&bad, &user, &other).is_err(),
            "control",
            None,
        )?;
    }
    let attributes = event_attributes(3, 4)?;
    need(
        std::mem::size_of::<EventAttributes>() == 48
            && attributes.root == 3
            && attributes.name == 4
            && attributes.flags == 0
            && attributes.descriptor == 0
            && attributes.qos == 0
            && EVENT_LEAF == "DefaultDaclEvent",
        "control",
        None,
    )?;
    let primary = preparation_failure("read-primary", anyhow::anyhow!("fixed original"));
    need(
        primary.to_string() == "child default-security preparation failed phase=read-primary"
            && primary.error.to_string() == "fixed original",
        "control",
        None,
    )?;
    let cleanup_error = finish_objects(
        Some(primary.into()),
        [1, 0, 0],
        |_| anyhow::bail!("fixed cleanup"),
        Vec::new(),
    )
    .unwrap_err();
    need(
        cleanup_error
            .downcast_ref::<Failures>()
            .is_some_and(|group| {
                group.errors[0]
                    .downcast_ref::<PreparationFailure>()
                    .is_some()
            }),
        "control",
        None,
    )?;
    need(
        require_directory_policy(&directory, &other, &user).is_err(),
        "control",
        None,
    )?;
    let prepared = encode_acl(2, &[entry(0, 0x10000000, &user)?, entry(0, 2, &other)?])?;
    let expected = encode_acl(2, &[entry(0, 0x1f0003, &user)?, entry(0, 2, &other)?])?;
    let descriptor = |acl: &[u8]| {
        let mut bytes = vec![1, 0, 4, 0x80];
        for offset in [20u32, 0, 0, 20 + user.len() as u32] {
            bytes.extend(offset.to_le_bytes());
        }
        bytes.extend(&user);
        bytes.extend(acl);
        bytes
    };
    let bytes = descriptor(&expected);
    require_object_policy(&bytes, &user, &prepared)?;
    for entries in [
        vec![entry(0, 2, &user)?, entry(0, 2, &other)?],
        vec![entry(0, 0x1f0003, &user)?],
        vec![
            entry(0, 0x1f0003, &user)?,
            entry(0, 2, &other)?,
            entry(0, 1, &other)?,
        ],
        vec![entry(0, 2, &other)?, entry(0, 0x1f0003, &user)?],
    ] {
        need(
            require_object_policy(&descriptor(&encode_acl(2, &entries)?), &user, &prepared)
                .is_err(),
            "control",
            None,
        )?;
    }
    need(
        require_object_policy(&[0; 19], &user, &prepared).is_err()
            && require_object_policy(&bytes, &sid(5, &[32, 546]), &prepared).is_err(),
        "control",
        None,
    )?;
    let order = RefCell::new(Vec::<&str>::new());
    finish_context(
        None,
        true,
        || {
            order.borrow_mut().push("revert");
            Ok(true)
        },
        || anyhow::bail!("unexpected fatal"),
        vec![Box::new(|| {
            order.borrow_mut().push("close");
            Ok(())
        })],
    )?;
    need(*order.borrow() == ["revert", "close"], "control", None)?;
    for throws in [false, true] {
        order.borrow_mut().clear();
        let error = finish_context(
            None,
            true,
            || {
                order.borrow_mut().push("revert");
                if throws {
                    anyhow::bail!("fixed revert")
                };
                Ok(false)
            },
            || {
                order.borrow_mut().push("fatal");
                anyhow::bail!("fixed fatal")
            },
            vec![Box::new(|| {
                order.borrow_mut().push("close");
                Ok(())
            })],
        )
        .unwrap_err();
        need(
            error.to_string() == "fixed fatal" && *order.borrow() == ["revert", "fatal"],
            "control",
            None,
        )?;
    }
    for aliases in [false, true] {
        let handles = if aliases { [1, 1, 1] } else { [2, 1, 3] };
        let visited = RefCell::new(Vec::new());
        let result = finish_objects(
            Some(anyhow::anyhow!("fixed primary")),
            handles,
            |handle| {
                visited.borrow_mut().push(handle);
                anyhow::bail!("fixed close")
            },
            Vec::new(),
        )
        .unwrap_err();
        let group = result
            .downcast_ref::<Failures>()
            .context("independent closes were not retained")?;
        need(
            group.errors[0].to_string() == "fixed primary"
                && group.errors.len() == if aliases { 2 } else { 4 }
                && *visited.borrow() == if aliases { vec![1] } else { vec![2, 1, 3] },
            "control",
            None,
        )?;
    }
    let count = Cell::new(0);
    let result = finish_objects(
        Some(anyhow::anyhow!("fixed primary")),
        [0, usize::MAX, 0],
        |_| anyhow::bail!("invalid close"),
        vec![
            Box::new(|| {
                count.set(count.get() + 1);
                anyhow::bail!("fixed close")
            }),
            Box::new(|| {
                count.set(count.get() + 1);
                Ok(())
            }),
        ],
    )
    .unwrap_err();
    need(
        count.get() == 2
            && result
                .downcast_ref::<Failures>()
                .is_some_and(|group| group.errors.len() == 2),
        "control",
        None,
    )
}
