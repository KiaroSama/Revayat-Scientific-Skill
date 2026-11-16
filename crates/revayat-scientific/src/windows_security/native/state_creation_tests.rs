//! Test-only native creation diagnostics; no candidate authorizes production state.
use super::*;
use std::fmt::{self, Write};

const STATUS_CHARACTERS: usize = 512;

struct StatusText {
    text: String,
    characters: usize,
    truncated: bool,
}
impl fmt::Write for StatusText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            let escaped = if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
            {
                character.escape_default().collect::<String>()
            } else {
                character.to_string()
            };
            let count = escaped.chars().count();
            // Reserve Err(...), its closing parenthesis, and a truncation marker.
            if count > STATUS_CHARACTERS - 8 - self.characters {
                self.truncated = true;
                return Err(fmt::Error);
            }
            self.text.push_str(&escaped);
            self.characters += count;
        }
        Ok(())
    }
}

fn display_causes(error: &anyhow::Error, output: &mut StatusText) -> fmt::Result {
    for (index, cause) in error.chain().enumerate() {
        if index != 0 {
            output.write_str(" -> ")?;
        }
        write!(output, "{cause}")?;
        // This aggregate intentionally has no source(); preserve its ordered causes explicitly.
        if let Some(group) = cause.downcast_ref::<Failures>() {
            for (index, nested) in group.errors.iter().enumerate() {
                write!(output, " | cause{}: ", index + 1)?;
                display_causes(nested, output)?;
            }
        }
    }
    Ok(())
}

pub(super) fn compact_status<T>(result: &Result<T>) -> String {
    let Err(error) = result else {
        return "Ok".into();
    };
    let mut output = StatusText {
        text: String::new(),
        characters: 0,
        truncated: false,
    };
    let _ = display_causes(error, &mut output);
    format!(
        "Err({}{})",
        output.text,
        if output.truncated { "..." } else { "" }
    )
}

pub(super) struct AssignmentMatrix {
    rows: Vec<String>,
    pub(super) private_lineage_qualified: bool,
}

pub(super) fn compact_assignment_rows(result: &Result<AssignmentMatrix>) -> String {
    match result {
        Ok(matrix) => matrix.rows.join("\n"),
        Err(_) => compact_status(result),
    }
}

pub(super) fn check_compact_status() {
    struct DisplayOnly;
    impl fmt::Debug for DisplayOnly {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("compact diagnostics must never invoke Debug")
        }
    }
    impl fmt::Display for DisplayOnly {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("native winerror=5\n\r\t\u{1b}\u{2028}")
        }
    }
    impl std::error::Error for DisplayOnly {}
    let primary = anyhow::Error::new(DisplayOnly).context("private creation");
    let result: Result<()> = Err(Failures {
        errors: vec![primary, anyhow::anyhow!("close winerror=6")],
    }
    .into());
    let status = compact_status(&result);
    assert!(status.find("private creation").unwrap() < status.find("native winerror=5").unwrap());
    assert!(status.find("native winerror=5").unwrap() < status.find("close winerror=6").unwrap());
    assert!(status.contains("\\n\\r\\t\\u{1b}\\u{2028}") && !status.chars().any(char::is_control));
    let long: Result<()> = Err(anyhow::anyhow!("{}", "failure\n\u{1b}".repeat(1024)));
    let bounded = compact_status(&long);
    assert!(bounded.chars().count() <= STATUS_CHARACTERS && bounded.ends_with("...)"));
    assert!(!bounded.chars().any(char::is_control));
    assert_eq!(compact_status(&Ok::<_, anyhow::Error>(())), "Ok");
}

fn state_creation_variant(path: &Path, sddl: Option<&str>) -> Result<()> {
    #[repr(C)]
    struct Security {
        size: u32,
        descriptor: Handle,
        inherit: i32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateDirectoryW(path: *const u16, security: *const Security) -> i32;
    }
    let mut descriptor = sddl.map(Descriptor::new).transpose()?;
    let attributes = Security {
        size: size_of::<Security>() as u32,
        descriptor: descriptor.as_ref().map_or(null_mut(), |value| value.0),
        inherit: 0,
    };
    let path = wide(path);
    let created = unsafe {
        CreateDirectoryW(
            path.as_ptr(),
            if sddl.is_some() {
                &attributes
            } else {
                std::ptr::null()
            },
        )
    };
    let code = if created == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let result = (|| {
        ensure!(
            created != 0,
            "native state creation variant failed winerror={code}"
        );
        Ok(())
    })();
    finish(
        result,
        descriptor.as_mut().map_or(Ok(()), Descriptor::close),
    )
}

pub(super) fn state_creation_assignment_matrix(
    root: &Path,
    host: &str,
) -> Result<AssignmentMatrix> {
    let noninheritable = private_sddl(host, true)?;
    ensure!(
        noninheritable.contains("(D;;0x000C0000;;;S-1-3-4)"),
        "private state owner denial is absent or inheritable"
    );
    // Keep the measured failing policy independent of the corrected production builder.
    let original = noninheritable.replacen(
        "(D;;0x000C0000;;;S-1-3-4)",
        "(D;OICI;0x000C0000;;;S-1-3-4)",
        1,
    );
    let ownerless = original
        .strip_prefix(&format!("O:{host}"))
        .context("private assignment owner section absent")?;
    let grouped = original.replacen("D:", &format!("G:{host}D:"), 1);
    let grouped_noninheritable = noninheritable.replacen("D:", &format!("G:{host}D:"), 1);
    let policies = [
        ("original", &original),
        ("noninheritable", &noninheritable),
        ("grouped", &grouped),
        ("grouped_noninheritable", &grouped_noninheritable),
    ];
    let mut observations = Vec::new();
    let mut private_lineage_qualified = false;
    let mut cleanup_complete = true;
    for (index, (parent_label, parent_sddl)) in policies.iter().enumerate() {
        let parent = root.join(format!("assignment-parent-{index}"));
        let parent_result = state_creation_variant(&parent, Some(parent_sddl));
        let parent_policy = exact_assignment_policy(&parent, parent_sddl);
        let mut children = Vec::new();
        for (child_label, child_sddl) in policies {
            let child = parent.join(format!("protected-{child_label}"));
            let creation = state_creation_variant(&child, Some(child_sddl));
            let policy = exact_assignment_policy(&child, child_sddl);
            // A failed creation/readback never authorizes durable writes into that object.
            let record = if creation.is_ok() && policy.is_ok() {
                assignment_record(&child, host)
            } else {
                Err(anyhow::anyhow!(
                    "unqualified candidate prevents record creation"
                ))
            };
            if *parent_label == "noninheritable" && child_label == "noninheritable" {
                private_lineage_qualified = parent_result.is_ok()
                    && parent_policy.is_ok()
                    && creation.is_ok()
                    && policy.is_ok()
                    && record.is_ok();
            }
            children.push(format!(
                "parent={index} child={child_label} creation={} policy_and_denial={} durable_record={}",
                compact_status(&creation), compact_status(&policy), compact_status(&record)
            ));
        }
        let inherited = state_creation_variant(&parent.join("inherited-child"), None);
        let ownerless = state_creation_variant(&parent.join("ownerless-child"), Some(ownerless));
        // Every create/readback/control is collected before this parent's explicit cleanup.
        let cleanup = fs::remove_dir_all(&parent).map_err(anyhow::Error::from);
        cleanup_complete &= cleanup.is_ok();
        observations.push(format!(
            "parent={index} kind={parent_label} creation={} policy_and_denial={}",
            compact_status(&parent_result),
            compact_status(&parent_policy)
        ));
        observations.extend(children);
        observations.push(format!(
            "parent={index} inherited={} ownerless={} cleanup={}",
            compact_status(&inherited),
            compact_status(&ownerless),
            compact_status(&cleanup)
        ));
    }
    Ok(AssignmentMatrix {
        rows: observations,
        private_lineage_qualified: private_lineage_qualified && cleanup_complete,
    })
}

fn exact_assignment_policy(path: &Path, sddl: &str) -> Result<()> {
    let mut pin = Pin::open(path, true)?;
    let result = (|| {
        require_assignment_descriptor(
            pin.file.as_ref().context("private assignment pin absent")?,
            sddl,
        )?;
        state_assignment_mutation_denied(path)?;
        pin.require()
    })();
    finish(result, pin.close())
}

fn assignment_record(directory: &Path, host: &str) -> Result<()> {
    let mut directory_pin = Pin::open(directory, true)?;
    let result = (|| {
        directory_pin.require()?;
        let path = directory.join("private-record");
        let expected = b"fixed private state assignment";
        write_new(&path, host, expected)?;
        let mut pin = Pin::open(&path, false)?;
        let result = (|| {
            private(
                pin.file.as_ref().context("private record pin absent")?,
                host,
                false,
            )?;
            state_assignment_mutation_denied(&path)?;
            ensure!(
                pin.bytes()?.as_slice() == expected.as_slice(),
                "private durable record readback differs"
            );
            directory_pin.require()
        })();
        finish(result, pin.close())
    })();
    finish(result, directory_pin.close())
}

fn require_assignment_descriptor(file: &std::fs::File, sddl: &str) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(
            object: Handle,
            kind: i32,
            information: u32,
            owner: *mut Handle,
            group: *mut Handle,
            dacl: *mut Handle,
            sacl: *mut Handle,
            descriptor: *mut Handle,
        ) -> u32;
        fn GetSecurityDescriptorLength(descriptor: Handle) -> u32;
    }
    let mut expected = Descriptor::new(sddl)?;
    let (mut owner, mut group, mut dacl, mut sacl, mut raw) =
        (null_mut(), null_mut(), null_mut(), null_mut(), null_mut());
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            7,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut raw,
        )
    };
    let result = (|| {
        ensure!(
            status == 0
                && !raw.is_null()
                && !owner.is_null()
                && !group.is_null()
                && !dacl.is_null(),
            "private assignment descriptor query failed winerror={status}"
        );
        let actual_size = unsafe { GetSecurityDescriptorLength(raw) };
        let expected_size = unsafe { GetSecurityDescriptorLength(expected.0) };
        ensure!(
            (20..=65536).contains(&actual_size) && (20..=65536).contains(&expected_size),
            "private assignment descriptor exceeds bound"
        );
        let actual = Relative::parse(unsafe {
            std::slice::from_raw_parts(raw.cast::<u8>(), actual_size as usize)
        })?;
        let expected = Relative::parse(unsafe {
            std::slice::from_raw_parts(expected.0.cast::<u8>(), expected_size as usize)
        })?;
        ensure!(
            actual.control & 0x1004 == 0x1004
                && actual.owner == expected.owner
                && actual.group.is_some()
                && (expected.group.is_none() || actual.group == expected.group),
            "private assignment owner/group/protection differs"
        );
        let actual = Acl::parse(actual.dacl.context("private assignment DACL absent")?)?;
        let expected = Acl::parse(
            expected
                .dacl
                .context("private assignment expected DACL absent")?,
        )?;
        ensure!(
            actual.revision == expected.revision
                && actual.aces.len() == expected.aces.len()
                && actual
                    .aces
                    .iter()
                    .zip(&expected.aces)
                    .all(|(a, b)| a.bytes == b.bytes),
            "private assignment exact DACL differs"
        );
        Ok(())
    })();
    let cleanup = if raw.is_null() || unsafe { LocalFree(raw) }.is_null() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "private assignment descriptor cleanup failed"
        ))
    };
    finish(finish(result, cleanup), expected.close())
}

fn state_assignment_mutation_denied(path: &Path) -> Result<()> {
    use std::os::windows::{fs::OpenOptionsExt, io::IntoRawHandle};

    for access in [0x40000, 0x80000] {
        match fs::OpenOptions::new()
            .access_mode(access)
            .custom_flags(0x02200000)
            .open(path)
        {
            Ok(file) => {
                let closed = unsafe { CloseHandle(file.into_raw_handle()) };
                ensure!(
                    closed != 0,
                    "unexpected assignment mutation handle close failed"
                );
                anyhow::bail!("private assignment unexpectedly granted mutation access");
            }
            Err(error) => ensure!(
                error.raw_os_error() == Some(5),
                "private assignment mutation denial differs"
            ),
        }
    }
    Ok(())
}

pub(super) fn native_private_child(parent: &Pin, name: &str, user: &str) -> Result<()> {
    use registry_authority::native::{Attributes, Unicode};
    use std::os::windows::io::AsRawHandle;

    use crate::windows_security::sxs::{
        native_file_abi::NtCreateFile,
        storage::creation::{IoStatus, IoValue},
    };
    parent.require()?;
    let path = parent.path.join(name);
    let name = wide(name);
    let text = Unicode {
        length: ((name.len() - 1) * 2) as u16,
        maximum: (name.len() * 2) as u16,
        buffer: name.as_ptr(),
    };
    let root = parent
        .file
        .as_ref()
        .context("native private parent pin absent")?
        .as_raw_handle();
    let mut descriptor = Descriptor::new(&private_sddl(user, true)?)?;
    let attributes = Attributes {
        length: size_of::<Attributes>() as u32,
        root,
        name: &text,
        flags: 0x1040,
        descriptor: descriptor.0,
        qos: null_mut(),
    };
    let mut raw = null_mut();
    let mut io = IoStatus {
        value: IoValue {
            pointer: usize::MAX,
        },
        information: 0,
    };
    let returned = unsafe {
        NtCreateFile(
            &mut raw,
            0x120080,
            &attributes,
            &mut io,
            null_mut(),
            0x80,
            3,
            2,
            0x200021,
            null_mut(),
            0,
        )
    };
    if returned == 0x103 || io.status() as u32 == 0x103 {
        std::process::abort();
    }
    let result = (|| {
        ensure!(
            returned == 0
                && io.status() as u32 == 0
                && io.information == 2
                && !raw.is_null()
                && raw as isize != -1,
            "native private child returned={:08X} completed={:08X} information={}",
            returned as u32,
            io.status() as u32,
            io.information
        );
        let mut pin = Pin::open(&path, true)?;
        let result = private(
            pin.file
                .as_ref()
                .context("native private child pin absent")?,
            user,
            true,
        );
        finish(result, pin.close())
    })();
    let cleanup = if raw.is_null() || raw as isize == -1 || unsafe { CloseHandle(raw) } != 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("native private child handle close failed"))
    };
    finish(finish(result, cleanup), descriptor.close())
}
