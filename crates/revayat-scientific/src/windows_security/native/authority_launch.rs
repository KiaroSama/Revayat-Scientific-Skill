//! Closed fixed-subject preparation. Every returned process remains qualified and suspended.
use super::*;
use super::{authority_completion::NativeCompletion, registry_scope::Plan};
use crate::{
    identity,
    windows_security::quota_controls::{Role, WorkerPlan},
};
use std::{
    ffi::OsStr,
    fs::File,
    os::windows::{fs::OpenOptionsExt, io::IntoRawHandle},
    path::PathBuf,
};

pub(super) enum LaunchKind<'a> {
    Machine(Plan),
    Quota {
        plan: &'a WorkerPlan,
        directory: tempfile::TempDir,
    },
}
fn close_file(file: File) -> Result<()> {
    let raw = file.into_raw_handle();
    ensure!(
        unsafe { CloseHandle(raw) } != 0,
        "close prepared native machine image failed"
    );
    Ok(())
}
fn environment(root: &OsStr, scratch: &Path) -> Result<Vec<u16>> {
    let mut output = Vec::new();
    for (name, value) in [
        ("LOCALAPPDATA", scratch.as_os_str()),
        ("SystemRoot", root),
        ("TEMP", scratch.as_os_str()),
        ("TMP", scratch.as_os_str()),
        ("WINDIR", root),
    ] {
        let units = value.encode_wide().collect::<Vec<_>>();
        ensure!(
            !units.is_empty() && !units.contains(&0),
            "invalid fixed machine environment value"
        );
        output.extend(name.encode_utf16());
        output.push(61);
        output.extend(units);
        output.push(0);
    }
    ensure!(
        output.len() < 32766,
        "fixed machine environment exceeds bound"
    );
    output.push(0);
    Ok(output)
}
/// Closed argv excludes quotes/NUL; quoting still doubles a final backslash
/// before its closing quote, including the fixed owned drive argument D:\\.
pub(super) fn command_line(target: &Path, arguments: &[String]) -> Result<Vec<u16>> {
    let mut output = Vec::new();
    for value in std::iter::once(target.as_os_str()).chain(arguments.iter().map(OsStr::new)) {
        let units = value.encode_wide().collect::<Vec<_>>();
        ensure!(
            !units.is_empty() && !units.contains(&0) && !units.contains(&34),
            "invalid closed native authority argument"
        );
        if !output.is_empty() {
            output.push(32);
        }
        output.push(34);
        output.extend(&units);
        let trailing = units.iter().rev().take_while(|unit| **unit == 92).count();
        output.extend(std::iter::repeat_n(92, trailing));
        output.push(34);
        ensure!(
            output.len() < 32766,
            "native authority command exceeds bound"
        );
    }
    output.push(0);
    Ok(output)
}
fn quota_source(image: &Path, expected: &identity::Fingerprint) -> Result<()> {
    let executable = std::env::current_exe()?;
    let sibling =
        crate::executable_paths::binary_directory(&executable)?.join("revayat-quota-worker.exe");
    plain_path(&sibling)?;
    ensure!(
        identity::file_identity(&sibling, Some(8 * 1024 * 1024))? == *expected
            && image.file_name() == sibling.file_name(),
        "quota source is not the fixed sibling image"
    );
    Ok(())
}
fn protect_quota_directory(directory: &Path, sid: &str) -> Result<()> {
    crate::windows_security::package_sid(sid)?;
    plain_path(directory)?;
    ensure!(directory.is_dir(), "quota prepared root is not a directory");
    // Deny package write/data/attributes, delete-child, DELETE, WRITE_DAC and
    // WRITE_OWNER. The package receives only read/execute, with medium NW.
    apply_policy(
        directory,
        &format!(
            "D:P(D;OICI;0x000d0156;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)(A;OICI;0x1200a9;;;{sid})S:(ML;OICI;NW;;;ME)"
        ),
    )
}

pub(super) fn prepare(
    owner: &mut NativeCompletion<'_>,
    image: &Path,
    expected: &identity::Fingerprint,
    profile: &Profile,
    kind: LaunchKind<'_>,
) -> Result<PathBuf> {
    let (machine, quota) = match kind {
        LaunchKind::Machine(plan) => {
            ensure!(
                matches!(plan, Plan::Original | Plan::Modified | Plan::Restored),
                "unsupported machine authority launch plan"
            );
            ensure!(
                owner.prepared.is_none(),
                "native authority preparation already owned"
            );
            (Some(plan), None)
        }
        LaunchKind::Quota { plan, directory } => {
            if owner.prepared.is_some() {
                return crate::runtime::with_cleanup(
                    Err(anyhow::anyhow!(
                        "native authority preparation already owned"
                    )),
                    directory.close().map_err(Into::into),
                );
            }
            // Transfer the actual fresh owner before any fallible plan check.
            owner.prepared = Some(directory);
            (None, Some(plan))
        }
    };
    let sid = profile.sid_text()?;
    let (name, arguments) = if let Some(plan) = quota {
        plan.validate()?;
        ensure!(
            plan.role == Role::Primary && plan.package == sid,
            "quota primary/profile binding differs"
        );
        quota_source(image, expected)?;
        ("revayat-quota-worker.exe", plan.arguments(Role::Primary)?)
    } else {
        (
            "registry-authority.exe",
            machine
                .unwrap()
                .argument()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
    };
    owner.observer.prepare(&sid)?;
    if quota.is_none() {
        owner.prepared = Some(
            tempfile::Builder::new()
                .prefix("revayat-machine-authority-")
                .tempdir()?,
        );
    }
    let directory = owner.prepared.as_ref().unwrap().path().to_owned();
    // Keep the quota directory's native object pinned through all preparation;
    // no external path is adopted and every independent close is reported.
    let held_directory = if quota.is_some() {
        Some(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x02000000 | 0x00200000)
                .open(&directory)?,
        )
    } else {
        None
    };
    let operation = (|| {
        let scratch = if let Some(plan) = quota {
            plain_path(&directory)?;
            ensure!(
                directory == plan.readonly_root
                    && held_directory.as_ref().unwrap().metadata()?.is_dir()
                    && identity::object_id(held_directory.as_ref().unwrap())?
                        == identity::path_object_id(&plan.readonly_root)?
                    && std::fs::read_dir(&directory)?.next().transpose()?.is_none()
                    && plan.auxiliary_image == directory.join(name),
                "quota preparation directory/object/argv binding differs"
            );
            protect_quota_directory(&directory, &sid)?;
            PathBuf::from(&plan.scratch)
        } else {
            protect_scratch(&directory, &sid)?;
            directory.clone()
        };
        let target = directory.join(name);
        owner.source = Some(if quota.is_some() {
            authority_image::AuthorityImage::open_quota(image, expected)?
        } else {
            authority_image::AuthorityImage::open(image, expected)?
        });
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&target)?;
        let copied: Result<()> = (|| {
            std::io::copy(owner.source.as_mut().unwrap().file()?, &mut file)?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })();
        let closed = close_file(file);
        crate::runtime::with_cleanup(copied, closed)?;
        let actual = identity::file_identity(&target, Some(8 * 1024 * 1024))?;
        ensure!(
            expected.same_bytes(&actual),
            "prepared machine authority image differs"
        );
        protect_image(&target, &sid)?;
        owner.target = Some(if quota.is_some() {
            authority_image::AuthorityImage::open_quota(&target, &actual)?
        } else {
            authority_image::AuthorityImage::open(&target, &actual)?
        });
        (owner.stdout, owner.stdout_writer) = pipe()?;
        (owner.stderr, owner.stderr_writer) = pipe()?;
        let security = Security {
            size: size_of::<Security>() as u32,
            descriptor: null_mut(),
            inherit: 1,
        };
        let nul = wide("NUL");
        owner.stdin = Owned::checked(unsafe {
            CreateFileW(nul.as_ptr(), 0x80000000, 3, &security, 3, 0x80, null_mut())
        })?;
        owner.attributes = Some(Attributes::new()?);
        let mut capabilities = Capabilities {
            sid: profile.sid,
            capabilities: null_mut(),
            count: 0,
            reserved: 0,
        };
        let mut lpac = 1u32;
        let mut handles = [owner.stdin.0, owner.stdout_writer.0, owner.stderr_writer.0];
        let attributes = owner.attributes.as_mut().unwrap();
        attributes.set(
            0x20009,
            (&mut capabilities as *mut Capabilities).cast(),
            size_of::<Capabilities>(),
        )?;
        attributes.set(0x2000f, (&mut lpac as *mut u32).cast(), 4)?;
        attributes.set(0x20002, handles.as_mut_ptr().cast(), size_of_val(&handles))?;
        let startup = StartupEx {
            startup: Startup {
                size: size_of::<StartupEx>() as u32,
                flags: 0x100,
                input: owner.stdin.0,
                output: owner.stdout_writer.0,
                error: owner.stderr_writer.0,
                ..Default::default()
            },
            attributes: attributes.data.as_mut_ptr().cast(),
        };
        let executable = wide(&target);
        let mut command = command_line(&target, &arguments)?;
        let cwd = wide(&scratch);
        let root = std::env::var_os("SystemRoot").context("SystemRoot is required")?;
        let mut environment = environment(&root, &scratch)?;
        owner.source.as_mut().unwrap().require(image)?;
        owner.target.as_mut().unwrap().require(&target)?;
        owner.restricted = restricted_primary()?;
        owner.descriptor = Descriptor::new(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GA;;;{sid})S:(ML;;NW;;;LW)"
        ))?;
        let process_security = Security {
            size: size_of::<Security>() as u32,
            descriptor: owner.descriptor.0,
            inherit: 0,
        };
        let mut info = ProcessInfo::default();
        owner.observer.before_create()?;
        let created = unsafe {
            CreateProcessAsUserW(
                owner.restricted.0,
                executable.as_ptr(),
                command.as_mut_ptr(),
                &process_security,
                &process_security,
                1,
                0x80000 | 0x400 | 8 | 4,
                environment.as_mut_ptr().cast(),
                cwd.as_ptr(),
                &startup,
                &mut info,
            )
        };
        let creation = creation_result(
            created,
            !info.process.is_null()
                && info.process as isize != -1
                && !info.thread.is_null()
                && info.thread as isize != -1,
            "CreateProcessAsUserW",
            || unsafe { GetLastError() },
        );
        owner.creation(info, created);
        creation?;
        owner.job.state.advance(Lifecycle::Suspended)?;
        ensure!(
            unsafe { AssignProcessToJobObject(owner.job.handle, owner.process.0) } != 0,
            "assign machine authority job failed"
        );
        owner.assigned = true;
        owner.job.state.advance(Lifecycle::Attached)?;
        let mut member = 0;
        ensure!(
            unsafe { IsProcessInJob(owner.process.0, owner.job.handle, &mut member) } != 0
                && member != 0,
            "machine authority job membership differs"
        );
        remove_privileges(owner.process.0)?;
        owner.job.state.advance(Lifecycle::Qualified)?;
        authority_policy::observe(owner.process.0, owner.observer)?;
        owner
            .profile_registry
            .prepare(owner.process.0, &sid, |record| {
                owner.observer.token_metadata(record)
            })?;
        authority_policy::observe(owner.process.0, owner.observer)?;
        owner
            .observer
            .token_metadata(&default_metadata(owner.process.0)?)?;
        let status = startup_access::observe_child(owner.process.0, &sid, |lines| {
            owner.observer.startup_registry(lines)
        })?;
        owner.observer.registry_status(status)?;
        if let Some(held) = held_directory.as_ref() {
            ensure!(
                identity::object_id(held)? == identity::path_object_id(&directory)?,
                "quota prepared directory identity changed"
            );
        }
        Ok(target)
    })();
    let cleanup = held_directory.map_or(Ok(()), close_file);
    crate::runtime::with_cleanup(operation, cleanup)
}
