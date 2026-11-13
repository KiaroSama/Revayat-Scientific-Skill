//! Fixed image admission and suspended owned diagnostic launch.
use super::*;
/// The only permitted subject is the same-profile built registry-authority sibling, fixed --oracle.
pub fn observe_authority_entry(image: &Path) -> Result<EntryProof> {
    observe_authority_entry_observed(image, |_| Ok(()))
}
pub fn observe_authority_entry_observed(
    image: &Path,
    observe: impl FnMut(DebugBoundary) -> Result<()>,
) -> Result<EntryProof> {
    observe_fixed(image, false, observe)
}
pub fn observe_explicit_id2_dispatch(image: &Path) -> Result<EntryProof> {
    observe_fixed(image, true, |_| Ok(()))
}
fn observe_fixed(
    image: &Path,
    dispatch: bool,
    mut observe: impl FnMut(DebugBoundary) -> Result<()>,
) -> Result<EntryProof> {
    require_host()?;
    ensure!(
        size_of::<Event>() == 176 && size_of::<Region>() == 48 && size_of::<Creation>() == 72,
        "debug x64 ABI differs"
    );
    let executable = std::env::current_exe()?;
    let parent = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("debug current image directory missing"))?;
    let parent = if parent.file_name().is_some_and(|name| name == "deps") {
        parent.parent().unwrap()
    } else {
        parent
    };
    let expected = parent.join(if dispatch {
        "startup-explicit-id2.exe"
    } else {
        "registry-authority.exe"
    });
    plain_path(image)?;
    ensure!(
        image == expected,
        "debug subject path is not the fixed authority sibling"
    );
    ensure!(
        identity::path_object_id(image)? == identity::path_object_id(&expected)?,
        "debug subject is not same-profile authority"
    );
    let identity = identity::file_identity(image, Some(8 * 1024 * 1024))?;
    let mut held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(image)?;
    ensure!(
        identity::object_id(&held)? == identity.identity,
        "debug image open identity differs"
    );
    let mut bytes = Vec::new();
    (&mut held)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == identity.size
            && sha256(&bytes) == identity.sha256
            && identity::file_identity(image, Some(8 * 1024 * 1024))? == identity,
        "debug held image fingerprint differs"
    );
    let parsed = PeImage::parse(&bytes, 1)?;
    if dispatch {
        parsed.qualify_explicit_id2()?;
    } else {
        parsed.qualify_rust_authority()?;
    }
    let (entry, image_size) = (parsed.entry, parsed.image_size);
    bytes.fill(0);
    let started = Instant::now();
    let job = WindowsJob::create(JobLimits {
        processes: 1,
        cpu_seconds: 10,
        ..JobLimits::default()
    })?;
    let source = image
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut command = format!(
        "\"{}\"{}",
        image.display(),
        if dispatch { "" } else { " --oracle" }
    )
    .encode_utf16()
    .chain(Some(0))
    .collect::<Vec<_>>();
    ensure!(
        !source[..source.len() - 1].contains(&0),
        "debug image path has terminator"
    );
    let cwd = parent
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut child = api::ProcessInfo::default();
    let (mut standard, transport) = abi::StandardHandles::new(dispatch)?;
    let startup = api::StartupEx {
        startup: api::Startup {
            size: size_of::<api::StartupEx>() as u32,
            flags: 0x100,
            input: standard.handles[0],
            output: standard.handles[1],
            error: standard.handles[2],
            ..Default::default()
        },
        attributes: standard.list(),
    };
    // Exactly three handles: NUL stdin plus fixed capture writers for ID2, NUL outputs for oracle.
    let success = unsafe {
        api::CreateProcessW(
            source.as_ptr(),
            command.as_mut_ptr(),
            null_mut(),
            null_mut(),
            1,
            0x08000000 | 0x80000 | 4 | 2,
            null_mut(),
            cwd.as_ptr(),
            &startup,
            &mut child,
        )
    };
    let error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let mut owner = Owner {
        process: child.process,
        thread: child.thread,
        original_process: null_mut(),
        original_thread: null_mut(),
        pid: child.pid,
        tid: child.tid,
        job,
        pending: None,
        generations: None,
        files: EventCleanup::default(),
        started,
        events: 0,
        creation: false,
        exited: false,
        exit_seen: false,
        retirement_attempted: false,
        termination_requested: false,
        event_file_released: false,
        initial: false,
        entry,
        image_size,
        expected: identity.identity,
        base: 0,
        dispatch: dispatch.then(debug_dispatch::DispatchImages::new),
        transport,
    };
    let execution = (|| {
        ensure!(
            success != 0 && !child.process.is_null() && !child.thread.is_null(),
            "create fixed debug child failed winerror={error:?}"
        );
        let process = duplicate(owner.process)?;
        owner.original_process = std::mem::replace(&mut owner.process, process);
        let thread = duplicate(owner.thread)?;
        owner.original_thread = std::mem::replace(&mut owner.thread, thread);
        standard.close()?;
        ensure!(
            unsafe { AssignProcessToJobObject(owner.job.handle, owner.process) } != 0,
            "debug child job attachment failed"
        );
        owner.job.state.advance(Lifecycle::Suspended)?;
        owner.job.state.advance(Lifecycle::Attached)?;
        owner.job.state.advance(Lifecycle::Qualified)?;
        ensure!(
            unsafe { NtResumeProcess(owner.process) } == 0,
            "debug child resume failed"
        );
        owner.job.state.advance(Lifecycle::Running)?;
        owner.run(&mut observe)
    })();
    let cleanup = if success != 0 {
        owner.cleanup(&mut observe)
    } else {
        let mut errors = Vec::new();
        for handle in [&mut owner.thread, &mut owner.process] {
            let value = std::mem::replace(handle, null_mut());
            if let Err(error) = close(value) {
                errors.push(error);
            }
        }
        if let Err(error) = owner.job.finish() {
            errors.push(error);
        }
        if let Some(transport) = &mut owner.transport
            && let Err(error) = transport.close()
        {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Failures { errors }.into())
        }
    };
    let standard_cleanup = standard.close();
    let cleanup = match (cleanup, standard_cleanup) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(first), Err(second)) => Err(Failures {
            errors: vec![first, second],
        }
        .into()),
    };
    drop(held);
    match (execution, cleanup) {
        (Ok(mut proof), Ok(())) => {
            proof.reaped = true;
            Ok(proof)
        }
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(Failures {
            errors: vec![primary, cleanup],
        }
        .into()),
    }
}
