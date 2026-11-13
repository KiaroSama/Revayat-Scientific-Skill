//! Fixed LPAC execution and exhaustive post-launch owned cleanup.
use super::*;
use crate::windows_security::preparation::{self, SourceEntry};

fn validate_authority_source(image: &Path) -> Result<()> {
    preparation::runtime_progress("leaf-check", "before", 0)?;
    preparation::assert_source_path(image).map_err(preparation::controller_error)?;
    ensure!(image.is_file(), "authority image is missing");
    preparation::runtime_progress("leaf-check", "after", 1)
}

/// Reporting can fail before any authority child exists. Explicitly finalize the
/// already acquired preparation owners instead of hiding close failures in Drop.
fn reporting_cleanup_before_launch(
    primary: anyhow::Error,
    observer: &mut impl AuthorityObserver,
    profile: &mut Profile,
    registry: &mut super::super::fixture::RegistryFixture,
    prepared: tempfile::TempDir,
    foreign: tempfile::TempDir,
    input: Option<&mut authority_image::AuthorityImage>,
) -> Result<String> {
    let mut errors = vec![primary];
    // No child has been created, so no authority process can retain these resources.
    let observed = observer.after_reap(true);
    let uncertain = observed.is_err();
    for result in [
        observed,
        input.map_or(Ok(()), |input| input.close()),
        registry.close(),
        prepared.close().map_err(Into::into),
        foreign.close().map_err(Into::into),
        if uncertain {
            profile.retain()
        } else {
            profile.close()
        },
    ] {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.len() == 1 {
        Err(errors.remove(0))
    } else {
        Err(crate::windows_security::activation::Failures { errors }.into())
    }
}

/// Run only the fixed native verifier. A host launch cannot satisfy this API.
/// Success requires the primary AND descendant's actual token/registry proofs.
pub fn run_registry_authority(image: &Path) -> Result<String> {
    run_observed(image, &mut NoObserver)
}
pub(crate) fn run_observed(image: &Path, observer: &mut impl AuthorityObserver) -> Result<String> {
    validate_authority_source(image)?;
    let profile = Profile::new()?;
    run_profile(image, observer, profile)
}
pub fn run_owned_registry_authority(
    image: &Path,
    view: &super::super::state::NativeRunView,
) -> Result<String> {
    view.require()?;
    validate_authority_source(image)?;
    let profile = Profile::new_owned(view)?;
    run_profile(image, &mut NoObserver, profile)
}
fn run_profile(
    image: &Path,
    observer: &mut impl AuthorityObserver,
    mut profile: Profile,
) -> Result<String> {
    let sid = match profile.sid_text() {
        Ok(sid) => sid,
        Err(primary) => return retain_cleanup(Err(primary), usize::from(profile.close().is_err())),
    };
    if let Err(primary) = observer.prepare(&sid) {
        return retain_cleanup(Err(primary), usize::from(profile.close().is_err()));
    }
    let network = super::super::network::NetworkControls::new()?;
    let mut registry = super::super::fixture::RegistryFixture::new(&sid)?;
    let foreign = tempfile::Builder::new()
        .prefix("revayat-private-control-")
        .tempdir()?;
    let foreign_file = foreign.path().join("private-sentinel");
    std::fs::write(&foreign_file, b"owned private sentinel\0\r\n")?;
    super::super::fixture::protect_foreign(foreign.path(), &sid)?;
    super::super::fixture::protect_foreign(&foreign_file, &sid)?;
    let foreign_identity = crate::identity::file_identity(&foreign_file, None)?;
    let prepared = tempfile::Builder::new()
        .prefix("revayat-authority-")
        .tempdir()?;
    protect_scratch(prepared.path(), &sid)?;
    let target = prepared.path().join("registry-authority.exe");
    if let Err(primary) = preparation::runtime_progress("copy-authority", "before", 0) {
        return reporting_cleanup_before_launch(
            primary,
            observer,
            &mut profile,
            &mut registry,
            prepared,
            foreign,
            None,
        );
    }
    let source = crate::identity::file_identity(image, Some(8 * 1024 * 1024))?;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&target)?;
    let mut input = authority_image::AuthorityImage::open(image, &source)?;
    std::io::copy(input.file()?, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    drop(output);
    let copied = crate::identity::file_identity(&target, Some(8 * 1024 * 1024))?;
    ensure!(
        source.same_bytes(&copied)
            && crate::identity::file_identity(image, Some(8 * 1024 * 1024))? == source,
        "authority image changed during preparation"
    );
    // A value is produced only after the held source copy, flush, sync and both
    // fingerprint checks succeeded. This is completion evidence, not the copy plan.
    let reporting = preparation::measure_runtime_copy(
        "copy-authority",
        std::iter::once(Ok(SourceEntry {
            path: target.clone(),
            is_directory: false,
            is_reparse_point: false,
        })),
        preparation::runtime_progress,
    );
    if let Err(primary) = reporting {
        return reporting_cleanup_before_launch(
            primary,
            observer,
            &mut profile,
            &mut registry,
            prepared,
            foreign,
            Some(&mut input),
        );
    }
    protect_image(&target, &sid)?;
    let mut target_image = authority_image::AuthorityImage::open(&target, &copied)?;
    let (mut stdout, mut stdout_writer) = pipe()?;
    let (mut stderr, mut stderr_writer) = pipe()?;
    let security = Security {
        size: size_of::<Security>() as u32,
        descriptor: null_mut(),
        inherit: 1,
    };
    let nul = wide("NUL");
    let mut stdin = Owned::checked(unsafe {
        CreateFileW(nul.as_ptr(), 0x80000000, 3, &security, 3, 0x80, null_mut())
    })?;
    let mut attributes = Attributes::new()?;
    let mut capabilities = Capabilities {
        sid: profile.sid,
        capabilities: null_mut(),
        count: 0,
        reserved: 0,
    };
    let mut lpac = 1u32;
    let mut handles = [stdin.0, stdout_writer.0, stderr_writer.0];
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
            input: stdin.0,
            output: stdout_writer.0,
            error: stderr_writer.0,
            ..Default::default()
        },
        attributes: attributes.data.as_mut_ptr().cast(),
    };
    let target_wide = wide(&target);
    let mut command = wide(format!("\"{}\"", target.display()));
    let cwd = wide(prepared.path());
    let root = std::env::var_os("SystemRoot").context("SystemRoot is required")?;
    let mut environment = super::creation::authority_environment(
        &root,
        prepared.path(),
        &registry.name,
        &foreign_file,
        &network.ports,
    )?;
    let mut info = ProcessInfo::default();
    let mut job = WindowsJob::create(JobLimits::default())?;
    let mut restricted = Owned(null_mut());
    let mut descriptor = Descriptor(null_mut());
    let mut process = Owned(null_mut());
    let mut thread = Owned(null_mut());
    let mut out = Capture::default();
    let mut err = Capture::default();
    let mut creation_succeeded = false;
    let mut profile_registry = profile_registry::ProfileRegistry::default();
    let execution = (|| {
        input.require(image)?;
        target_image.require(&target)?;
        restricted = restricted_primary()?;
        descriptor = Descriptor::new(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GA;;;{sid})S:(ML;;NW;;;LW)"
        ))?;
        let process_security = Security {
            size: size_of::<Security>() as u32,
            descriptor: descriptor.0,
            inherit: 0,
        };
        observer.before_create()?;
        // SAFETY: live initialized backing storage; exact three-handle allowlist;
        // explicit image/environment/cwd; no execution before attachment/qualification.
        let created = unsafe {
            CreateProcessAsUserW(
                restricted.0,
                target_wide.as_ptr(),
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
        creation_succeeded = created != 0;
        process = Owned::creation_output(info.process);
        thread = Owned::creation_output(info.thread);
        creation?;
        job.state.advance(Lifecycle::Suspended)?;
        ensure!(
            unsafe { AssignProcessToJobObject(job.handle, process.0) } != 0,
            "assign authority job"
        );
        job.state.advance(Lifecycle::Attached)?;
        let mut member = 0;
        ensure!(
            unsafe { IsProcessInJob(process.0, job.handle, &mut member) } != 0 && member != 0,
            "authority job membership mismatch"
        );
        remove_privileges(process.0)?;
        job.state.advance(Lifecycle::Qualified)?;
        profile_registry.prepare(process.0, &sid, |record| observer.token_metadata(record))?;
        let metadata = default_metadata(process.0)?;
        observer.token_metadata(&metadata)?;
        super::super::super::sxs::observe_startup_token(process.0, &sid, |lines| {
            observer.startup_token(lines)
        })?;
        startup_access::observe_child(process.0, &sid, |lines| observer.startup_registry(lines))?;
        observer.before_resume(process.0, &sid, &target)?;
        restricted.close()?;
        descriptor.close()?;
        stdout_writer.close()?;
        stderr_writer.close()?;
        stdin.close()?;
        ensure!(
            unsafe { NtResumeProcess(process.0) } == 0,
            "resume authority"
        );
        job.state.advance(Lifecycle::Running)?;
        let started = Instant::now();
        loop {
            drain(&stdout, &mut out, OUTPUT_LIMIT)?;
            drain(&stderr, &mut err, ERROR_LIMIT)?;
            let wait = unsafe { WaitForSingleObject(process.0, 10) };
            ensure!(wait == 0 || wait == 258, "authority wait failed");
            if wait == 0 {
                break;
            }
            ensure!(
                started.elapsed() < Duration::from_secs(20),
                "authority wall deadline exceeded"
            );
        }
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(process.0, &mut code) } != 0,
            "authority exit query failed"
        );
        // Kill/reap surviving descendants before final EOF, policy restore, or profile deletion.
        job.terminate()?;
        drain(&stdout, &mut out, OUTPUT_LIMIT)?;
        drain(&stderr, &mut err, ERROR_LIMIT)?;
        let output = out.finish(OUTPUT_LIMIT)?;
        let errors = err.finish(ERROR_LIMIT)?;
        ensure!(
            code == 0 && errors.is_empty(),
            "native authority refused containment exit={code:08X} diagnostic={}",
            registry_authority::protocol::failure_summary(errors)
                .as_deref()
                .unwrap_or("unqualified")
        );
        let lines = output.split_inclusive('\n').collect::<Vec<_>>();
        ensure!(
            lines.len() == 2,
            "authority must provide two complete records"
        );
        let child = registry_authority::protocol::fixture_child_record(lines[1].as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid descendant authority frame"))?;
        ensure!(
            child
                == registry_authority::protocol::fixture_record("descendant", 1, 0)
                    .map_err(|_| anyhow::anyhow!("invalid fixed fixture record"))?,
            "owned fixture inventory differs"
        );
        let expected = child.replace("\"role\":\"descendant\"", "\"role\":\"primary\"");
        // Native controls guarantee accessible=0; permissive source-oracle fixtures are not admission.
        ensure!(
            lines[0] == expected && lines[0].starts_with("{\"accessible\":0,"),
            "primary and descendant authority differ"
        );
        input.require(image)?;
        target_image.require(&target)?;
        Ok(output.to_owned())
    })();
    let mut cleanup = Vec::new();
    let mut process_reaped = !creation_succeeded && process.0.is_null();
    // A failed assignment must also reap a still-suspended, not-yet-job-owned child.
    if !process.0.is_null() {
        let wait = unsafe { WaitForSingleObject(process.0, 0) };
        if wait == 258 {
            let killed = unsafe { TerminateProcess(process.0, 125) };
            let waited = unsafe { WaitForSingleObject(process.0, 2000) };
            process_reaped = waited == 0;
            if killed == 0 || waited != 0 {
                cleanup.push("process");
            }
        } else if wait != 0 {
            cleanup.push("process");
        } else {
            process_reaped = true;
        }
    }
    let job_reaped = job.finish().is_ok();
    if !job_reaped {
        cleanup.push("job");
    }
    drop(job);
    if observer.after_reap(process_reaped && job_reaped).is_err() {
        cleanup.push("observer-reap");
    }
    for owned in [
        &mut thread,
        &mut process,
        &mut stdin,
        &mut stdout_writer,
        &mut stderr_writer,
        &mut stdout,
        &mut stderr,
    ] {
        if owned.close().is_err() {
            cleanup.push("handle");
        }
    }
    if restricted.close().is_err() {
        cleanup.push("restricted-token");
    }
    if descriptor.close().is_err() {
        cleanup.push("descriptor");
    }
    drop(attributes);
    out.clear();
    err.clear();
    if input.close().is_err() {
        cleanup.push("source-image");
    }
    if target_image.close().is_err() {
        cleanup.push("target-image");
    }
    match crate::identity::file_identity(&foreign_file, None) {
        Ok(current) if current == foreign_identity => {}
        _ => cleanup.push("private-sentinel"),
    }
    if registry.close().is_err() {
        cleanup.push("registry-fixture");
    }
    if prepared.close().is_err() {
        cleanup.push("scratch");
    }
    if foreign.close().is_err() {
        cleanup.push("private-fixture");
    }
    let profile_keys_closed = profile_registry.close().is_ok();
    if !profile_keys_closed {
        cleanup.push("profile-registry");
    }
    if !profile_keys_closed || !process_reaped || !job_reaped {
        cleanup.push("retained-profile");
        if profile.retain().is_err() {
            cleanup.push("retained-profile-sid");
        }
    } else if profile.close().is_err() {
        cleanup.push("profile");
    }
    retain_cleanup(execution, cleanup.len())
}
