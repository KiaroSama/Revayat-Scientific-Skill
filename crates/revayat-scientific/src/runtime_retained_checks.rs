//! Assertions reached by an existing registration, against actual server/client result seams.
use super::*;
fn output() -> CommandOutput {
    CommandOutput {
        code: 7,
        stdout: b"PRIVATE_COMPLETED_BYTES\nfailures:\ncontrolled owned test failed\n".to_vec(),
        stderr: vec![255],
    }
}
pub(super) fn check_completed_retention() {
    let mut spec = CommandSpec::new("controlled-unused-program");
    spec.max_output = 128;
    // The real server combines a completed result and independent late cleanup failure.
    let response = super::super::completed_response(
        Ok(output()),
        Err(anyhow::anyhow!("controlled late cleanup")),
        false,
        None,
    );
    assert_eq!(
        response.code,
        Some(7),
        "genuinely completed code/bytes must survive late cleanup failure"
    );
    assert!(
        !response.cleanup_complete && response.error.is_some() && response.deadline_idle.is_none()
    );
    let mut wire = Vec::new();
    let encoded = serde_json::to_vec(&Event::Complete(response)).unwrap();
    wire.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    wire.extend(encoded);
    let decoded = decode_events(&mut wire).unwrap().pop().unwrap();
    let Event::Complete(response) = decoded else {
        panic!("missing retained complete response")
    };
    let error = completed_result(
        response,
        &spec,
        Err(anyhow::anyhow!("controlled owner finalization")),
    )
    .unwrap_err();
    assert_retained(&error);
    // A server's normal completed response must likewise survive a later client finish failure.
    let response = super::super::completed_response(Ok(output()), Ok(()), false, None);
    let error = completed_result(
        response,
        &spec,
        Err(anyhow::anyhow!("controlled owner finalization")),
    )
    .unwrap_err();
    assert_retained(&error);
    // Even an erroneously optimistic caller cannot turn cleanup=false into success.
    let response = super::super::completed_response(
        Ok(output()),
        Err(anyhow::anyhow!("controlled late cleanup")),
        false,
        None,
    );
    assert_retained(&completed_result(response, &spec, Ok(())).unwrap_err());
    let response = super::super::completed_response(Ok(output()), Ok(()), false, None);
    assert_retained(&completed_result(response, &spec, Ok(())).unwrap_err());
    let response = super::super::completed_response(
        Ok(output()),
        Err(std::io::Error::from_raw_os_error(libc::ENOENT).into()),
        false,
        None,
    );
    assert_eq!(response.code, Some(7));
    assert_ne!(response.error.as_deref(), Some("not-found"));
    let error = completed_result(response, &spec, Ok(())).unwrap_err();
    assert_retained(&error);
    assert!(!crate::runtime::is_missing_executable(&error));
    let response = super::super::completed_response(Ok(output()), Ok(()), true, None);
    let completed = completed_result(response, &spec, Ok(())).unwrap();
    assert_eq!(completed.code, output().code);
    assert_eq!(completed.stdout, output().stdout);
    assert_eq!(completed.stderr, output().stderr);

    for idle in [false, true] {
        spec.idle_timeout = Some(Duration::from_millis(17));
        let limit = if idle {
            spec.idle_timeout.unwrap()
        } else {
            spec.timeout
        };
        let response = super::super::completed_response(
            Err(DeadlineExceeded { idle, limit }.into()),
            Err(anyhow::anyhow!("controlled cleanup uncertainty")),
            false,
            Some(libc::SIGKILL),
        );
        let error = completed_result(
            response,
            &spec,
            Err(anyhow::anyhow!("controlled owner finalization")),
        )
        .unwrap_err();
        assert_eq!(error.downcast_ref::<DeadlineExceeded>().unwrap().idle, idle);
        assert_eq!(
            error.downcast_ref::<DeadlineExceeded>().unwrap().limit,
            limit
        );
        assert!(crate::runtime::retained_command_output(&error).is_none());
        assert!(
            error
                .downcast_ref::<crate::runtime::CleanupFailure>()
                .is_some()
        );
    }
    spec.idle_timeout = None;
    for (stage, errno) in [
        ("owned-status-query", libc::EINTR),
        ("owned-group-cleanup", libc::EPERM),
        ("owned-child-reap", libc::ECHILD),
    ] {
        let owned = crate::runtime::with_cleanup::<CommandOutput>(
            Err(DeadlineExceeded {
                idle: false,
                limit: spec.timeout,
            }
            .into()),
            Err(anyhow::Error::new(std::io::Error::from_raw_os_error(errno)).context(stage)),
        );
        let response = super::super::completed_response(
            owned,
            Err(anyhow::anyhow!(
                "controlled later container settlement failure"
            )),
            false,
            None,
        );
        let stage = stage.strip_prefix("owned-").unwrap();
        assert_eq!(
            response.error,
            Some(format!("operation-{stage}-os-{errno}")),
            "late container cleanup must not mask the observed original owned stage"
        );
        let error = completed_result(
            response,
            &spec,
            Err(anyhow::anyhow!("controlled owner finalization")),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<DeadlineExceeded>().unwrap().limit,
            spec.timeout
        );
        let summary = crate::migration::execution::discovery_failure_summary(&error);
        assert!(
            summary.contains(&format!("runtime={stage} os_error={errno}")),
            "{summary}"
        );
        assert!(
            error
                .downcast_ref::<crate::runtime::CleanupFailure>()
                .is_some()
        );
        assert!(crate::runtime::retained_command_output(&error).is_none());
    }
    let normal = || super::super::completed_response(Ok(output()), Ok(()), true, None);
    let mut malformed = Vec::new();
    let mut value = normal();
    value.cleanup_complete = false;
    malformed.push(value);
    let mut value = normal();
    value.error = Some("operation-unknown".into());
    malformed.push(value);
    let mut value = normal();
    value.cleanup_complete = false;
    value.error = Some("cancelled".into());
    malformed.push(value);
    let mut value = normal();
    value.cleanup_complete = false;
    value.error = Some("operation-unknown".into());
    value.deadline_idle = Some(false);
    malformed.push(value);
    let mut value = normal();
    value.code = None;
    value.error = Some("output-limit".into());
    malformed.push(value);
    let mut value = normal();
    value.stdout.clear();
    value.stderr.clear();
    value.code = None;
    malformed.push(value);
    let mut value = normal();
    value.stdout = vec![0; 129];
    value.stderr.clear();
    malformed.push(value);
    let mut value = normal();
    value.stdout = vec![0; 90];
    value.stderr = vec![0; 39];
    malformed.push(value);
    let mut value = normal();
    value.code = None;
    value.stdout.clear();
    value.stderr.clear();
    value.error = Some("PRIVATE_RESPONSE_CATEGORY".into());
    malformed.push(value);
    let mut value = normal();
    value.code = None;
    value.stdout.clear();
    value.stderr.clear();
    value.error = Some("operation-unknown".into());
    value.deadline_idle = Some(true);
    malformed.push(value);
    for value in malformed {
        let error = completed_result(value, &spec, Ok(())).unwrap_err();
        assert!(error.downcast_ref::<DeadlineExceeded>().is_none());
        assert!(crate::runtime::retained_command_output(&error).is_none());
        for text in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#}"),
        ] {
            assert!(
                !text.contains("PRIVATE_RESPONSE_CATEGORY")
                    && !text.contains("PRIVATE_COMPLETED_BYTES")
            );
        }
    }
}
fn assert_retained(error: &anyhow::Error) {
    assert!(
        error
            .downcast_ref::<crate::runtime::CleanupFailure>()
            .is_some()
    );
    let retained = crate::runtime::retained_command_output(error)
        .expect("completed bytes are inspectable after failed cleanup");
    assert_eq!(retained.code, output().code);
    assert_eq!(retained.stdout, output().stdout);
    assert_eq!(retained.stderr, output().stderr);
    for safe in [
        error.to_string(),
        format!("{error:#}"),
        format!("{error:?}"),
    ] {
        assert!(!safe.contains("PRIVATE_COMPLETED_BYTES"));
    }
}
