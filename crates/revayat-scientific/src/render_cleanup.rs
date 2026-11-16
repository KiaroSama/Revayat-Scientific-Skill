//! Retry transient Windows profile locks only after the owned process tree is reaped.
use std::{io, path::Path, thread, time::Duration};

pub(super) fn remove_profile(path: &Path) -> io::Result<()> {
    retry(
        || std::fs::remove_dir_all(path),
        |attempt, code| {
            eprintln!("browser cleanup step=profile_remove attempt={attempt} os_error={code}");
            thread::sleep(Duration::from_millis(50));
        },
    )
}

fn retry(
    mut remove: impl FnMut() -> io::Result<()>,
    mut waiting: impl FnMut(usize, i32),
) -> io::Result<()> {
    for attempt in 1..=20 {
        match remove() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => match error.raw_os_error() {
                Some(code @ (5 | 32 | 33)) if attempt < 20 => waiting(attempt, code),
                _ => return Err(error),
            },
        }
    }
    unreachable!("the final removal attempt returns its result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_only_transient_locks_and_preserves_exhausted_error() {
        for code in [5, 32, 33, 87] {
            let mut attempts = 0;
            let mut waits = Vec::new();
            let error = retry(
                || {
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(code))
                },
                |attempt, observed| waits.push((attempt, observed)),
            )
            .unwrap_err();
            let expected = if code == 87 { 1 } else { 20 };
            assert_eq!(attempts, expected);
            assert_eq!(waits.len(), expected - 1);
            assert!(waits.iter().all(|(_, observed)| *observed == code));
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    #[test]
    fn removes_profile_after_the_observed_sharing_handle_closes() {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
        let parent = tempfile::tempdir().unwrap();
        let profile = parent.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        let mut held = Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(0)
                .open(profile.join("held"))
                .unwrap(),
        );
        let mut waits = 0;
        retry(
            || std::fs::remove_dir_all(&profile),
            |_, code| {
                assert!(matches!(code, 5 | 32 | 33));
                waits += 1;
                drop(held.take());
            },
        )
        .unwrap();
        assert_eq!(waits, 1);
        assert!(!profile.exists());
    }
}
