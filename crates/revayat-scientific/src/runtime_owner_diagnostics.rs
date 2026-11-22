//! Closed cleanup evidence. No child output, paths, identities or credentials are recorded.
use super::Response;
use anyhow::Result;
use std::{
    ffi::CString,
    fmt,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AccountingFailure {
    RegistrationAfterStop,
    PeerEof,
    PeerFailed,
    PeerTransport,
    Other,
}
impl AccountingFailure {
    fn label(self) -> &'static str {
        match self {
            Self::RegistrationAfterStop => "registration-after-stop",
            Self::PeerEof => "peer-eof",
            Self::PeerFailed => "peer-failed",
            Self::PeerTransport => "peer-transport",
            Self::Other => "other",
        }
    }
    fn parse(label: &str) -> Option<Self> {
        [
            Self::RegistrationAfterStop,
            Self::PeerEof,
            Self::PeerFailed,
            Self::PeerTransport,
            Self::Other,
        ]
        .into_iter()
        .find(|failure| failure.label() == label)
    }
}
impl fmt::Display for AccountingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ownership accounting failed ({})", self.label())
    }
}
impl std::error::Error for AccountingFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CleanupDiagnostic {
    mask: u8,
    accounting: Option<AccountingFailure>,
}
impl CleanupDiagnostic {
    const OWNED: u8 = 1;
    const DESCENDANTS: u8 = 2;
    const CONTAINERS: u8 = 4;
    const ACK: u8 = 8;
    const ROOT: u8 = 16;

    pub(super) fn collect(
        owned: bool,
        descendants_failed: bool,
        container_sweep_failed: bool,
        acknowledgment: &Result<()>,
        root: &Result<()>,
    ) -> Self {
        let mut mask = 0;
        for (failed, flag) in [
            (!owned, Self::OWNED),
            (descendants_failed, Self::DESCENDANTS),
            (container_sweep_failed, Self::CONTAINERS),
            (acknowledgment.is_err(), Self::ACK),
            (root.is_err(), Self::ROOT),
        ] {
            if failed {
                mask |= flag;
            }
        }
        let accounting = root.as_ref().err().map(|error| {
            error
                .downcast_ref::<AccountingFailure>()
                .copied()
                .unwrap_or(AccountingFailure::Other)
        });
        Self { mask, accounting }
    }

    fn suffix(self) -> String {
        format!(
            ";cleanup={:02x};accounting={}",
            self.mask,
            self.accounting.map_or("none", AccountingFailure::label)
        )
    }

    pub(super) fn attach(self, response: &mut Response) {
        if self.mask != 0 && !response.cleanup_complete {
            response
                .error
                .get_or_insert_with(|| "operation-unknown".into())
                .push_str(&self.suffix());
            FixtureDiagnostic::Cleanup(self).record();
        }
    }
}

enum FixtureDiagnostic {
    Cleanup(CleanupDiagnostic),
    RegistrationDenied,
}

pub(super) fn registration_denied() {
    FixtureDiagnostic::RegistrationDenied.record();
}

impl FixtureDiagnostic {
    fn record(&self) {
        // Explicit test opt-in only; diagnostic failure never alters owner cleanup.
        if std::env::var("REVAYAT_TEST_OWNER_DIAGNOSTICS").as_deref() != Ok("1") {
            return;
        }
        if let Some(directory) = std::env::var_os("SCIENTIFIC_EVIDENCE_DIR") {
            let _ = self.record_at(Path::new(&directory));
        }
    }

    fn record_at(&self, directory: &Path) -> Result<()> {
        let directory = evidence_directory(directory)?;
        let (slots, level, message) = match self {
            Self::Cleanup(diagnostic) => (
                if diagnostic.mask & CleanupDiagnostic::ROOT != 0 {
                    0..8
                } else {
                    8..24
                },
                "ERROR",
                format!("cleanup-unverified{}", diagnostic.suffix()),
            ),
            Self::RegistrationDenied => (24..32, "INFO", "registration-after-stop-denied".into()),
        };
        // Fixed create-new slots bound total evidence to 32 small records without
        // blocking the owner on a lock. Reserve root slots so nested evidence
        // cannot consume every slot before the accounting origin is observed.
        for slot in slots {
            let name = CString::new(format!("runtime-owner-cleanup-{slot:02}.log"))?;
            // SAFETY: the directory descriptor is owned and the fixed C string is
            // valid. O_EXCL refuses occupied slots, including links and hard links.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            let opened = if descriptor < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                // SAFETY: successful openat returned a new owned descriptor.
                Ok(unsafe { File::from_raw_fd(descriptor) })
            };
            match opened {
                Ok(mut file) => {
                    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                    let timestamp = crate::runtime::utc_timestamp(seconds)?;
                    writeln!(file, "[{timestamp}] [{level}] [runtime-owner] {message}")?;
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn evidence_directory(path: &Path) -> Result<File> {
    anyhow::ensure!(path.is_absolute(), "diagnostic directory must be absolute");
    let mut directory = File::open("/")?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => CString::new(name.as_bytes())?,
            _ => anyhow::bail!("diagnostic directory must be normalized"),
        };
        // SAFETY: each lookup is relative to the previous owned directory; reject
        // every link and retain the final handle so later path swaps cannot redirect writes.
        let mut descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0
            && components.peek().is_none()
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
        {
            // SAFETY: only the final missing component may be created beneath
            // the pinned existing parent; no recursive creation or link traversal.
            let created = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            anyhow::ensure!(
                created == 0
                    || std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists,
                "diagnostic directory cannot be created"
            );
            // SAFETY: re-open even after EEXIST so a raced link is never followed.
            descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        anyhow::ensure!(descriptor >= 0, "diagnostic directory is unavailable");
        // SAFETY: successful openat returned a new owned descriptor.
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(directory)
}

/// Legacy closed labels remain valid; diagnostic suffixes have one canonical form.
pub(super) fn split_category(label: &str) -> Option<(&str, Option<CleanupDiagnostic>)> {
    let Some((category, suffix)) = label.split_once(';') else {
        return Some((label, None));
    };
    let (mask, accounting) = suffix
        .strip_prefix("cleanup=")?
        .split_once(";accounting=")?;
    let mask_value = u8::from_str_radix(mask, 16).ok()?;
    if mask_value == 0
        || mask_value > 31
        || format!("{mask_value:02x}") != mask
        || mask_value & CleanupDiagnostic::DESCENDANTS != 0
            && mask_value & CleanupDiagnostic::CONTAINERS != 0
    {
        return None;
    }
    let accounting = if accounting == "none" {
        None
    } else {
        Some(AccountingFailure::parse(accounting)?)
    };
    if (mask_value & CleanupDiagnostic::ROOT != 0) != accounting.is_some() {
        return None;
    }
    Some((
        category,
        Some(CleanupDiagnostic {
            mask: mask_value,
            accounting,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_survives_downstream_cleanup_failures_without_private_error_text() {
        let root = Err(anyhow::Error::new(AccountingFailure::RegistrationAfterStop)
            .context("PRIVATE_TOKEN_PATH_CHILD_TEXT"));
        let diagnostic = CleanupDiagnostic::collect(
            false,
            true,
            false,
            &Err(anyhow::anyhow!("PRIVATE_ACK_TEXT")),
            &root,
        );
        let suffix = diagnostic.suffix();
        assert_eq!(suffix, ";cleanup=1b;accounting=registration-after-stop");
        let label = format!("cancelled{suffix}");
        assert_eq!(
            split_category(&label),
            Some(("cancelled", Some(diagnostic)))
        );
        let temp = tempfile::tempdir().unwrap();
        for _ in 0..40 {
            FixtureDiagnostic::Cleanup(diagnostic)
                .record_at(temp.path())
                .unwrap();
        }
        let paths: Vec<_> = std::fs::read_dir(temp.path()).unwrap().collect();
        assert_eq!(paths.len(), 8);
        for entry in paths {
            let bytes = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            assert!(bytes.contains("[ERROR] [runtime-owner] cleanup-unverified"));
            assert!(bytes.contains(&suffix));
            assert!(!bytes.contains("PRIVATE"));
            assert!(bytes.len() < 200);
        }
    }

    #[test]
    fn diagnostic_parser_rejects_unknown_or_contradictory_suffixes() {
        assert_eq!(
            split_category("operation-child-reap"),
            Some(("operation-child-reap", None))
        );
        for suffix in [
            ";cleanup=00;accounting=none",
            ";cleanup=20;accounting=none",
            ";cleanup=1;accounting=none",
            ";cleanup=0A;accounting=none",
            ";cleanup=06;accounting=none",
            ";cleanup=01;accounting=peer-eof",
            ";cleanup=10;accounting=none",
            ";cleanup=10;accounting=PRIVATE_TOKEN",
            ";cleanup=10;accounting=peer-eof;private=payload",
        ] {
            assert!(split_category(&format!("operation-unknown{suffix}")).is_none());
        }
    }

    #[test]
    fn evidence_rejects_linked_directories_and_never_overwrites_occupied_slots() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("evidence");
        std::fs::create_dir(&directory).unwrap();
        let linked = temp.path().join("linked");
        std::os::unix::fs::symlink(&directory, &linked).unwrap();
        let event = FixtureDiagnostic::RegistrationDenied;
        assert!(event.record_at(&linked).is_err());
        std::fs::create_dir(directory.join("nested")).unwrap();
        assert!(event.record_at(&linked.join("nested")).is_err());
        assert!(event.record_at(Path::new("relative")).is_err());
        let missing = temp.path().join("missing");
        event.record_at(&missing).unwrap();
        assert!(missing.join("runtime-owner-cleanup-24.log").is_file());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&missing).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let missing_parent = temp.path().join("missing-parent");
        assert!(event.record_at(&missing_parent.join("final")).is_err());
        assert!(!missing_parent.exists());
        let occupied = directory.join("runtime-owner-cleanup-24.log");
        let preserved = temp.path().join("preserved");
        std::fs::write(&preserved, b"private existing bytes").unwrap();
        std::os::unix::fs::symlink(&preserved, occupied).unwrap();
        event.record_at(&directory).unwrap();
        assert_eq!(
            std::fs::read(&preserved).unwrap(),
            b"private existing bytes"
        );
        let logged =
            std::fs::read_to_string(directory.join("runtime-owner-cleanup-25.log")).unwrap();
        assert!(logged.contains("[INFO] [runtime-owner] registration-after-stop-denied"));
        assert!(!logged.contains("private"));
    }

    #[test]
    fn nested_evidence_cannot_exhaust_reserved_root_slots() {
        let temp = tempfile::tempdir().unwrap();
        let nested = CleanupDiagnostic::collect(false, false, false, &Ok(()), &Ok(()));
        let root = CleanupDiagnostic::collect(
            true,
            false,
            false,
            &Ok(()),
            &Err(anyhow::Error::new(AccountingFailure::PeerFailed)),
        );
        for _ in 0..40 {
            FixtureDiagnostic::Cleanup(nested)
                .record_at(temp.path())
                .unwrap();
            FixtureDiagnostic::RegistrationDenied
                .record_at(temp.path())
                .unwrap();
        }
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 24);
        for _ in 0..40 {
            FixtureDiagnostic::Cleanup(root)
                .record_at(temp.path())
                .unwrap();
        }
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 32);
        let logged =
            std::fs::read_to_string(temp.path().join("runtime-owner-cleanup-00.log")).unwrap();
        assert!(logged.contains("cleanup=10;accounting=peer-failed"));
    }
}
