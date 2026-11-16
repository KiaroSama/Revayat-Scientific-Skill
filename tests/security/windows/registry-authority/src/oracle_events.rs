//! Actual oracle assertions and raw observations; the harness owner finalizes cleanup.
use crate::protocol::{basic, denied, identity, record, token_fields};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

const OWNER: &str = "tests/security/windows/registry-authority/lib/registry_authority::protocol::tests::source_generated_oracle";
const PREDICATE: &str =
    "tests/security/windows/registry-authority/lib/registry_authority::protocol::";
const FILE_NAME: &str = "oracle-observations.json";
const LIMIT: usize = 16 * 1024 * 1024;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid fixed oracle observations",
    )
}
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/:_.-".contains(&byte))
}
fn append(output: &mut String, value: &str, limit: usize) -> io::Result<()> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|size| size > limit)
    {
        return Err(invalid());
    }
    output.push_str(value);
    Ok(())
}
fn directory(path: &Path) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = metadata.file_type().is_symlink();
    if !path.is_absolute() || !metadata.is_dir() || reparse || path.canonicalize()? != path {
        return Err(invalid());
    }
    Ok(path.to_owned())
}

struct Journal {
    output: Option<PathBuf>,
    events: String,
    seen: BTreeSet<String>,
    count: usize,
}
impl Journal {
    fn new(output: Option<&Path>) -> io::Result<Self> {
        Ok(Self {
            output: output.map(directory).transpose()?,
            events: String::new(),
            seen: BTreeSet::new(),
            count: 0,
        })
    }
    // Called only after the actual predicate/wire assertion has returned normally.
    fn observe(&mut self, row: &[&str], sequence: usize) -> io::Result<()> {
        if sequence != self.count + 1 || sequence > 41 {
            return Err(invalid());
        }
        let (case, predicate) = row_identity(row)?;
        if !safe_name(&case) || self.seen.contains(&case) {
            return Err(invalid());
        }
        let event = format!(
            "{}{{\"case_id\":\"{case}\",\"parent_id\":\"{OWNER}\",\"sequence\":{sequence},\"invokes_ids\":[\"{PREDICATE}{predicate}\"],\"obligation_ids\":[\"ORACLE-{sequence:03}\"],\"source\":\"execution\",\"outcome\":\"passed\",\"exit\":0,\"cleanup_complete\":false,\"assertions_complete\":true,\"variants\":[],\"check_results\":[]}}",
            if self.count == 0 { "" } else { "," }
        );
        append(&mut self.events, &event, LIMIT)?;
        self.seen.insert(case);
        self.count = sequence;
        Ok(())
    }
    fn complete(&self) -> io::Result<String> {
        if self.count != 41 || self.seen.len() != 41 {
            return Err(invalid());
        }
        let mut output = format!(
            "{{\"schema\":1,\"population\":\"oracle\",\"owner_case_id\":\"{OWNER}\",\"events\":["
        );
        append(&mut output, &self.events, LIMIT)?;
        append(&mut output, "]}\n", LIMIT)?;
        Ok(output)
    }
    fn finish(self) -> io::Result<()> {
        let bytes = self.complete()?;
        if let Some(path) = self.output {
            let path = directory(&path)?.join(FILE_NAME);
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(bytes.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
        }
        Ok(())
    }
}

fn row_identity(row: &[&str]) -> io::Result<(String, &'static str)> {
    let Some(family) = row.first().copied() else {
        return Err(invalid());
    };
    let (fields, predicate) = match family {
        "token" if row.len() == 5 => (3, "token_fields"),
        "denied" if row.len() == 4 => (2, "denied"),
        "basic" if row.len() == 6 => (4, "basic"),
        "wire" if row.len() == 5 && matches!(row[1], "primary" | "descendant") => (3, "record"),
        "identity" if row.len() == 6 => {
            let label = match (row[1], row[2], row[3], row[4]) {
                ("0", "6", "020000004100", "2") => "latin-A",
                ("0", "20", "1000000052006500670069007300740072007900", "16") => "Registry",
                ("0", "8", "040000003dd842de", "4") => "surrogate-pair",
                ("0", "6", "020000000000", "2") => "embedded-NUL",
                ("0", "6", "0200000000d8", "2") => "lone-surrogate",
                ("0", "3", "00000000", "0") => "truncated-header",
                ("0", "4097", "00000000", "0") => "oversized-return",
                ("0", "6", "040000004100", "4") => "short-body",
                ("0", "5", "0100000041", "1") => "odd-count",
                _ => return Err(invalid()),
            };
            return Ok((format!("registry-oracle::identity/{label}"), "identity"));
        }
        _ => return Err(invalid()),
    };
    for value in &row[1..=fields] {
        if family == "wire" && matches!(*value, "primary" | "descendant") {
            continue;
        }
        let number = value.parse::<u32>().map_err(|_| invalid())?;
        if number.to_string() != *value {
            return Err(invalid());
        }
    }
    Ok((
        format!("registry-oracle::{family}/{}", row[1..=fields].join("/")),
        predicate,
    ))
}
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("fixture ASCII"), 16)
                .expect("fixture hex")
        })
        .collect()
}
fn assert_rows(source: &str, journal: &mut Journal) {
    let mut count = 0;
    for line in source.lines() {
        let row = line.split('\t').collect::<Vec<_>>();
        let n = |index: usize| row[index].parse::<u32>().expect("oracle integer");
        let actual = match row[0] {
            "token" => token_fields(n(1), n(2), n(3)),
            "denied" => denied(n(1), n(2) as usize),
            "basic" => basic(n(1), n(2), n(3), n(4)),
            "identity" => identity(n(1), n(2) as usize, &hex(row[3]), n(4) as usize).is_ok(),
            "wire" => {
                assert_eq!(
                    record(row[1], n(2), n(3))
                        .expect("valid source record")
                        .as_bytes(),
                    hex(row[4])
                );
                count += 1;
                journal.observe(&row, count).expect("observed wire row");
                continue;
            }
            _ => panic!("unknown oracle case"),
        };
        assert_eq!(actual, row[row.len() - 1] == "1", "{line}");
        count += 1;
        journal
            .observe(&row, count)
            .expect("observed predicate row");
    }
    assert_eq!(count, 41);
}

pub(crate) fn source_generated_oracle() {
    let output = std::env::var_os("REVAYAT_ORACLE_EVENT_DIR").map(PathBuf::from);
    let mut journal = Journal::new(output.as_deref()).expect("owned oracle journal directory");
    assert_rows(&crate::oracle::generate(), &mut journal);
    journal
        .finish()
        .expect("complete oracle observation journal");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn row_observations_follow_assertions_and_never_claim_owner_cleanup() {
        let source = crate::oracle::generate();
        let mut journal = Journal::new(None).expect("unrouted journal");
        assert_rows(&source, &mut journal);
        let payload = journal.complete().expect("complete actual rows");
        assert_eq!(payload.matches("\"source\":\"execution\"").count(), 41);
        assert_eq!(payload.matches("\"cleanup_complete\":false").count(), 41);
        assert_eq!(payload.matches("\"assertions_complete\":true").count(), 41);
        assert!(payload.contains("\"case_id\":\"registry-oracle::token/0/0/0\""));
        assert!(payload.contains("\"case_id\":\"registry-oracle::identity/surrogate-pair\""));
        assert!(payload.contains("\"case_id\":\"registry-oracle::wire/descendant/256/256\""));
        assert!(payload.contains("\"obligation_ids\":[\"ORACLE-041\"]"));
        assert!(!payload.contains("tested_sha") && !payload.contains("run_id"));
        let mut unreached = Journal::new(None).expect("unrouted journal");
        let wrong = source.replacen("token\t0\t0\t0\t0", "token\t0\t0\t0\t1", 1);
        assert!(catch_unwind(AssertUnwindSafe(|| assert_rows(&wrong, &mut unreached))).is_err());
        assert_eq!(unreached.count, 0);
        assert!(unreached.complete().is_err());
    }

    #[test]
    fn fixed_journal_publication_refuses_existing_file_and_invalid_directory() {
        let root = Scratch::new();
        let mut journal = Journal::new(Some(&root.0)).expect("owned directory");
        assert_rows(&crate::oracle::generate(), &mut journal);
        journal.finish().expect("first raw journal");
        let path = root.0.join(FILE_NAME);
        let original = std::fs::read(&path).expect("raw journal");
        let mut collision = Journal::new(Some(&root.0)).expect("same directory");
        assert_rows(&crate::oracle::generate(), &mut collision);
        assert_eq!(
            collision.finish().unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(Journal::new(Some(std::path::Path::new("relative"))).is_err());
        assert!(Journal::new(Some(&root.0.join("missing"))).is_err());
        assert!(Journal::new(Some(&path)).is_err());
        let mut partial = Journal::new(Some(&root.0)).unwrap();
        partial.observe(&["token", "0", "0", "0", "0"], 1).unwrap();
        assert!(partial.finish().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn event_identity_and_material_bounds_fail_before_mutation() {
        let mut journal = Journal::new(None).unwrap();
        let first = ["token", "0", "0", "0", "0"];
        journal.observe(&first, 1).unwrap();
        let before = journal.events.clone();
        assert!(journal.observe(&first, 2).is_err());
        assert_eq!(journal.events, before);
        assert!(journal.observe(&["private\"sentinel"], 2).is_err());
        assert!(
            journal
                .observe(&["identity", "0", "6", "unknown", "2", "0"], 2)
                .is_err()
        );
        assert!(!safe_name("quote\""));
        assert!(!safe_name("line\n"));
        assert!(!safe_name("back\\slash"));
        let mut bytes = String::from("123");
        append(&mut bytes, "45", 5).unwrap();
        assert!(append(&mut bytes, "6", 5).is_err());
        assert_eq!(bytes, "12345");
    }

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            for _ in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "registry-oracle-events-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path.canonicalize().unwrap()),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create owned oracle fixture: {error}"),
                }
            }
            panic!("unique oracle fixture unavailable");
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("owned fixture cleanup");
        }
    }
}
