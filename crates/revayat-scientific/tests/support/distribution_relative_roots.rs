//! Run relative-root admission against an actual export with an isolated current directory.
use std::{fs, path::Path, process::Command};

const WORKER: &str = "REVAYAT_TEST_RELATIVE_DISTRIBUTION_ROOT";

pub fn is_worker(test: &str) -> bool {
    std::env::var(WORKER).as_deref() == Ok(test)
}

pub fn run(test: &str) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("skills/revayat-scientific");
    fs::create_dir_all(source.join("references")).unwrap();
    fs::write(
        source.join("SKILL.md"),
        b"---\nname: revayat-scientific\ndescription: Fixture\n---\n",
    )
    .unwrap();
    fs::write(source.join("references/kept.md"), b"retained reference").unwrap();
    fs::write(source.join("local-note.txt"), b"owner note outside payload").unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .current_dir(&root)
        .env(WORKER, test);
    for name in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
    ] {
        command.env_remove(name);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "relative-root production boundary failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(source.join(Path::new("local-note.txt")).is_file());
}
