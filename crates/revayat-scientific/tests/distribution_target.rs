//! Cross-packaging selects companions from the target, not the packaging host.
use revayat_scientific::distribution::{Payload, package_for_target};
use std::{fs, path::Path};

#[test]
fn cross_target_archives_select_exact_companion_and_executable_modes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("SKILL.md"),
        "---\nname: revayat-scientific\ndescription: Fixture\n---\n",
    )
    .unwrap();
    for (target, main, companion) in [
        (
            "x86_64-pc-windows-msvc",
            "revayat-scientific.exe",
            "revayat-quota-worker.exe",
        ),
        (
            "aarch64-unknown-linux-gnu",
            "revayat-scientific",
            "revayat-process-owner",
        ),
        (
            "x86_64-apple-darwin",
            "revayat-scientific",
            "revayat-process-owner",
        ),
    ] {
        let binaries = root.join(target);
        fs::create_dir(&binaries).unwrap();
        let binary = binaries.join(main);
        fs::write(&binary, b"target-main").unwrap();
        assert!(Payload::collect_for_target(&source, &binary, target).is_err());
        fs::write(binaries.join(companion), b"target-companion").unwrap();
        let payload = Payload::collect_for_target(&source, &binary, target).unwrap();
        let actual = payload
            .files
            .iter()
            .filter(|file| file.relative.starts_with("bin"))
            .map(|file| file.relative.clone())
            .collect::<Vec<_>>();
        let mut expected = vec![
            Path::new("bin").join(main),
            Path::new("bin").join(companion),
        ];
        expected.sort();
        assert_eq!(actual, expected);
        let output = root.join(format!("{target}.zip"));
        package_for_target(&source, &root, &output, &binary, target).unwrap();
        let mut zip = zip::ZipArchive::new(fs::File::open(output).unwrap()).unwrap();
        for name in [main, companion] {
            let entry = zip
                .by_name(&format!("revayat-scientific/bin/{name}"))
                .unwrap();
            assert_eq!(entry.unix_mode().unwrap() & 0o777, 0o755);
        }
    }
}
