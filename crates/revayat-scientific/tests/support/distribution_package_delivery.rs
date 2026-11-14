// Public delivery cases stay in the integration-suite root through include!.
include!("distribution_package_commands.rs");
include!("distribution_package_acl.rs");
#[cfg(windows)]
fn assert_quota_companion_layout(executable: &Path, directory: &Path) -> Result<()> {
    let worker = executable.parent().unwrap().join("revayat-quota-worker.exe");
    assert_eq!(fs::read(&worker)?, fs::read(env!("CARGO_BIN_EXE_revayat-quota-worker"))?);
    let refused = delivery_command(&worker, directory, &["--arbitrary-program"], None)?;
    assert!(!refused.success());
    assert!(refused.stdout.is_empty());
    let expected: &[u8] = if cfg!(target_arch = "x86_64") { b"WINDOWS_QUOTA_FAILURE phase=native kind=control_or_cleanup\n" } else { b"Native quota controls require Windows x64.\n" };
    assert_eq!(refused.stderr, expected);
    Ok(())
}
#[test]
fn test_metadata_and_references() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    revayat_scientific::validation::validate_family_layout(root)?;
    let skill = root.join("skills/revayat-scientific");
    let text = fs::read_to_string(skill.join("SKILL.md"))?;
    assert!(text.contains("name: revayat-scientific\n"));
    assert!(text.lines().count() < 500);
    let links = regex::Regex::new(r"\]\(((?:references|assets|bin)/[^)]+)\)")?;
    for link in links.captures_iter(&text) {
        assert!(skill.join(link[1].split('#').next().unwrap()).is_file());
    }
    for name in [".codex-plugin/plugin.json", ".claude-plugin/plugin.json", ".cursor-plugin/plugin.json"] {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(root.join(name))?)?;
        assert_eq!(value["name"], "revayat-scientific");
        assert_eq!(value["version"], "2.0.0");
        assert!(value["keywords"].as_array().unwrap().iter().any(|v| v == "rust"));
        assert!(root.join(value["skills"].as_str().unwrap()).is_dir());
    }
    Ok(())
}
#[test]
fn test_install_launchers_replacement_and_logs() -> Result<()> {
    let f = Fixture::new();
    let project = f.root.join("project فارسی");
    fs::create_dir(&project)?;
    let hosts = [".claude", ".agents", ".cursor", ".kiro", ".cline", ".hermes", ".opencode"];
    for host in hosts {
        fs::create_dir(project.join(host))?;
    }
    let binary = Path::new(env!("CARGO_BIN_EXE_revayat-scientific"));
    let output = delivery_command(binary, &project,
        &["install", "--scope", "project", "--path", project.to_str().unwrap()], Some(&f.repo))?;
    assert!(output.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8_lossy(&output.stdout).matches("Installed revayat-scientific:").count(), 7);
    let payload = d::Payload::collect(&f.source, Some(Path::new(env!("CARGO_BIN_EXE_revayat-scientific"))))?;
    for host in hosts {
        let destination = project.join(host).join("skills").join(NAME);
        assert!(destination.is_dir());
        for row in &payload.files {
            assert_eq!(fs::read(destination.join(&row.relative))?, fs::read(&row.source)?);
        }
    }
    let target = project.join(".agents/skills").join(NAME);
    #[cfg(windows)]
    assert_directory_inherits_access(&target)?;
    fs::write(target.join("local-note.txt"), b"preserve on replacement")?;
    let refused = delivery_command(binary, &project,
        &["install", "--agent", "codex", "--scope", "project", "--path", project.to_str().unwrap()], Some(&f.repo))?;
    assert!(!refused.success());
    assert_eq!(fs::read(target.join("local-note.txt"))?, b"preserve on replacement");
    let updated = delivery_command(binary, &project,
        &["install", "--agent", "codex", "--scope", "project", "--path", project.to_str().unwrap(), "--force"], Some(&f.repo))?;
    assert!(updated.success());
    let backups = fs::read_dir(project.join(".agents/skill-backups"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path().join("local-note.txt"))?, b"preserve on replacement");
    let target = f.root.join("installed");
    let output = delivery_command(binary, &f.root,
        &["install", "--dest", target.to_str().unwrap()], Some(&f.repo))?;
    assert!(output.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let executable = target.join("bin").join(if cfg!(windows) { "revayat-scientific.exe" } else { "revayat-scientific" });
    let output = delivery_command(&executable, &f.root, &["--version"], None)?;
    assert!(output.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("2.0.0"));
    assert!(target.join("LICENSE").is_file());
    #[cfg(unix)]
    assert_companion_layout(&executable, &f.root)?;
    #[cfg(windows)]
    assert_quota_companion_layout(&executable, &f.root)?;
    fs::write(target.join("local-note.txt"), b"preserve on replacement")?;
    let refused = delivery_command(binary, &f.root,
        &["install", "--dest", target.to_str().unwrap()], Some(&f.repo))?;
    assert!(!refused.success());
    assert_eq!(fs::read(target.join("local-note.txt"))?, b"preserve on replacement");
    let updated = delivery_command(binary, &f.root,
        &["install", "--dest", target.to_str().unwrap(), "--force"], Some(&f.repo))?;
    assert!(updated.success());
    let backups = fs::read_dir(f.root.join("skill-backups"))?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path().join("local-note.txt"))?, b"preserve on replacement");
    for _ in 0..2 {
        let help = delivery_command(&executable, &f.root, &["build", "--help"], None)?;
        assert!(help.success());
        assert!(String::from_utf8_lossy(&help.stdout).contains("--output-dir"));
    }
    // The native CLI records operations in the caller's working directory.
    let logs = f.root.join("logs");
    let entries = fs::read_dir(&logs)?.collect::<std::io::Result<Vec<_>>>()?;
    let mut help_logs = 0;
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        assert!(name.contains("_UTC") && name.ends_with(".log"));
        let text = fs::read_to_string(entry.path())?;
        assert!(!text.contains("preserve on replacement"));
        if text.contains("command=build") { help_logs += 1; }
    }
    assert_eq!(help_logs, 2);
    let missing = delivery_command(&executable, &f.root, &["lint", "absent.tex"], None)?;
    assert!(!missing.success());
    assert_document_commands(&executable, &f.root)?;
    Ok(())
}
#[test]
fn test_archive_is_self_contained() -> Result<()> {
    let f = Fixture::new();
    let binary = f.root.join("native-binary");
    fs::write(&binary, b"synthetic executable payload")?;
    let target = f.repo.join("bundle.skill");
    #[cfg(any(unix, windows))]
    {
        let error = d::package(&f.source, &f.repo, &target, Some(&binary)).unwrap_err();
        assert!(error.to_string().contains("required companion"));
        assert!(!target.exists());
        fs::write(&target, b"approved previous archive")?;
        assert!(d::package(&f.source, &f.repo, &target, Some(&binary)).is_err());
        assert_eq!(fs::read(&target)?, b"approved previous archive");
        fs::remove_file(&target)?;
        let companion = f.root.join(if cfg!(windows) { "revayat-quota-worker.exe" } else { "revayat-process-owner" });
        let outside = f.root.join("foreign-owner");
        fs::write(&outside, b"unrelated owner bytes")?;
        link(&outside, &companion);
        assert!(d::package(&f.source, &f.repo, &target, Some(&binary)).is_err());
        assert_eq!(fs::read(&outside)?, b"unrelated owner bytes");
        assert!(!target.exists());
        fs::remove_file(&companion)?;
        fs::create_dir(&companion)?;
        assert!(d::package(&f.source, &f.repo, &target, Some(&binary)).is_err());
        assert!(!target.exists());
        fs::remove_dir(&companion)?;
        fs::write(companion, b"synthetic owner payload")?;
    }
    d::package(&f.source, &f.repo, &target, Some(&binary))?;
    let mut archive = zip::ZipArchive::new(fs::File::open(target)?)?;
    for name in ["SKILL.md", "LICENSE", "NOTICE.md", "references/contract.md"] {
        assert_eq!(archive.by_name(&format!("{NAME}/{name}"))?.unix_mode().unwrap() & 0o777, 0o644);
    }
    let name = format!("{NAME}/bin/{}", if cfg!(windows) { "revayat-scientific.exe" } else { "revayat-scientific" });
    let mut file = archive.by_name(&name)?;
    assert_eq!(file.unix_mode().unwrap() & 0o777, 0o755);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"synthetic executable payload");
    drop(file);
    #[cfg(any(unix, windows))]
    {
        let companion = if cfg!(windows) { "revayat-quota-worker.exe" } else { "revayat-process-owner" };
        let mut file = archive.by_name(&format!("{NAME}/bin/{companion}"))?;
        assert_eq!(file.unix_mode().unwrap() & 0o777, 0o755);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"synthetic owner payload");
    }
    let actual = f.repo.join("actual.skill");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap().canonicalize()?;
    let source = repository.join("skills").join(NAME);
    d::package(&source, &repository, &actual, Some(Path::new(env!("CARGO_BIN_EXE_revayat-scientific"))))?;
    let extracted = f.root.join("extracted");
    fs::create_dir(&extracted)?;
    let mut actual = zip::ZipArchive::new(fs::File::open(actual)?)?;
    for relative in [
        "SKILL.md", "LICENSE", "NOTICE.md", "assets/Dockerfile.tex",
        "references/terminology.md", "references/docx.md", "references/pdf-processing.md",
        "references/evidence-and-terminology.md",
    ] {
        let mut bytes = Vec::new();
        actual.by_name(&format!("{NAME}/{relative}"))?.read_to_end(&mut bytes)?;
        assert_eq!(bytes, fs::read(source.join(relative))?);
    }
    for index in 0..actual.len() {
        let mut member = actual.by_index(index)?;
        let name = member.name()?.into_owned();
        assert!(!name.contains("/logs/") && !name.contains("/tests/") && !name.contains("__pycache__"));
        let relative = Path::new(&name);
        assert!(!relative.is_absolute());
        assert!(relative.components().all(|part| matches!(part, std::path::Component::Normal(_))));
        let path = extracted.join(relative);
        fs::create_dir_all(path.parent().unwrap())?;
        let mut output = fs::File::create(&path)?;
        std::io::copy(&mut member, &mut output)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(member.unix_mode().unwrap() & 0o777))?;
        }
    }
    let executable = extracted.join(NAME).join("bin").join(if cfg!(windows) { "revayat-scientific.exe" } else { "revayat-scientific" });
    #[cfg(unix)]
    assert_companion_layout(&executable, &f.root)?;
    #[cfg(windows)]
    assert_quota_companion_layout(&executable, &f.root)?;
    let fixtures = repository.join("tests/fixtures");
    let document = fixtures.join("journal.tex");
    let terms = fixtures.join("terms-empty.tsv");
    let manifest = fixtures.join("manifest-empty.txt");
    let lint = delivery_command(&executable, &f.root, &[
        "lint", document.to_str().unwrap(), "--level", "journal",
        "--terms", terms.to_str().unwrap(), "--manifest", manifest.to_str().unwrap(), "--strict",
    ], None)?;
    assert!(lint.success(), "{}{}", String::from_utf8_lossy(&lint.stderr), String::from_utf8_lossy(&lint.stdout));
    let missing = delivery_command(&executable, &f.root, &["lint", "absent.tex"], None)?;
    assert!(!missing.success());
    assert_document_commands(&executable, &f.root)?;
    Ok(())
}
#[test]
fn archive_corruption_is_rejected_before_previous_delivery_changes() {
    let f = Fixture::new();
    let target = f.repo.join("approved.skill");
    fs::write(&target, "approved").unwrap();
    assert!(package_observed(&f.source, &f.repo, &target, None, |at, path| {
        if at == B::Staged {
            let mut file = fs::OpenOptions::new().write(true).open(path)?;
            file.write_all(b"damaged archive")?;
        }
        Ok(())
    }).is_err());
    assert_eq!(fs::read(target).unwrap(), b"approved");
}
