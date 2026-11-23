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
    for name in [
        "plugin.json",
        ".antigravity-plugin/plugin.json",
        ".codex-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".cursor-plugin/plugin.json",
    ] {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(root.join(name))?)?;
        assert_eq!(value["name"], "revayat-scientific", "{name}");
        assert_eq!(value["version"], "2.2.0", "{name}");
        assert_eq!(value["license"], "GPL-3.0-or-later", "{name}");
        assert!(
            value["keywords"].as_array().unwrap().iter().any(|v| v == "rust"),
            "{name}"
        );
        if let Some(skills_path) = value.get("skills").and_then(serde_json::Value::as_str) {
            assert!(root.join(skills_path).is_dir(), "{name}");
        }
    }
    let root_plugin: serde_json::Value = serde_json::from_slice(&fs::read(root.join("plugin.json"))?)?;
    assert_eq!(root_plugin["$schema"], "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json");
    let root_allowed = [
        "$schema", "name", "version", "description", "author",
        "homepage", "repository", "license", "keywords", "extensions",
    ];
    for key in root_plugin.as_object().unwrap().keys() {
        assert!(root_allowed.contains(&key.as_str()), "plugin.json unexpected key: {key}");
    }
    let agy_plugin: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(".antigravity-plugin/plugin.json"))?)?;
    assert_eq!(agy_plugin["$schema"], "https://antigravity.google/schemas/v1/plugin.json");
    assert_eq!(agy_plugin["displayName"], "Revayat Scientific");
    let prompts = agy_plugin["suggestedPrompts"].as_array().unwrap();
    assert!((1..=3).contains(&prompts.len()));
    assert!(prompts.iter().all(|p| !p.as_str().unwrap_or("").trim().is_empty()));
    let agy_allowed = [
        "$schema", "name", "displayName", "display_name", "description", "version",
        "disabled", "logo", "suggestedPrompts", "suggested_prompts", "skills",
        "author", "homepage", "repository", "license", "keywords", "extensions",
    ];
    for key in agy_plugin.as_object().unwrap().keys() {
        assert!(agy_allowed.contains(&key.as_str()), ".antigravity-plugin/plugin.json unexpected key: {key}");
    }
    if let Some(logo) = agy_plugin.get("logo").and_then(serde_json::Value::as_str) {
        assert!(root.join(logo).is_file(), "missing Antigravity logo: {logo}");
    }
    let claude_mkt: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(".claude-plugin/marketplace.json"))?)?;
    assert_eq!(claude_mkt["name"], "revayat-scientific-skill");
    assert_eq!(claude_mkt["plugins"][0]["name"], "revayat-scientific");
    assert_eq!(claude_mkt["plugins"][0]["source"], "./");
    assert_eq!(claude_mkt["plugins"][0]["version"], "2.2.0");
    let codex_mkt: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(".agents/plugins/marketplace.json"))?)?;
    assert_eq!(codex_mkt["name"], "revayat-scientific-skill");
    assert_eq!(codex_mkt["plugins"][0]["name"], "revayat-scientific");
    assert_eq!(codex_mkt["plugins"][0]["source"]["source"], "url");
    assert_eq!(
        codex_mkt["plugins"][0]["source"]["url"],
        "https://github.com/KiaroSama/Revayat-Scientific-Skill.git"
    );
    let cursor_mkt: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(".cursor-plugin/marketplace.json"))?)?;
    assert_eq!(cursor_mkt["name"], "revayat-scientific-skill");
    assert_eq!(cursor_mkt["plugins"][0]["name"], "revayat-scientific");
    assert_eq!(cursor_mkt["plugins"][0]["source"], "./");
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("2.2.0"));
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
fn payload_exclusion_fixture() -> Result<(Fixture, [&'static str; 14])> {
    let f = Fixture::new();
    let excluded = [
        "references/lower/secrets.md",
        "references/upper/Secrets.MD",
        "references/lower/logs/private.txt",
        "references/upper/LOGS/private.txt",
        "references/lower/fonts/private.ttf",
        "references/upper/FONTS/private.ttf",
        "references/lower/AGENTS.md",
        "references/upper/agents.MD",
        "assets/lower/worker.py",
        "assets/upper/worker.PY",
        "assets/lower/worker.ps1",
        "assets/upper/worker.PS1",
        "assets/lower/worker.log",
        "assets/upper/worker.LOG",
    ];
    for relative in excluded {
        let path = f.source.join(relative);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, b"excluded local payload")?;
    }
    fs::write(f.source.join("references/KEPT.MD"), b"eligible reference")?;
    let collected = d::Payload::collect(&f.source, None)?;
    for relative in excluded {
        assert!(
            !collected
                .files
                .iter()
                .any(|row| row.relative == Path::new(relative)),
            "excluded local payload was collected: {relative}"
        );
    }
    for relative in [
        "SKILL.md",
        "LICENSE",
        "NOTICE.md",
        "references/KEPT.MD",
        "references/contract.md",
    ] {
        assert!(
            collected
                .files
                .iter()
                .any(|row| row.relative == Path::new(relative)),
            "eligible payload was omitted: {relative}"
        );
    }
    Ok((f, excluded))
}
#[test]
fn payload_collection_excludes_case_variants_before_publication() -> Result<()> {
    payload_exclusion_fixture()?;
    Ok(())
}
#[test]
fn test_archive_is_self_contained() -> Result<()> {
    let (f, excluded) = payload_exclusion_fixture()?;
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
    for relative in excluded {
        assert!(
            archive.by_name(&format!("{NAME}/{relative}")).is_err(),
            "excluded payload was published: {relative}"
        );
    }
    let mut kept = Vec::new();
    archive
        .by_name(&format!("{NAME}/references/KEPT.MD"))?
        .read_to_end(&mut kept)?;
    assert_eq!(kept, b"eligible reference");
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
    let mut damaged = false;
    assert!(package_observed(&f.source, &f.repo, &target, None, |at, path| {
        if at == B::Staged {
            let mut file = fs::OpenOptions::new().write(true).open(path)?;
            file.write_all(b"damaged archive")?;
            damaged = true;
        }
        Ok(())
    }).is_err());
    assert!(damaged, "the actual archive corruption boundary must execute");
    assert_eq!(fs::read(&target).unwrap(), b"approved");
    let mut changed = false;
    let inconsistent = package_observed(&f.source, &f.repo, &target, None, |at, path| {
        if at == B::Staged {
            use std::io::{Seek, SeekFrom};
            let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
            let offset = archive.by_name(&format!("{NAME}/SKILL.md"))?.header_start();
            drop(archive);
            let mut file = fs::OpenOptions::new().write(true).open(path)?;
            file.seek(SeekFrom::Start(offset + 30 + NAME.len() as u64 + 1))?;
            file.write_all(b"X")?;
            changed = true;
        }
        Ok(())
    });
    assert!(changed, "the actual archive header mutation must execute");
    assert!(
        inconsistent.is_err(),
        "a mismatched local archive filename was published"
    );
    assert_eq!(fs::read(&target).unwrap(), b"approved");
}
