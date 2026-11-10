use revayat_scientific::{fonts, pdf_font};
use std::{collections::BTreeMap, fs, io::Write, path::Path};
fn bundle(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("Vazirmatn-Regular.ttf"), pdf_font::REGULAR).unwrap();
    fs::write(dir.join("Vazirmatn-Bold.ttf"), pdf_font::BOLD).unwrap();
    fs::write(dir.join("OFL.txt"), pdf_font::LICENSE).unwrap();
}
fn files(directory: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), fs::read(entry.path()).unwrap())
        })
        .collect()
}
fn name_variant(font: &[u8], old: &str, new: &str) -> Vec<u8> {
    let encode = |text: &str| {
        text.encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>()
    };
    let (old, new) = (encode(old), encode(new));
    assert_eq!(old.len(), new.len());
    let count = u16::from_be_bytes(font[4..6].try_into().unwrap()) as usize;
    let table = font[12..12 + count * 16]
        .as_chunks::<16>()
        .0
        .iter()
        .find(|row| &row[..4] == b"name")
        .unwrap();
    let start = u32::from_be_bytes(table[8..12].try_into().unwrap()) as usize;
    let end = start + u32::from_be_bytes(table[12..16].try_into().unwrap()) as usize;
    let positions = font[start..end]
        .windows(old.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == old).then_some(start + index))
        .collect::<Vec<_>>();
    assert!(!positions.is_empty(), "the intended name field must exist");
    let mut changed = font.to_vec();
    for index in positions {
        changed[index..index + old.len()].copy_from_slice(&new);
    }
    changed
}
#[test]
fn test_incomplete_existing_delivery_is_not_success() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let d = t.path().join("delivery");
    fs::create_dir(&d).unwrap();
    for name in ["Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf"] {
        fs::write(d.join(name), b"not a validated font").unwrap();
    }
    assert!(fonts::fetch_with_cache(&d, "999.999", true, &t.path().join("cache/999.999")).is_err());
    assert_eq!(fs::read_dir(&d).unwrap().count(), 2);
    let before = files(&d);
    let mut command = revayat_scientific::runtime::CommandSpec::new(
        env!("CARGO_BIN_EXE_revayat-scientific"),
    ).args(["font-fetch", d.to_str().unwrap(), "--offline", "--version", "999.999"]);
    command.timeout = std::time::Duration::from_secs(20);
    command.max_output = 64 * 1024;
    for name in ["XDG_CACHE_HOME", "LOCALAPPDATA"] {
        command.env.insert(name.into(), t.path().join("private cache").into_os_string());
    }
    let output = revayat_scientific::runtime::run(&command).unwrap();
    assert!(!output.success());
    assert_eq!(files(&d), before);
    fonts::fetch_with_cache(&d, "33.003", true, &t.path().join("offline-cache/33.003")).unwrap();
    fonts::validate_bundle(&d, "33.003", true).unwrap();
    let provenance: serde_json::Value =
        serde_json::from_slice(&fs::read(d.join(fonts::PROVENANCE)).unwrap()).unwrap();
    assert_eq!(provenance["source"], "bundled");
}
#[test]
fn test_cache_delivery_includes_license_provenance_and_survives_failure() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let cache = t.path().join("cache/33.003");
    bundle(&cache);
    let d = t.path().join("delivery");
    fs::create_dir(&d).unwrap();
    fs::write(d.join("Vazirmatn-Regular.ttf"), b"previous font").unwrap();
    let result = fonts::fetch_with_cache_observed(&d, "33.003", true, &cache, |b, path| {
        if b == fonts::Boundary::Delivery(revayat_scientific::publication::Boundary::BeforeCommit)
            && path.file_name().unwrap() == "OFL.txt"
        {
            anyhow::bail!("injected license publication failure");
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(d.join("Vazirmatn-Regular.ttf")).unwrap(),
        b"previous font"
    );
    assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
    fonts::fetch_with_cache(&d, "33.003", true, &cache).unwrap();
    let records = fonts::validate_bundle(&d, "33.003", true).unwrap();
    assert_eq!(records.len(), 3);
    for name in [
        "Vazirmatn-Regular.ttf",
        "Vazirmatn-Bold.ttf",
        "OFL.txt",
        "font-provenance.json",
    ] {
        assert!(d.join(name).is_file());
    }
    assert_eq!(
        fs::read(d.join("OFL.txt")).unwrap(),
        fs::read(cache.join("OFL.txt")).unwrap()
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(d.join(fonts::PROVENANCE)).unwrap()).unwrap();
    assert_eq!(metadata["source"], "cache");
    assert_eq!(metadata["version"], "33.003");
    let before = files(&d);
    fonts::fetch_with_cache_observed(&d, "33.003", true, &cache, |_, _| {
        anyhow::bail!("a valid existing bundle must not republish or populate cache")
    })
    .unwrap();
    assert_eq!(files(&d), before);
    let previous = fs::read(d.join("Vazirmatn-Regular.ttf")).unwrap();
    fs::write(cache.join("Vazirmatn-Regular.ttf"), b"bad").unwrap();
    fs::remove_file(d.join("OFL.txt")).unwrap();
    assert!(fonts::fetch_with_cache(&d, "999.999", true, &cache).is_err());
    assert_eq!(fs::read(d.join("Vazirmatn-Regular.ttf")).unwrap(), previous);
}
#[test]
fn test_nonobject_provenance_recovers_valid_offline_bundle() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let d = t.path().join("delivery");
    bundle(&d);
    let expected = files(&d);
    for bad in [
        "[]",
        "null",
        "true",
        "false",
        "\"metadata\"",
        "{\"schema\":true}",
        "{\"schema\":2}",
        "{broken",
    ] {
        fs::write(d.join(fonts::PROVENANCE), bad).unwrap();
        fonts::fetch_with_cache(&d, "33.003", true, &t.path().join("cache/33.003")).unwrap();
        fonts::validate_bundle(&d, "33.003", true).unwrap();
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(d.join(fonts::PROVENANCE)).unwrap()).unwrap();
        assert_eq!(metadata["schema"], 1);
        for (name, bytes) in &expected {
            assert_eq!(fs::read(d.join(name)).unwrap(), *bytes);
        }
    }
}
#[test]
fn test_identity_refuses_renamed_weight_fd_wrong_version_and_bad_font() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    bundle(t.path());
    let f = t.path().join("Vazirmatn-Regular.ttf");
    assert!(fonts::font_identity(&f, 700, "33.003").is_err());
    assert!(fonts::font_identity(&f, 400, "99.999").is_err());
    fs::write(&f, name_variant(pdf_font::REGULAR, "Regular", "FD     ")).unwrap();
    let error = fonts::font_identity(&f, 400, "33.003").unwrap_err();
    assert!(error.to_string().contains("Western-digit"));
    let mut data = pdf_font::REGULAR.to_vec();
    let needle = "Vazirmatn"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    let replacement = "FarsiDigi"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    for i in 0..data.len() - needle.len() {
        if data[i..].starts_with(&needle) {
            data[i..i + needle.len()].copy_from_slice(&replacement);
        }
    }
    fs::write(&f, data).unwrap();
    assert!(fonts::font_identity(&f, 400, "33.003").is_err());
    for bad in [b"not a font".as_slice(), &[0, 1, 0, 0]] {
        fs::write(&f, bad).unwrap();
        assert!(fonts::font_identity(&f, 400, "33.003").is_err());
    }
}
#[test]
fn test_partial_cache_offline_and_bad_archives_do_not_publish() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let cache = t.path().join("cache/99.999");
    bundle(&cache);
    fs::remove_file(cache.join("Vazirmatn-Bold.ttf")).unwrap();
    let d = t.path().join("delivery");
    assert!(fonts::fetch_with_cache(&d, "99.999", true, &cache).is_err());
    assert!(!d.join(fonts::PROVENANCE).exists());
    for missing in ["Vazirmatn-Bold.ttf", "OFL.txt"] {
        let cache = t.path().join(missing).join("99.999");
        bundle(&cache);
        for (name, _) in fonts::FILES {
            let bytes = fs::read(cache.join(name)).unwrap();
            fs::write(cache.join(name), name_variant(&bytes, "33.003", "99.999")).unwrap();
        }
        fonts::validate_bundle(&cache, "99.999", false).unwrap();
        fs::remove_file(cache.join(missing)).unwrap();
        let error = fonts::fetch_with_cache(&d, "99.999", true, &cache).unwrap_err();
        assert!(error.to_string().contains("offline"));
        assert!(files(&d).is_empty());
    }
    let archive = t.path().join("bad.zip");
    {
        let mut w = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
        w.start_file(
            "nested/Vazirmatn-Regular.ttf",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        w.write_all(pdf_font::REGULAR).unwrap();
        w.finish().unwrap();
    }
    assert!(fonts::extract_bundle(&archive, &d).is_err());
    assert_eq!(fs::read_dir(&d).unwrap().count(), 0);
    {
        let mut writer = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
        for (name, bytes) in [
            ("../Vazirmatn-Regular.ttf", pdf_font::REGULAR),
            ("duplicate/Vazirmatn-Regular.ttf", pdf_font::REGULAR),
            ("Vazirmatn-Bold.ttf", pdf_font::BOLD),
            ("OFL.txt", pdf_font::LICENSE),
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    let error = fonts::extract_bundle(&archive, &d).unwrap_err();
    assert!(error.to_string().contains("ambiguous"));
    assert!(files(&d).is_empty());
    assert!(!t.path().join("Vazirmatn-Regular.ttf").exists());
}
#[test]
fn test_installed_pair_requires_both_real_weights_and_license() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    bundle(t.path());
    fonts::validate_bundle(t.path(), "33.003", false).unwrap();
    let delivered = tempfile::tempdir_in(t.path()).unwrap();
    assert!(fonts::installed_from_candidates(
        delivered.path(),
        "33.003",
        &[t.path().to_owned()]
    )
    .unwrap());
    for name in ["Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf", "OFL.txt"] {
        assert_eq!(
            fs::read(delivered.path().join(name)).unwrap(),
            fs::read(t.path().join(name)).unwrap()
        );
    }
    fs::remove_file(t.path().join("OFL.txt")).unwrap();
    assert!(fonts::validate_bundle(t.path(), "33.003", false).is_err());
    let empty = tempfile::tempdir_in(t.path()).unwrap();
    assert!(!fonts::installed_from_candidates(empty.path(), "33.003", &[t.path().to_owned()]).unwrap());
    assert!(files(empty.path()).is_empty());
    bundle(t.path());
    fs::copy(
        t.path().join("Vazirmatn-Regular.ttf"),
        t.path().join("Vazirmatn-Bold.ttf"),
    )
    .unwrap();
    assert!(fonts::validate_bundle(t.path(), "33.003", false).is_err());
    bundle(t.path());
    fs::write(t.path().join("OFL.txt"), b"SIL OPEN FONT LICENSE").unwrap();
    assert!(fonts::validate_bundle(t.path(), "33.003", false).is_err());
}
#[test]
fn test_legacy_cache_is_validated_before_versioned_migration() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let legacy = t.path().join("cache");
    bundle(&legacy);
    let d = t.path().join("delivery");
    fonts::fetch_with_cache(&d, "33.003", true, &legacy.join("33.003")).unwrap();
    fonts::validate_bundle(&legacy.join("33.003"), "33.003", true).unwrap();
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(d.join(fonts::PROVENANCE)).unwrap()).unwrap();
    assert_eq!(metadata["source"], "legacy-cache");
    assert_eq!(metadata["version"], "33.003");
    assert_eq!(
        fs::read(legacy.join("33.003/OFL.txt")).unwrap(),
        fs::read(d.join("OFL.txt")).unwrap()
    );
    let bad = t.path().join("wrong");
    assert!(fonts::fetch_with_cache(&bad, "99.999", true, &legacy.join("99.999")).is_err());
    assert!(!bad.join(fonts::PROVENANCE).exists());
}
