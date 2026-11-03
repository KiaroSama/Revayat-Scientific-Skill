use revayat_scientific::{fonts, pdf_font};
use std::{fs, io::Write, path::Path};
fn bundle(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("Vazirmatn-Regular.ttf"), pdf_font::REGULAR).unwrap();
    fs::write(dir.join("Vazirmatn-Bold.ttf"), pdf_font::BOLD).unwrap();
    fs::write(dir.join("OFL.txt"), pdf_font::LICENSE).unwrap();
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
    for bad in ["[]", "null", "true", "{\"schema\":true}"] {
        fs::write(d.join(fonts::PROVENANCE), bad).unwrap();
        fonts::fetch_with_cache(&d, "33.003", true, &t.path().join("cache/33.003")).unwrap();
        fonts::validate_bundle(&d, "33.003", true).unwrap();
    }
}
#[test]
fn test_identity_refuses_renamed_weight_fd_wrong_version_and_bad_font() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    bundle(t.path());
    let f = t.path().join("Vazirmatn-Regular.ttf");
    assert!(fonts::font_identity(&f, 700, "33.003").is_err());
    assert!(fonts::font_identity(&f, 400, "99.999").is_err());
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
}
#[test]
fn test_installed_pair_requires_both_real_weights_and_license() {
    let t = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    bundle(t.path());
    fonts::validate_bundle(t.path(), "33.003", false).unwrap();
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
    let bad = t.path().join("wrong");
    assert!(fonts::fetch_with_cache(&bad, "99.999", true, &legacy.join("99.999")).is_err());
    assert!(!bad.join(fonts::PROVENANCE).exists());
}
