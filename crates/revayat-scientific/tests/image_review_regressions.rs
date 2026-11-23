use revayat_scientific::{images, publication};
use std::{fs, path::Path};

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn jpeg(path: &Path, color: [u8; 3]) {
    image::RgbImage::from_pixel(6, 6, image::Rgb(color))
        .save(path)
        .unwrap();
}

fn alpha_png(path: &Path) {
    image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
        .save(path)
        .unwrap();
}

#[test]
fn normalized_input_keys_keep_in_place_source_and_original_checks_bound() {
    let temp = workspace();
    fs::create_dir(temp.path().join("parent")).unwrap();
    let source = temp.path().join("figure.png");
    let input = temp.path().join("parent/../figure.png");
    alpha_png(&source);
    let before = fs::read(&source).unwrap();
    assert_eq!(images::prepare(&[input], false).unwrap(), 1);
    assert_eq!(
        fs::read(temp.path().join("figure.png.orig")).unwrap(),
        before
    );
    assert!(!image::open(&source).unwrap().color().has_alpha());
}

#[cfg(target_os = "linux")]
#[test]
fn readonly_source_case_sibling_does_not_collide_with_a_distinct_png_output() {
    let temp = workspace();
    let source = temp.path().join("figure.jpg");
    let sibling = temp.path().join("FIGURE.JPG");
    jpeg(&source, [30, 80, 160]);
    jpeg(&sibling, [200, 210, 220]);
    let before = [fs::read(&source).unwrap(), fs::read(&sibling).unwrap()];
    assert_eq!(
        images::prepare(std::slice::from_ref(&source), false).unwrap(),
        1
    );
    assert_eq!(fs::read(&source).unwrap(), before[0]);
    assert_eq!(fs::read(&sibling).unwrap(), before[1]);
    assert_eq!(
        image::open(source.with_extension("png")).unwrap().to_rgb8(),
        image::open(&source).unwrap().to_rgb8()
    );

    let other = workspace();
    let source = other.path().join("figure.jpg");
    let collision = other.path().join("FIGURE.PNG");
    jpeg(&source, [30, 80, 160]);
    fs::write(&collision, b"foreign output").unwrap();
    assert!(images::prepare(std::slice::from_ref(&source), false).is_err());
    assert_eq!(fs::read(&collision).unwrap(), b"foreign output");
    assert!(!source.with_extension("png").exists());
}

#[cfg(unix)]
#[test]
fn compliant_png_does_not_need_to_admit_an_output_beside_a_case_variant() {
    let temp = workspace();
    let source = temp.path().join("figure.png");
    let sibling = temp.path().join("FIGURE.PNG");
    image::RgbImage::from_pixel(6, 6, image::Rgb([30, 80, 160]))
        .save(&source)
        .unwrap();
    if sibling.exists() {
        return; // This filesystem cannot represent the two distinct names.
    }
    fs::write(&sibling, b"unselected sibling").unwrap();
    let before = fs::read(&source).unwrap();

    assert_eq!(
        images::prepare(std::slice::from_ref(&source), false).unwrap(),
        0
    );
    assert_eq!(fs::read(&source).unwrap(), before);
    assert_eq!(fs::read(&sibling).unwrap(), b"unselected sibling");
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn encoded_png_mode_drift_is_rejected_at_stage_admission() {
    use std::os::unix::fs::PermissionsExt;

    let temp = workspace();
    let first = temp.path().join("first.jpg");
    let second = temp.path().join("second.jpg");
    jpeg(&first, [30, 80, 160]);
    jpeg(&second, [200, 210, 220]);
    fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap();
    let mut changed = false;
    let result =
        images::prepare_observed(&[first.clone(), second.clone()], false, |event, path| {
            if event == images::Boundary::BeforeEncode && path == second {
                let stage = fs::read_dir(temp.path())?
                    .map(|entry| entry.map(|e| e.path().join("figure.png")))
                    .collect::<std::io::Result<Vec<_>>>()?
                    .into_iter()
                    .find(|candidate| candidate.is_file())
                    .expect("the first encoded PNG must exist before the second encoder");
                assert_eq!(
                    fs::metadata(stage.parent().unwrap())?.permissions().mode() & 0o7777,
                    0o700
                );
                assert_eq!(fs::metadata(&stage)?.permissions().mode() & 0o7777, 0o600);
                fs::set_permissions(&stage, fs::Permissions::from_mode(0o644))?;
                changed = true;
            }
            Ok(())
        });
    assert!(changed, "the staged mode must be changed successfully");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("image stage differs")
    );
    assert!(!first.with_extension("png").exists());
    assert!(!second.with_extension("png").exists());
}

#[cfg(unix)]
#[test]
fn rollback_refuses_a_backup_with_unchanged_bytes_and_a_different_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = workspace();
    let stage = temp.path().join("stage");
    let output = temp.path().join("output");
    fs::write(&stage, b"proposed bytes").unwrap();
    fs::write(&output, b"original bytes").unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).unwrap();
    let mut backup = None;
    let error =
        publication::publish_observed(&[(stage, output.clone())], &[], None, |event, path| {
            if event == publication::Boundary::BackupPrepared {
                backup = Some(path.to_owned());
            }
            if event == publication::Boundary::AfterCommit {
                let path = backup
                    .as_ref()
                    .expect("the rollback backup must have been admitted");
                assert_eq!(fs::metadata(path)?.permissions().mode() & 0o7777, 0o600);
                fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
                anyhow::bail!("test requested rollback after changing backup mode");
            }
            Ok(())
        })
        .unwrap_err();
    let failures = &error
        .downcast_ref::<publication::RecoveryFailures>()
        .unwrap()
        .0;
    assert!(failures.iter().any(|failure| {
        failure
            .to_string()
            .contains("previous backup changed before rollback")
    }));
    let backup = backup.unwrap();
    assert_eq!(fs::read(&backup).unwrap(), b"original bytes");
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert_eq!(fs::read(&output).unwrap(), b"proposed bytes");
}

#[test]
fn earlier_encoded_stage_is_not_readmitted_after_a_later_encode_callback() {
    let temp = workspace();
    let first = temp.path().join("first.jpg");
    let second = temp.path().join("second.jpg");
    jpeg(&first, [30, 80, 160]);
    jpeg(&second, [200, 210, 220]);
    let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
    let mut replaced = false;
    let result = images::prepare_observed(&[first.clone(), second.clone()], false, |b, path| {
        if b == images::Boundary::BeforeEncode && path == second {
            let stage = fs::read_dir(temp.path())?
                .map(|entry| entry.map(|e| e.path().join("figure.png")))
                .collect::<std::io::Result<Vec<_>>>()?
                .into_iter()
                .find(|candidate| candidate.is_file())
                .expect("the first encoded PNG must exist before the second encoder");
            image::RgbImage::from_pixel(6, 6, image::Rgb([255, 0, 0])).save(&stage)?;
            replaced = true;
        }
        Ok(())
    });
    assert!(
        replaced,
        "the actual previously encoded stage must be replaced"
    );
    assert!(
        result.is_err(),
        "a replacement PNG was published as the encoded output"
    );
    assert_eq!(fs::read(&first).unwrap(), before[0]);
    assert_eq!(fs::read(&second).unwrap(), before[1]);
    assert!(!first.with_extension("png").exists());
    assert!(!second.with_extension("png").exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn private_original_and_in_place_conversion_keep_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt;
    for mode in [0o600, 0o640] {
        let temp = workspace();
        let source = temp.path().join("figure.png");
        alpha_png(&source);
        fs::set_permissions(&source, fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::read(&source).unwrap();
        assert_eq!(
            images::prepare(std::slice::from_ref(&source), false).unwrap(),
            1
        );
        let original = temp.path().join("figure.png.orig");
        assert_eq!(fs::read(&original).unwrap(), before);
        assert_eq!(
            fs::metadata(&original).unwrap().permissions().mode() & 0o777,
            mode
        );
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            mode
        );
        assert!(!image::open(&source).unwrap().color().has_alpha());
    }
}

#[test]
fn cleanup_source_or_original_changes_roll_back_the_complete_image_batch() {
    for event in [
        publication::Boundary::BeforeCleanup,
        publication::Boundary::BeforeBackupDisposal,
    ] {
        for change_backup in [false, true] {
            let temp = workspace();
            let png = temp.path().join("first.png");
            let original = temp.path().join("first.png.orig");
            let source = temp.path().join("second.jpg");
            alpha_png(&png);
            fs::copy(&png, &original).unwrap();
            jpeg(&source, [200, 210, 220]);
            let png_before = fs::read(&png).unwrap();
            let source_before = fs::read(&source).unwrap();
            let changed = if change_backup { &original } else { &source };
            let mut replaced = false;
            let result =
                images::prepare_observed(&[png.clone(), source.clone()], false, |b, path| {
                    if !replaced
                        && b == images::Boundary::Publication(event)
                        && (event != publication::Boundary::BeforeCleanup
                            || path == source.with_extension("png"))
                    {
                        fs::write(changed, b"foreign revision after all image commits")?;
                        replaced = true;
                    }
                    Ok(())
                });
            assert!(replaced, "the cleanup boundary must execute: {event:?}");
            assert!(
                result.is_err(),
                "cleanup mutation was accepted: {event:?}, backup={change_backup}"
            );
            assert_eq!(fs::read(&png).unwrap(), png_before);
            assert_eq!(
                fs::read(changed).unwrap(),
                b"foreign revision after all image commits"
            );
            if change_backup {
                assert_eq!(fs::read(&source).unwrap(), source_before);
            } else {
                assert_eq!(fs::read(&original).unwrap(), png_before);
            }
            assert!(!source.with_extension("png").exists());
        }
    }
}

#[test]
fn final_original_check_cannot_invalidate_an_already_checked_source() {
    let temp = workspace();
    let png = temp.path().join("first.png");
    let original = temp.path().join("first.png.orig");
    let source = temp.path().join("second.jpg");
    let replacement = temp.path().join("replacement.jpg");
    alpha_png(&png);
    fs::copy(&png, &original).unwrap();
    jpeg(&source, [200, 210, 220]);
    jpeg(&replacement, [100, 110, 120]);
    let foreign = fs::read(&replacement).unwrap();
    let png_before = fs::read(&png).unwrap();
    let mut finalizing = false;
    let mut reached = false;
    let mut final_original_checks = 0;
    let result =
        images::prepare_observed(&[png.clone(), source.clone()], false, |boundary, path| {
            if boundary == images::Boundary::Publication(publication::Boundary::BeforeFinalize) {
                finalizing = true;
            }
            if finalizing && boundary == images::Boundary::BeforeInputCheck && path == original {
                final_original_checks += 1;
                if final_original_checks == 2 {
                    fs::write(&source, &foreign)?;
                    reached = true;
                }
            }
            Ok(())
        });
    assert!(reached, "the final original-check callback must execute");
    assert!(
        result.is_err(),
        "stale batch accepted after final input observation"
    );
    assert_eq!(fs::read(&png).unwrap(), png_before);
    assert_eq!(fs::read(&original).unwrap(), png_before);
    assert!(!source.with_extension("png").exists());
    assert_eq!(fs::read(&source).unwrap(), foreign);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 4);
}

#[test]
fn final_later_original_check_cannot_invalidate_an_earlier_original() {
    let temp = workspace();
    let first = temp.path().join("first.png");
    let earlier_original = temp.path().join("first.png.orig");
    let second = temp.path().join("second.png");
    let later_original = temp.path().join("second.png.orig");
    for (source, backup) in [(&first, &earlier_original), (&second, &later_original)] {
        alpha_png(source);
        fs::copy(source, backup).unwrap();
    }
    let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
    let foreign = b"foreign original changed during final validation";
    let mut finalizing = false;
    let mut reached = false;
    let mut final_original_checks = 0;
    let result =
        images::prepare_observed(&[first.clone(), second.clone()], false, |boundary, path| {
            if boundary == images::Boundary::Publication(publication::Boundary::BeforeFinalize) {
                finalizing = true;
            }
            if finalizing
                && boundary == images::Boundary::BeforeInputCheck
                && path == later_original
            {
                final_original_checks += 1;
                if final_original_checks == 2 {
                    fs::write(&earlier_original, foreign)?;
                    reached = true;
                }
            }
            Ok(())
        });
    assert!(reached, "the final later-original callback must execute");
    assert!(
        result.is_err(),
        "stale original accepted after final input observation"
    );
    assert_eq!(fs::read(&first).unwrap(), before[0]);
    assert_eq!(fs::read(&second).unwrap(), before[1]);
    assert_eq!(fs::read(&earlier_original).unwrap(), foreign);
    assert_eq!(fs::read(&later_original).unwrap(), before[1]);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 4);
}
