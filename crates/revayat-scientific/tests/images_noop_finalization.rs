//! Final input admission when every selected image is already compliant.
use revayat_scientific::images;
use std::{fs, path::PathBuf};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = temp.path().canonicalize().unwrap();
    let first = root.join("a.png");
    let second = root.join("b.png");
    for (path, color) in [(&first, [160, 170, 180]), (&second, [190, 200, 210])] {
        image::RgbImage::from_pixel(6, 6, image::Rgb(color))
            .save(path)
            .unwrap();
    }
    (temp, first, second)
}

#[test]
fn unchanged_batch_returns_zero_without_publication_or_artifacts() {
    let (temp, first, second) = fixture();
    let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
    let mut notifications = Vec::new();
    let result =
        images::prepare_observed(&[first.clone(), second.clone()], false, |event, path| {
            assert_eq!(event, images::Boundary::BeforeInputCheck);
            notifications.push(path.to_owned());
            Ok(())
        });
    assert_eq!(result.unwrap(), 0);
    assert_eq!(notifications, [first.clone(), second.clone()]);
    assert_eq!(fs::read(first).unwrap(), before[0]);
    assert_eq!(fs::read(second).unwrap(), before[1]);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
}

#[test]
fn current_input_mutation_is_rejected() {
    let (temp, first, second) = fixture();
    let second_before = fs::read(&second).unwrap();
    let mut reached = false;
    let result =
        images::prepare_observed(&[first.clone(), second.clone()], false, |event, path| {
            if event == images::Boundary::BeforeInputCheck && path == first {
                fs::write(&first, b"foreign revision in current input")?;
                reached = true;
            }
            Ok(())
        });
    assert!(
        reached,
        "the successful mutation must precede the rejection"
    );
    assert!(result.is_err());
    assert_eq!(
        fs::read(first).unwrap(),
        b"foreign revision in current input"
    );
    assert_eq!(fs::read(second).unwrap(), second_before);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
}

#[test]
fn later_input_callback_cannot_invalidate_an_earlier_input() {
    let (temp, first, second) = fixture();
    let second_before = fs::read(&second).unwrap();
    let mut reached = false;
    let result =
        images::prepare_observed(&[first.clone(), second.clone()], false, |event, path| {
            if event == images::Boundary::BeforeInputCheck && path == second {
                fs::write(&first, b"foreign revision after the earlier input check")?;
                reached = true;
            }
            Ok(())
        });
    assert!(
        reached,
        "the later callback must successfully mutate the earlier input"
    );
    assert_eq!(
        fs::read(&first).unwrap(),
        b"foreign revision after the earlier input check"
    );
    assert_eq!(fs::read(second).unwrap(), second_before);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    assert!(
        result.is_err(),
        "the no-op batch returned stale success after its earlier source changed: {result:?}"
    );
}

#[cfg(unix)]
#[test]
fn later_input_callback_cannot_invalidate_an_earlier_mode() {
    use std::os::unix::fs::PermissionsExt;

    let (temp, first, second) = fixture();
    fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap();
    let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
    let mut reached = false;
    let result =
        images::prepare_observed(&[first.clone(), second.clone()], false, |event, path| {
            if event == images::Boundary::BeforeInputCheck && path == second {
                fs::set_permissions(&first, fs::Permissions::from_mode(0o640))?;
                reached = true;
            }
            Ok(())
        });
    assert!(
        reached,
        "the later callback must successfully change the earlier mode"
    );
    assert_eq!(fs::read(&first).unwrap(), before[0]);
    assert_eq!(fs::read(second).unwrap(), before[1]);
    assert_eq!(
        fs::metadata(&first).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    assert!(
        result.is_err(),
        "the no-op batch returned stale success after its earlier mode changed: {result:?}"
    );
}

#[test]
fn observer_error_propagates_without_publication() {
    for fail_later in [false, true] {
        let (temp, first, second) = fixture();
        let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
        let failure_path = if fail_later { &second } else { &first };
        let mut reached = false;
        let error =
            images::prepare_observed(&[first.clone(), second.clone()], false, |event, path| {
                assert_eq!(event, images::Boundary::BeforeInputCheck);
                if path == failure_path {
                    reached = true;
                    anyhow::bail!("controlled no-op observer failure");
                }
                Ok(())
            })
            .unwrap_err();
        assert!(reached, "the selected callback must run");
        assert!(
            error
                .to_string()
                .contains("controlled no-op observer failure")
        );
        assert_eq!(fs::read(first).unwrap(), before[0]);
        assert_eq!(fs::read(second).unwrap(), before[1]);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }
}

#[test]
fn empty_selection_is_refused_without_callbacks() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    for paths in [Vec::new(), vec![temp.path().canonicalize().unwrap()]] {
        let mut callbacks = 0;
        let result = images::prepare_observed(&paths, false, |_, _| {
            callbacks += 1;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(callbacks, 0);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }
}

#[test]
fn compliant_source_does_not_admit_or_change_an_existing_original() {
    let (temp, first, second) = fixture();
    let original = first.with_file_name("a.png.orig");
    fs::write(&original, b"preserved original from a previous revision").unwrap();
    let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
    let mut notifications = Vec::new();
    let result = images::prepare_observed(std::slice::from_ref(&first), false, |event, path| {
        assert_eq!(event, images::Boundary::BeforeInputCheck);
        notifications.push(path.to_owned());
        Ok(())
    });
    assert_eq!(result.unwrap(), 0);
    assert_eq!(notifications.as_slice(), std::slice::from_ref(&first));
    assert_eq!(fs::read(first).unwrap(), before[0]);
    assert_eq!(fs::read(second).unwrap(), before[1]);
    assert_eq!(
        fs::read(original).unwrap(),
        b"preserved original from a previous revision"
    );
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 3);
}
