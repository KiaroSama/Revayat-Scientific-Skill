use revayat_scientific::{images, publication};
use std::fs;

fn late_destination(backup: bool, boundary: images::Boundary) {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let source = temp
        .path()
        .join(if backup { "figure.png" } else { "figure.jpg" });
    if backup {
        image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
            .save(&source)
            .unwrap();
    } else {
        image::RgbImage::from_pixel(6, 6, image::Rgb([20, 30, 40]))
            .save(&source)
            .unwrap();
    }
    let original = fs::read(&source).unwrap();
    let destination = if backup {
        source.with_file_name("figure.png.orig")
    } else {
        source.with_extension("png")
    };
    let foreign = b"user content that appeared after admission";
    let mut reached = false;
    let result = images::prepare_observed(std::slice::from_ref(&source), false, |event, path| {
        if event == boundary && (event == images::Boundary::BeforeEncode || path == destination) {
            fs::write(&destination, foreign)?;
            reached = true;
        }
        Ok(())
    });
    assert!(reached, "the late-destination boundary must be reached");
    assert!(
        result.is_err(),
        "late destination was accepted at {boundary:?}"
    );
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&destination).unwrap(), foreign);
}

#[test]
fn late_original_backup_preserves_source_and_foreign_backup() {
    for boundary in [
        images::Boundary::BeforeEncode,
        images::Boundary::Publication(publication::Boundary::BeforeCommit),
        images::Boundary::Publication(publication::Boundary::BeforeReplace),
    ] {
        late_destination(true, boundary);
    }
}

#[test]
fn late_converted_destination_preserves_source_and_foreign_output() {
    for boundary in [
        images::Boundary::BeforeEncode,
        images::Boundary::Publication(publication::Boundary::BeforeCommit),
        images::Boundary::Publication(publication::Boundary::BeforeReplace),
    ] {
        late_destination(false, boundary);
    }
}

#[test]
fn removed_admitted_backup_refuses_in_place_conversion() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let source = temp.path().join("figure.png");
    let backup = temp.path().join("figure.png.orig");
    image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
        .save(&source)
        .unwrap();
    fs::copy(&source, &backup).unwrap();
    let original = fs::read(&source).unwrap();
    let mut reached = false;
    let result = images::prepare_observed(std::slice::from_ref(&source), false, |event, _| {
        if event == images::Boundary::BeforeEncode {
            fs::remove_file(&backup)?;
            reached = true;
        }
        Ok(())
    });
    assert!(reached);
    assert!(result.is_err());
    assert_eq!(fs::read(&source).unwrap(), original);
    assert!(!backup.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn batch_source_verification_work_grows_linearly() {
    for count in [4usize, 12] {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let mut sources = Vec::new();
        for index in 0..count {
            let source = temp.path().join(format!("figure-{index}.jpg"));
            image::RgbImage::from_pixel(6, 6, image::Rgb([20, 30, 40]))
                .save(&source)
                .unwrap();
            sources.push(source);
        }
        let mut reads = 0;
        let mut checked = std::collections::HashSet::new();
        images::prepare_observed(&sources, false, |boundary, path| {
            if boundary == images::Boundary::BeforeInputCheck {
                reads += 1;
                checked.insert(path.to_path_buf());
            }
            Ok(())
        })
        .unwrap();
        assert!(reads >= count, "all sources must actually be checked");
        assert!(
            sources.iter().all(|source| checked.contains(source)),
            "every admitted source must actually be checked"
        );
        assert!(
            reads <= 6 * count,
            "source fingerprint work must grow linearly: {reads} checks for {count} images"
        );
        for source in sources {
            assert!(source.with_extension("png").is_file());
        }
    }
}

#[test]
fn published_original_backup_is_verified_before_source_replacement() {
    let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let source = temp.path().join("figure.png");
    let backup = temp.path().join("figure.png.orig");
    image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
        .save(&source)
        .unwrap();
    let original = fs::read(&source).unwrap();
    let foreign = b"foreign backup revision";
    let mut reached = false;
    let result = images::prepare_observed(std::slice::from_ref(&source), false, |event, path| {
        if event == images::Boundary::Publication(publication::Boundary::AfterCommit)
            && path == backup
        {
            fs::write(&backup, foreign)?;
            reached = true;
        }
        Ok(())
    });
    assert!(reached);
    assert!(
        result.is_err(),
        "changed original backup permitted source replacement"
    );
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&backup).unwrap(), foreign);
}

#[test]
fn relative_image_filenames_are_prepared_from_cli_working_directory() {
    for (name, has_alpha) in [
        ("./figure.jpg", false),
        ("figure.jpg", false),
        ("./figure.png", true),
        ("figure.png", true),
    ] {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = temp.path().join(name);
        if has_alpha {
            image::RgbaImage::from_pixel(6, 6, image::Rgba([20, 30, 40, 20]))
                .save(&source)
                .unwrap();
        } else {
            image::RgbImage::from_pixel(6, 6, image::Rgb([20, 30, 40]))
                .save(&source)
                .unwrap();
        }
        let original = fs::read(&source).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
            .args(["--worker", "figures", name])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "relative image {name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let png = image::open(source.with_extension("png")).unwrap();
        assert_eq!((png.width(), png.height()), (6, 6));
        assert_eq!(png.color(), image::ColorType::Rgb8);
        let retained_original = if has_alpha {
            source.with_file_name("figure.png.orig")
        } else {
            source
        };
        assert_eq!(fs::read(retained_original).unwrap(), original);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }
}
