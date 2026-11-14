#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::dictionary;
use revayat_scientific::runtime::{CommandSpec, run};
use revayat_scientific::{crop as c, pdf as p, pdf_content};
use std::fs;
#[path = "support/pdf_encryption.rs"]
mod pdf_encryption;
fn painted_page(media: [f64; 4], artwork: [f64; 4]) -> lopdf::Document {
    let mut doc = blank();
    let page = pages(&doc)[0];
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set(
            "MediaBox",
            media
                .into_iter()
                .map(|v| lopdf::Object::Real(v as f32))
                .collect::<Vec<_>>(),
        );
    let [x0, y0, x1, y1] = artwork;
    let stream = lopdf::Stream::new(
        dictionary! {},
        format!("q 1 0 0 rg {x0} {y0} {} {} re f Q", x1 - x0, y1 - y0).into_bytes(),
    );
    let content = doc.add_object(stream);
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Contents", content);
    doc
}
fn args(x: &Fixture) -> c::Args {
    c::Args {
        pdf: x.source.clone(),
        out: x.temp.path().join("figures"),
        map: Some(x.temp.path().join("map.tsv")),
        cover: false,
        cover_page: 1,
        author_page: 0,
        dpi: 72,
    }
}
fn explicit(x: &Fixture) -> c::Args {
    let a = args(x);
    fs::write(
        a.map.as_ref().unwrap(),
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nsample\t1\t60\t70\t120\t130\n",
    )
    .unwrap();
    a
}
#[test]
fn test_invalid_late_map_preserves_previous_output() {
    let x = Fixture::new();
    x.save(document(1));
    let a = explicit(&x);
    let before = fs::read(&x.source).unwrap();
    fs::create_dir(&a.out).unwrap();
    let old = a.out.join("fig-sample.png");
    fs::write(&old, b"old approved crop").unwrap();
    fs::write(
        a.map.as_ref().unwrap(),
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nsample\t1\t0\t0\t60\t60\nlate\t2\t0\t0\t60\t60\n",
    )
    .unwrap();
    assert!(c::crop_document(&a).is_err());
    assert_eq!(fs::read(old).unwrap(), b"old approved crop");
    assert_eq!(fs::read(&x.source).unwrap(), before);
    assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
    assert!(!fs::read_dir(x.temp.path()).unwrap().any(|p| {
        p.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-")
    }));
}
#[test]
fn test_transitive_components_edges_and_ambiguity() {
    let groups = c::cluster(
        &[
            [0., 0., 40., 40.],
            [65., 0., 105., 40.],
            [130., 0., 170., 40.],
        ],
        28.,
    )
    .unwrap();
    assert_eq!(groups, vec![[0., 0., 170., 40.]]);
    assert_eq!(
        c::cluster(
            &[
                [0., 50., 40., 80.],
                [90., 50., 130., 80.],
                [40., 70., 90., 100.]
            ],
            1.
        )
        .unwrap(),
        vec![[0., 50., 130., 100.]]
    );
    for rectangle in [
        [598., 30., 608., 100.],
        [0., 0., 60., 60.],
        [10., 740., 100., 792.],
    ] {
        let clipped = c::pad_clip([0., 0., 612., 792.], rectangle, 12., 72.);
        assert!(
            clipped[0] <= rectangle[0]
                && clipped[1] <= rectangle[1]
                && clipped[2] >= rectangle[2]
                && clipped[3] >= rectangle[3]
        );
    }
    let groups = c::cluster(
        &[
            [0., 0., 40., 40.],
            [60., 60., 100., 100.],
            [70., 0., 110., 20.],
        ],
        20.,
    )
    .unwrap();
    assert_eq!(groups.len(), 2);
    assert!(c::pick_clusters(&groups, 1).is_err());
    assert_eq!(
        c::pad_clip([0., 0., 200., 200.], [0., 0., 40., 40.], 12., 72.),
        [0., 0., 124., 52.]
    );
}
#[test]
fn test_map_rejects_malformed_rows_duplicates_and_nonfinite_rectangles() {
    let x = Fixture::new();
    let path = x.temp.path().join("map.tsv");
    for bad in [
        "",
        "figure_id\tpdf_page\n",
        "wrong\theader\n",
        "x\t0\n",
        "x\t1.5\n",
        "x\t1\nx\t2\n",
        "X\t1\nx\t2\n",
        "x\t1\ninvalid\n",
        "figure_id\tpdf_page\nx\t0\n",
        "figure_id\tpdf_page\nx\t1\nX\t2\n",
        "figure_id\tpdf_page\n../x\t1\n",
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nx\t1\t0\t0\tNaN\t20\n",
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nx\t1\t20\t0\t10\t20\n",
        "figure_id\tpdf_page\nx\t1\textra\n",
        "figure_id\tpdf_page\n\nx\t1\n",
    ] {
        fs::write(&path, bad).unwrap();
        assert!(c::load_map(&path).is_err(), "accepted {bad:?}");
    }
    fs::write(&path, "figure_id,printed,pdf_page\nsample,12,2\n").unwrap();
    assert_eq!(c::load_map(&path).unwrap().get(&2).unwrap()[0].id, "sample");
    fs::write(&path, "figure_id,pdf_page\nx,1\ny,2\n").unwrap();
    let grouped = c::load_map(&path).unwrap();
    assert_eq!(grouped.keys().copied().collect::<Vec<_>>(), [1, 2]);
    assert_eq!(grouped[&1][0].id, "x");
    assert_eq!(grouped[&2][0].id, "y");
}
#[test]
#[ignore = "requires Poppler"]
fn test_explicit_edge_crop_and_late_failures_preserve_batch() {
    let x = Fixture::new();
    x.save(painted_page([0., 0., 612., 792.], [598., 712., 608., 772.]));
    let a = args(&x);
    fs::write(a.map.as_ref().unwrap(), "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nfirst\t1\t590\t10\t612\t90\nsecond\t1\t580\t10\t612\t90\n").unwrap();
    fs::create_dir(&a.out).unwrap();
    let output = a.out.join("fig-first.png");
    fs::write(&output, b"old approved crop").unwrap();
    let source = fs::read(&x.source).unwrap();
    for publication in [false, true] {
        let mut first_rendered = false;
        let mut reached_failure = false;
        let result =
            c::crop_document_observed(&a, p::AdmissionLimits::default(), |boundary, path| {
                if boundary == c::CropBoundary::BeforeRender
                    && path.file_name().unwrap() == "fig-second.png"
                {
                    first_rendered = true;
                    if !publication {
                        reached_failure = true;
                        anyhow::bail!("injected second render failure");
                    }
                }
                if publication
                    && boundary
                        == c::CropBoundary::Publication(
                            revayat_scientific::publication::Boundary::BeforeCommit,
                        )
                    && path.file_name().unwrap() == "fig-second.png"
                {
                    reached_failure = true;
                    anyhow::bail!("injected second publication failure");
                }
                Ok(())
            });
        assert!(result.is_err());
        assert!(first_rendered && reached_failure);
        assert_eq!(fs::read(&output).unwrap(), b"old approved crop");
        assert_eq!(
            fs::read_dir(&a.out)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>(),
            vec![std::ffi::OsString::from("fig-first.png")]
        );
        assert_eq!(fs::read(&x.source).unwrap(), source);
    }
    assert_eq!(c::crop_document(&a).unwrap(), 2);
    let image = image::open(&output).unwrap().to_rgb8();
    assert_eq!(image.dimensions(), (22, 80));
    assert!(image.pixels().any(|p| p.0 == [255, 0, 0]));
    assert_eq!(fs::read(&x.source).unwrap(), source);
}
#[test]
#[ignore = "requires Poppler"]
fn test_selected_crop_admission_preserves_source() {
    let x = Fixture::new();
    let a = explicit(&x);
    fs::create_dir(&a.out).unwrap();
    let output = a.out.join("fig-sample.png");
    x.save(document(2));
    assert_eq!(
        p::page_ids(&p::open_pdf(&x.source, false).unwrap())
            .unwrap()
            .len(),
        2
    );
    let ordinary = fs::read(&x.source).unwrap();
    for limits in [
        p::AdmissionLimits {
            max_bytes: 1,
            ..Default::default()
        },
        p::AdmissionLimits {
            max_pages: 1,
            ..Default::default()
        },
        p::AdmissionLimits {
            max_objects: 1,
            ..Default::default()
        },
    ] {
        fs::write(&output, b"old crop").unwrap();
        let mut reached_render = false;
        assert!(
            c::crop_document_observed(&a, limits, |_, _| {
                reached_render = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!reached_render);
        assert_eq!(fs::read(&output).unwrap(), b"old crop");
        assert_eq!(fs::read(&x.source).unwrap(), ordinary);
        assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
    }
    for kind in ["ordinary", "signature", "encrypted", "repaired"] {
        let mut d = painted_page([0., 0., 400., 500.], [60., 370., 120., 430.]);
        if kind == "signature" {
            let id = d.add_object(dictionary!{"Type"=>"Sig","ByteRange"=>vec![0.into(),10.into(),20.into(),30.into()]});
            d.catalog_mut()
                .unwrap()
                .set("Perms", dictionary! { "DocMDP"=>id });
        }
        if kind == "encrypted" {
            pdf_encryption::encrypt(&mut d, "");
            assert!(d.trailer.has(b"Encrypt"));
        }
        x.save(d);
        if kind == "repaired" {
            let raw = fs::read(&x.source).unwrap();
            let offset = raw.windows(9).position(|s| s == b"startxref").unwrap();
            fs::write(&x.source, [&raw[..offset], b"%%EOF\n"].concat()).unwrap();
        }
        let before = fs::read(&x.source).unwrap();
        let a = explicit(&x);
        fs::create_dir_all(&a.out).unwrap();
        let output = a.out.join("fig-sample.png");
        fs::write(&output, b"old crop").unwrap();
        let result = c::crop_document(&a);
        if kind == "encrypted" || kind == "repaired" {
            assert!(result.is_err());
            assert_eq!(fs::read(&output).unwrap(), b"old crop");
        } else {
            result.unwrap();
            let crop = image::open(&output).unwrap().to_rgb8();
            assert_eq!(crop.dimensions(), (60, 60));
            assert!(crop.pixels().any(|p| p.0 == [255, 0, 0]));
            if kind == "signature" {
                let admitted = p::open_pdf(&x.source, false).unwrap();
                let signature = admitted
                    .catalog()
                    .unwrap()
                    .get(b"Perms")
                    .unwrap()
                    .as_dict()
                    .unwrap()
                    .get(b"DocMDP")
                    .unwrap()
                    .as_reference()
                    .unwrap();
                assert_eq!(
                    admitted
                        .get_object(signature)
                        .unwrap()
                        .as_dict()
                        .unwrap()
                        .get(b"Type")
                        .unwrap()
                        .as_name()
                        .unwrap(),
                    b"Sig"
                );
            }
        }
        assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
#[ignore = "requires Poppler"]
fn test_crop_preserves_source_sampling_and_rotation() {
    let x = Fixture::new();
    let mut d = document(2);
    image_page(&mut d, 720, 360, vec![150; 720 * 360 * 3], false);
    let page_ids = pages(&d);
    let first = d
        .get_object(page_ids[0])
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    let second = d
        .get_object_mut(page_ids[1])
        .unwrap()
        .as_dict_mut()
        .unwrap();
    second.set("Contents", first.get(b"Contents").unwrap().clone());
    second.set("Resources", first.get(b"Resources").unwrap().clone());
    second.set("Rotate", 90);
    x.save(d.clone());
    let before = fs::read(&x.source).unwrap();
    let a = args(&x);
    fs::write(
        a.map.as_ref().unwrap(),
        "figure_id\tpdf_page\nnormal\t1\nrotated\t2\n",
    )
    .unwrap();
    let output = run(
        &CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
            std::ffi::OsStr::new("crop"),
            a.pdf.as_os_str(),
            std::ffi::OsStr::new("--out"),
            a.out.as_os_str(),
            std::ffi::OsStr::new("--map"),
            a.map.as_ref().unwrap().as_os_str(),
            std::ffi::OsStr::new("--dpi"),
            std::ffi::OsStr::new("300"),
        ]),
    )
    .unwrap();
    assert!(
        output.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for name in ["normal", "rotated"] {
        let out = a.out.join(format!("fig-{name}.png"));
        let im = image::open(&out).unwrap();
        assert!(im.width().max(im.height()) >= 720);
        let reader = png::Decoder::new(std::io::BufReader::new(fs::File::open(out).unwrap()))
            .read_info()
            .unwrap();
        let density = reader.info().pixel_dims.unwrap();
        assert!(density.xppu as f64 * 0.0254 >= 359.);
        assert!(density.yppu as f64 * 0.0254 >= 359.);
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
fn test_crop_rejects_oversized_allocation_and_invalid_density() {
    let x = Fixture::new();
    let mut d = document(1);
    let page = pages(&d)[0];
    d.get_object_mut(page).unwrap().as_dict_mut().unwrap().set(
        "MediaBox",
        vec![0.into(), 0.into(), 1000.into(), 1000.into()],
    );
    x.save(d);
    let mut a = explicit(&x);
    fs::write(
        a.map.as_ref().unwrap(),
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nsample\t1\t0\t0\t1000\t1000\n",
    )
    .unwrap();
    fs::create_dir(&a.out).unwrap();
    let old = a.out.join("fig-sample.png");
    fs::write(&old, b"previous output must survive").unwrap();
    for dpi in [2400, 0] {
        a.dpi = dpi;
        assert!(c::crop_document(&a).is_err());
        assert_eq!(fs::read(&old).unwrap(), b"previous output must survive");
        let public = run(
            &CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
                "crop".into(),
                a.pdf.clone().into_os_string(),
                "--out".into(),
                a.out.clone().into_os_string(),
                "--map".into(),
                a.map.clone().unwrap().into_os_string(),
                "--dpi".into(),
                dpi.to_string().into(),
            ]),
        )
        .unwrap();
        assert_eq!(public.code, 2);
        let error = String::from_utf8(public.stderr).unwrap();
        assert!(error.contains(if dpi == 0 {
            "--dpi must be"
        } else {
            "50 million pixels"
        }));
        assert_eq!(fs::read(&old).unwrap(), b"previous output must survive");
        assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
    }
}
#[test]
fn test_image_preparation_and_pdf_pages() {
    let x = Fixture::new();
    let figures = x.temp.path().join("figures");
    fs::create_dir(&figures).unwrap();
    let image = figures.join("asset.png");
    image::RgbaImage::from_pixel(80, 60, image::Rgba([160, 190, 220, 128]))
        .save(&image)
        .unwrap();
    let original = fs::read(&image).unwrap();
    let result = run(&CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["figures", figures.to_str().unwrap()]))
    .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(image.with_file_name("asset.png.orig")).unwrap(),
        original
    );
    assert_eq!(image::open(&image).unwrap().color(), image::ColorType::Rgb8);
    let checked = run(
        &CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
            "figures",
            figures.to_str().unwrap(),
            "--check",
        ]),
    )
    .unwrap();
    assert!(
        checked.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let mut doc = document(3);
    let raster = image::open(&image).unwrap().to_rgb8();
    let asset = doc.add_object(lopdf::Stream::new(dictionary! {"Type"=>"XObject","Subtype"=>"Image","Width"=>80,"Height"=>60,"BitsPerComponent"=>8,"ColorSpace"=>"DeviceRGB"},raster.into_raw()));
    for page in pages(&doc) {
        let mut resources = revayat_scientific::pdf_forms::inherited(&doc, page, b"Resources")
            .unwrap()
            .unwrap()
            .as_dict()
            .unwrap()
            .clone();
        resources.set("XObject", dictionary! {"Im1"=>asset});
        doc.get_object_mut(page)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Resources", resources);
        doc.add_to_page_content(
            page,
            lopdf::content::Content {
                operations: vec![
                    lopdf::content::Operation::new("q", vec![]),
                    lopdf::content::Operation::new(
                        "cm",
                        vec![
                            160.into(),
                            0.into(),
                            0.into(),
                            120.into(),
                            50.into(),
                            200.into(),
                        ],
                    ),
                    lopdf::content::Operation::new(
                        "Do",
                        vec![lopdf::Object::Name(b"Im1".to_vec())],
                    ),
                    lopdf::content::Operation::new("Q", vec![]),
                ],
            },
        )
        .unwrap();
    }
    x.save(doc);
    let before = fs::read(&x.source).unwrap();
    let result = run(
        &CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args([
            "pages",
            x.source.to_str().unwrap(),
            x.output.to_str().unwrap(),
            "2-3",
        ]),
    )
    .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let extracted = p::open_pdf(&x.output, false).unwrap();
    assert_eq!(p::page_ids(&extracted).unwrap().len(), 2);
    assert_eq!(pdf_content::artwork(&extracted, 1).unwrap().1.len(), 1);
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
