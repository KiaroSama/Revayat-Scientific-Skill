#[path = "common/pdf.rs"]
mod common;
use common::*;
use lopdf::dictionary;
use revayat_scientific::{crop as c, pdf as p, pdf_content};
use std::fs;
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
    assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
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
}
#[test]
#[ignore = "requires Poppler"]
fn test_explicit_edge_crop_and_late_failures_preserve_batch() {
    let x = Fixture::new();
    x.save(document(1));
    let a = explicit(&x);
    c::crop_document(&a).unwrap();
    let output = a.out.join("fig-sample.png");
    let image = image::open(&output).unwrap();
    assert_eq!((image.width(), image.height()), (60, 60));
    let before = fs::read(&output).unwrap();
    fs::write(
        a.map.as_ref().unwrap(),
        "figure_id\tpdf_page\tx0\ty0\tx1\ty1\nsample\t1\t0\t0\t60\t60\nlate\t1\t390\t0\t450\t60\n",
    )
    .unwrap();
    assert!(c::crop_document(&a).is_err());
    assert_eq!(fs::read(output).unwrap(), before);
}
#[test]
#[ignore = "requires Poppler"]
fn test_selected_crop_admission_preserves_source() {
    let x = Fixture::new();
    for kind in ["ordinary", "signature", "encrypted", "repaired"] {
        let mut d = document(1);
        if kind == "signature" {
            d.add_object(dictionary!{"Type"=>"Sig","ByteRange"=>vec![0.into(),10.into(),20.into(),30.into()]});
        }
        if kind == "encrypted" {
            let id = d.add_object(dictionary! {"Filter"=>"Standard","V"=>1,"R"=>2});
            d.trailer.set("Encrypt", id);
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
            assert_eq!(image::open(&output).unwrap().width(), 60);
        }
        assert_eq!(fs::read(&x.source).unwrap(), before);
    }
}
#[test]
#[ignore = "requires Poppler"]
fn test_crop_preserves_source_sampling_and_rotation() {
    let x = Fixture::new();
    let mut d = blank();
    image_page(&mut d, 720, 360, vec![150; 720 * 360 * 3], false);
    for rotation in [0, 90] {
        d.get_object_mut(pages(&d)[0])
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Rotate", rotation);
        x.save(d.clone());
        let before = fs::read(&x.source).unwrap();
        let a = args(&x);
        fs::write(a.map.as_ref().unwrap(), "figure_id\tpdf_page\nnormal\t1\n").unwrap();
        let (_, images) = pdf_content::artwork(&d, 1).unwrap();
        assert!(c::crop_dpi(&images, p::geometry(&d).unwrap()[0].rect, 300).unwrap() >= 360);
        c::crop_document(&a).unwrap();
        let out = a.out.join("fig-normal.png");
        let im = image::open(&out).unwrap();
        assert!(im.width().max(im.height()) >= 720);
        let reader = png::Decoder::new(std::io::BufReader::new(fs::File::open(out).unwrap()))
            .read_info()
            .unwrap();
        let density = reader.info().pixel_dims.unwrap();
        assert!(density.xppu as f64 * 0.0254 >= 359.);
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
        assert_eq!(fs::read_dir(&a.out).unwrap().count(), 1);
    }
}
#[test]
fn test_image_preparation_and_pdf_pages() {
    let x = Fixture::new();
    let image = x.temp.path().join("asset.png");
    image::RgbaImage::from_pixel(20, 20, image::Rgba([100, 150, 200, 128]))
        .save(&image)
        .unwrap();
    let original = fs::read(&image).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args(["figures", image.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(image.with_file_name("asset.png.orig")).unwrap(),
        original
    );
    assert_eq!(image::open(&image).unwrap().color(), image::ColorType::Rgb8);
    x.save(document(3));
    let before = fs::read(&x.source).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_revayat-scientific"))
        .args([
            "pages",
            x.source.to_str().unwrap(),
            x.output.to_str().unwrap(),
            "2-3",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        p::page_ids(&p::open_pdf(&x.output, false).unwrap())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(fs::read(&x.source).unwrap(), before);
}
