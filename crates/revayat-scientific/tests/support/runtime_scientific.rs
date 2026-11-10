use super::fixture::{Fixture, repo};
use anyhow::Result;
use std::fs;
#[cfg(target_os = "linux")]
pub(super) fn probe_output_integrity() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fs::create_dir(root.join("input"))?;
    fs::create_dir(root.join("output"))?;
    fs::write(root.join("input/sentinel.txt"), b"public sandbox fixture")?;
    fs::write(root.join("output/probe.txt"), b"allowed output\n")?;
    fs::write(
        root.join("output/sandbox-verified.json"),
        b"{\"verified\":true,\"checks\":29}",
    )?;
    revayat_scientific::sandbox::verify_probe_output(root)?;
    for (name, bytes) in [
        ("input/sentinel.txt", b"changed input".as_slice()),
        ("output/probe.txt", b"allowed output".as_slice()),
        (
            "output/sandbox-verified.json",
            b"{\"verified\":true,\"checks\":28}".as_slice(),
        ),
    ] {
        let path = root.join(name);
        let original = fs::read(&path)?;
        fs::write(&path, bytes)?;
        assert!(revayat_scientific::sandbox::verify_probe_output(root).is_err());
        fs::write(path, original)?;
    }
    Ok(())
}
pub(super) fn multipart_geometry_images_math_and_verified_delivery() -> Result<()> {
    let f = Fixture::new()?;
    fs::create_dir(f.root.join("chapters"))?;
    fs::create_dir(f.root.join("figures"))?;
    image::RgbImage::from_pixel(600, 300, image::Rgb([120, 180, 220]))
        .save(f.root.join("figures/plot.png"))?;
    let template =
        fs::read_to_string(repo().join("skills/revayat-scientific/assets/rtl-document.tex"))?
            .replace(
                "paperwidth=210mm,paperheight=297mm",
                "paperwidth=180mm,paperheight=240mm",
            )
            .replace("\\maketitle", "\\maketitle\n\\input{chapters/body}");
    let source = f.root.join("document.tex");
    fs::write(&source, template)?;
    let figure = "\n\\begin{LTR}\\includegraphics[width=50mm]{figures/plot.png}\\end{LTR}\n\\begin{tabular}{ll}کمیت & مقدار \\\\ دما & \\en{23.5 C} \\\\ \\end{tabular}\n\\begin{latin}La mesure dépend des conditions expérimentales.\\end{latin}\n";
    let body = fs::read_to_string(repo().join("tests/fixtures/build-smoke-body.tex"))?.replacen(
        "\\clearpage",
        &format!("{figure}\\clearpage"),
        1,
    );
    fs::write(f.root.join("chapters/body.tex"), body)?;
    fs::write(f.root.join("manifest.txt"), b"plot.png\n")?;
    let args = vec![
        source.display().to_string(),
        "article".into(),
        "--engine".into(),
        "tex".into(),
        "--level".into(),
        "journal".into(),
        "--verify".into(),
        "--output-dir".into(),
        f.root.join("delivered").display().to_string(),
    ];
    let mut command = vec![
        "--timeout".into(),
        "240".into(),
        std::ffi::OsString::from("build"),
    ];
    command.extend(args.iter().map(std::ffi::OsString::from));
    let built = f.run(command.clone(), 260, [])?;
    if !built.success() {
        let error = anyhow::anyhow!("scientific build failed: {}", built.stderr_text());
        let evidence = repo().join(".scratch/native-render-evidence");
        fs::create_dir_all(&evidence)?;
        if source.with_extension("pdf").is_file() {
            fs::copy(source.with_extension("pdf"), evidence.join("multipart.pdf"))?;
        }
        fs::write(
            evidence.join("multipart-source.txt"),
            revayat_scientific::text_order::source_plain(&source)?,
        )?;
        return Err(error);
    }
    let document = revayat_scientific::pdf::open_pdf(&f.output, false)?;
    let pages = revayat_scientific::pdf::geometry(&document)?;
    assert!(pages.len() >= 3);
    for page in &pages {
        assert!((page.rect[2] - 180.0 * 72.0 / 25.4).abs() < 0.5);
        assert!((page.rect[3] - 240.0 * 72.0 / 25.4).abs() < 0.5);
    }
    // Poppler supplies independent floating word bounds, matching the baseline's
    // full body clip while excluding legitimate Persian footer/page-number text.
    let mut extraction = revayat_scientific::runtime::CommandSpec::new(
        revayat_scientific::runtime::executable("pdftotext")?,
    )
    .args(["-f", "1", "-l", "1", "-enc", "UTF-8", "-bbox"]);
    extraction
        .args
        .extend([f.output.clone().into_os_string(), "-".into()]);
    extraction.cwd = Some(f.root.clone());
    extraction.timeout = std::time::Duration::from_secs(30);
    extraction.max_output = 2 * 1024 * 1024;
    let extracted = revayat_scientific::runtime::run(&extraction)?;
    anyhow::ensure!(
        extracted.success(),
        "body text consumer failed: {}",
        extracted.stderr_text()
    );
    let text = std::str::from_utf8(&extracted.stdout)?;
    // Poppler emits an external XHTML DOCTYPE. Parse the document element only;
    // this independent consumer never resolves external entities or DTDs.
    let start = text
        .find("<html")
        .ok_or_else(|| anyhow::anyhow!("missing text XHTML root"))?;
    let xml = roxmltree::Document::parse(&text[start..])?;
    let words = xml
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "word");
    let mut first = String::new();
    for word in words {
        let coordinate = |name| -> Result<f64> {
            Ok(word
                .attribute(name)
                .ok_or_else(|| anyhow::anyhow!("missing word {name}"))?
                .parse()?)
        };
        let [x0, y0, x1, y1] = [
            coordinate("xMin")?,
            coordinate("yMin")?,
            coordinate("xMax")?,
            coordinate("yMax")?,
        ];
        if x0 >= 0. && y0 >= 0. && x1 <= pages[0].rect[2] && y1 <= pages[0].rect[3] - 55. {
            first.push_str(word.text().unwrap_or(""));
            first.push(' ');
        }
    }
    let compact = first.split_whitespace().collect::<String>();
    for number in ["3.14", "2.5", "0.25"] {
        assert!(
            compact.contains(number),
            "missing mathematical value {number}"
        );
    }
    assert!(
        !first
            .chars()
            .any(|c| ('\u{0660}'..='\u{0669}').contains(&c)
                || ('\u{06f0}'..='\u{06f9}').contains(&c)),
        "scientific numeric content must use ASCII digits"
    );
    assert!((1..=pages.len()).any(|p| {
        revayat_scientific::pdf_content::artwork(&document, p)
            .is_ok_and(|(_, images)| images.iter().any(|i| i.width == 600 && i.height == 300))
    }));
    assert_eq!(
        fs::read(&f.output)?,
        fs::read(source.with_extension("pdf"))?
    );
    for sample in f.samples() {
        image::open(sample)?;
    }
    let approved = fs::read(&f.output)?;
    let mut body = fs::read_to_string(f.root.join("chapters/body.tex"))?;
    body.push_str("\nاين متن باید رد شود.\n");
    fs::write(f.root.join("chapters/body.tex"), body)?;
    let failed = f.run(command, 90, [])?;
    assert!(!failed.success());
    assert!(failed.stderr_text().contains("arabic-letters"));
    assert_eq!(fs::read(&f.output)?, approved);
    f.clean()
}
