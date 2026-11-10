fn delivery_command(
    executable: &Path,
    directory: &Path,
    args: &[&str],
    repository: Option<&Path>,
) -> Result<revayat_scientific::runtime::CommandOutput> {
    let mut command = revayat_scientific::runtime::CommandSpec::new(executable.as_os_str())
        .args(args.iter().copied());
    command.cwd = Some(directory.to_owned());
    command.env_remove.push("REVAYAT_REPOSITORY".into());
    if let Some(repository) = repository {
        command.env.insert("REVAYAT_REPOSITORY".into(), repository.as_os_str().into());
    } else {
        // Installed/extracted binaries must resolve their own sibling companion,
        // without borrowing the build tree's owner or dropping nested accounting.
        command.env_remove.push("REVAYAT_RUNTIME_OWNER".into());
    }
    command.timeout = std::time::Duration::from_secs(30);
    command.max_output = 128 * 1024;
    revayat_scientific::runtime::run(&command)
}
#[cfg(unix)]
fn assert_companion_layout(executable: &Path, directory: &Path) -> Result<()> {
    let companion = executable.parent().unwrap().join("revayat-process-owner");
    assert_eq!(fs::read(&companion)?, fs::read(env!("CARGO_BIN_EXE_revayat-process-owner"))?);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(&companion)?.permissions().mode() & 0o777, 0o755);
    let version = delivery_command(&companion, directory, &["--version"], None)?;
    assert!(version.success());
    assert_eq!(std::str::from_utf8(&version.stdout)?.trim(), "revayat-process-owner 2.0.0");
    let held = companion.with_file_name("retained-owner");
    fs::rename(&companion, &held)?;
    let missing = delivery_command(executable, directory,
        &["run-check", "--timeout", "5", "--", held.to_str().unwrap(), "--version"], None);
    fs::rename(&held, &companion)?;
    let missing = missing?;
    assert!(!missing.success(), "installed entry must not borrow original build companion");
    let ready = delivery_command(executable, directory,
        &["run-check", "--timeout", "5", "--", companion.to_str().unwrap(), "--version"], None)?;
    assert!(ready.success());
    assert_eq!(std::str::from_utf8(&ready.stdout)?.trim(), "revayat-process-owner 2.0.0");
    Ok(())
}
fn assert_document_commands(executable: &Path, directory: &Path) -> Result<()> {
    use lopdf::{Document, Object, Stream, dictionary};
    let content = directory.join("محتوا.json");
    let docx = directory.join("ترجمه.docx");
    let report = directory.join("docx-report.json");
    fs::write(&content, serde_json::to_vec(&serde_json::json!({
        "language":"fa-IR", "rtl":true, "sections":[{
            "width_mm":160,"height_mm":240,
            "margins_mm":{"top":15,"bottom":15,"left":15,"right":15},
            "blocks":[{"type":"paragraph","text":"این یک متن علمی فارسی است."}]
        }]
    }))?)?;
    for args in [
        vec!["docx", "create", content.to_str().unwrap(), docx.to_str().unwrap()],
        vec!["docx", "inspect", docx.to_str().unwrap(), "--output", report.to_str().unwrap()],
    ] {
        let output = delivery_command(executable, directory, &args, None)?;
        assert!(output.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }
    let mut archive = zip::ZipArchive::new(fs::File::open(&docx)?)?;
    let mut xml = String::new();
    archive.by_name("word/document.xml")?.read_to_string(&mut xml)?;
    assert!(xml.contains("متن علمی فارسی"));
    let metadata: serde_json::Value = serde_json::from_slice(&fs::read(report)?)?;
    assert!(!metadata["text_nodes"].as_array().unwrap().is_empty());
    let source = directory.join("source.pdf");
    let extracted = directory.join("pdf-text.json");
    let mut document = Document::with_version("1.7");
    let pages = document.new_object_id();
    let font = document.add_object(dictionary!{"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>"Helvetica"});
    let stream = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 20 30 Td (Scientific package boundary) Tj ET".to_vec(),
    ));
    let page = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages,
        "MediaBox" => vec![0.into(), 0.into(), 230.into(), 340.into()],
        "Resources" => dictionary! {"Font" => dictionary! {"F1" => font}},
        "Contents" => stream,
    });
    document.objects.insert(pages, Object::Dictionary(dictionary! {
        "Type" => "Pages", "Kids" => vec![Object::Reference(page)], "Count" => 1,
    }));
    let catalog = document.add_object(dictionary! {"Type" => "Catalog", "Pages" => pages});
    document.trailer.set("Root", catalog);
    document.save(&source)?;
    let original = fs::read(&source)?;
    let output = delivery_command(executable, directory, &["pdf", "text", source.to_str().unwrap(), extracted.to_str().unwrap()], None)?;
    assert!(output.success());
    let text: serde_json::Value = serde_json::from_slice(&fs::read(extracted)?)?;
    assert_eq!(text["pages"][0]["text"].as_str().unwrap().trim(), "Scientific package boundary");
    assert_eq!(fs::read(source)?, original);
    let original_text = directory.join("اصل.txt");
    let terms = directory.join("terms.tsv");
    fs::write(&original_text, "核融合 در گزارش.")?;
    fs::write(&terms, "source\toutput\tconcept\tstatus\n核融合\tهمجوشی هسته‌ای\tphysics-fusion\tpreferred\n")?;
    let output = delivery_command(executable, directory, &["term-brief", original_text.to_str().unwrap(), "--terms", terms.to_str().unwrap(), "--language", "ja"], None)?;
    assert!(output.success());
    let brief: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(brief["terms"][0]["output"], "همجوشی هسته‌ای");
    Ok(())
}
