use revayat_scientific::{
    build::select_source_with_available,
    tex::{plain_tex, source_closure},
};
use std::{collections::BTreeSet, fs};
#[test]
fn test_selection_honors_explicit_engine_and_actual_source() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let tex = root.join("document.tex");
    let html = tex.with_extension("html");
    fs::write(&tex, "source").unwrap();
    fs::write(&html, "<html></html>").unwrap();
    let chromium = BTreeSet::from(["chromium".to_owned()]);
    let both = BTreeSet::from(["tex".to_owned(), "chromium".to_owned()]);
    let weasyprint = BTreeSet::from(["weasyprint".to_owned()]);
    let all = BTreeSet::from([
        "tex".to_owned(),
        "chromium".to_owned(),
        "weasyprint".to_owned(),
    ]);
    assert_eq!(
        select_source_with_available(&tex, None, &chromium).unwrap(),
        (html.clone(), "chromium".into())
    );
    assert_eq!(
        select_source_with_available(&tex, Some("chromium"), &both).unwrap(),
        (html.clone(), "chromium".into())
    );
    assert!(select_source_with_available(&html, Some("tex"), &both).is_err());
    assert!(
        select_source_with_available(&html, Some("chromium"), &BTreeSet::from(["tex".into()]))
            .is_err()
    );
    assert!(select_source_with_available(&tex, Some("tex"), &chromium).is_err());
    // Optional external WeasyPrint retains its renderer identity and requires
    // its own successful discovery capability; Chromium never satisfies it.
    for source in [&tex, &html] {
        assert_eq!(
            select_source_with_available(source, Some("weasyprint"), &all).unwrap(),
            (html.clone(), "weasyprint".into())
        );
        assert!(select_source_with_available(source, Some("weasyprint"), &both).is_err());
        for requested in [None, Some("auto"), Some("weasyprint")] {
            assert_eq!(
                select_source_with_available(source, requested, &weasyprint).unwrap(),
                (html.clone(), "weasyprint".into())
            );
        }
    }
    for requested in [None, Some("auto")] {
        assert_eq!(
            select_source_with_available(&tex, requested, &all).unwrap(),
            (tex.clone(), "tex".into())
        );
        assert_eq!(
            select_source_with_available(&html, requested, &all).unwrap(),
            (html.clone(), "chromium".into())
        );
    }
    assert!(select_source_with_available(&html, Some("unknown"), &all).is_err());
    fs::remove_file(&html).unwrap();
    assert!(select_source_with_available(&tex, Some("weasyprint"), &weasyprint).is_err());
}
#[test]
fn test_nested_prose_and_repeated_includes_keep_order_and_location() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let chapter = root.join("chapter.tex");
    let main = root.join("main.tex");
    fs::write(&chapter, "متن \\textbf{علمی \\textit{روشن}}\n").unwrap();
    fs::write(
        &main,
        "\\begin{document}\n\\input{chapter}\nپایان\n\\input{chapter}\n\\end{document}",
    )
    .unwrap();
    let closure = source_closure(&main, None).unwrap();
    let plain = plain_tex(&closure.text).unwrap();
    assert_eq!(plain.matches("علمی روشن").count(), 2);
    assert!(plain.find("علمی روشن").unwrap() < plain.find("پایان").unwrap());
    assert_eq!(
        closure.location(closure.text.find("متن").unwrap() as isize),
        (chapter.clone(), 1)
    );
    assert_eq!(closure.sources, [main.clone(), chapter.clone()]);
    let repeated = closure.text.rfind("متن").unwrap();
    assert_eq!(closure.location(repeated as isize), (chapter.clone(), 1));
    assert_eq!(
        closure.location(closure.text.find("پایان").unwrap() as isize),
        (main.clone(), 3)
    );
    fs::write(chapter, r"\input{main}").unwrap();
    assert!(
        source_closure(&main, None)
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
}
#[test]
fn test_dynamic_and_outside_includes_are_explicit_failures() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("job");
    fs::create_dir(&root).unwrap();
    let source = root.join("main.tex");
    fs::write(temp.path().join("outside.tex"), "foreign sentinel").unwrap();
    for include in [r"\input{\chaptername}", r"\input{../outside.tex}"] {
        fs::write(&source, include).unwrap();
        assert!(source_closure(&source, None).is_err());
    }
}
