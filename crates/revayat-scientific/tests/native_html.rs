//! Native ports of HTML source, context integrity and scope boundary regressions.
use revayat_scientific::{
    html::{HtmlSource, ParsedHtml},
    lint::{self, Source},
    resource::ResourcePolicy,
};
use std::{fs, path::PathBuf};
fn model(body: &str) -> HtmlSource {
    HtmlSource::from_text(
        &PathBuf::from("/tmp/document.html"),
        &format!("<html lang=\"fa\" dir=\"rtl\"><body>{body}</body></html>"),
    )
    .unwrap()
}
fn live(body: &str) -> HtmlSource {
    let m = model(body);
    let p = m.html.text.rfind("كي").unwrap();
    assert!(!m.is_protected(p), "{body}");
    assert!(!m.suppressed(p, "arabic-letters"), "{body}");
    m
}
fn invalid(body: &str) {
    assert!(
        ParsedHtml::parse(&format!("<html lang=fa><body>{body}</body></html>")).is_err(),
        "{body}"
    );
}
fn findings(body: &str) -> Vec<lint::Finding> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("doc.html");
    fs::write(
        &p,
        format!("<html lang=\"fa\" dir=\"rtl\"><body>{body}</body></html>"),
    )
    .unwrap();
    lint::check(&Source::load(&p).unwrap(), &[], None, "system-docs").unwrap()
}
#[test]
fn test_rcdata_comment_text_never_grants_a_waiver() {
    for tag in ["textarea", "title"] {
        for slash in ["", "/"] {
            let m = live(&format!(
                "<{tag}{slash}><!-- fa-lint: allow all --></{tag}>كي"
            ));
            assert!(m.html.comments.is_empty());
        }
    }
}
#[test]
fn test_rcdata_markup_is_text_not_an_asset_or_active_element() {
    for tag in ["textarea", "title"] {
        for slash in ["", "/"] {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("doc.html");
            fs::write(&p,format!("<html><{tag}{slash}><img src=\"missing.png\"><script>literal</script></{tag}>متن</html>")).unwrap();
            let m = HtmlSource::load(&p).unwrap();
            assert!(m.html.image_references().is_empty());
            assert!(!m.html.nodes.iter().any(|n| n.tag == "script"));
            assert!(!m.is_protected(m.html.text.rfind("متن").unwrap()));
            ResourcePolicy::new(&p).unwrap();
        }
    }
}
#[test]
fn test_rcdata_character_references_decode_once_with_correct_offsets() {
    for ending in ["</textarea>", "</TEXTAREA >"] {
        for newline in ["\n", "\r\n"] {
            let m = model(&format!(
                "<textarea>&#1603;&amp;#1603; &NotEqualTilde;{ending}{newline}متن"
            ));
            assert!(m.html.text.contains("ك&#1603; ≂̸"), "{}", m.html.text);
            let after = m.html.text.rfind("متن").unwrap();
            assert_eq!(m.line_of(after), 2);
            let raw = m.html.raw.rfind("متن").unwrap();
            assert_eq!(m.html.original_offset(after), raw);
            assert_eq!(m.html.normalized_offset(raw), after);
        }
    }
}
#[test]
fn test_rcdata_end_tag_attributes_do_not_hide_following_text() {
    for end in [
        "</textarea data-x=1>",
        "</textarea data-x=\">\">",
        "</textarea/>",
    ] {
        live(&format!("<textarea>literal{end}كي"));
    }
}
#[test]
fn test_raw_text_comments_do_not_grant_a_waiver() {
    for tag in ["style", "script", "xmp", "iframe", "noembed", "noframes"] {
        let m = live(&format!(
            "<{tag}><!-- fa-lint: allow all --><img src=\"fake.png\"></{tag}>كي"
        ));
        assert!(m.html.image_references().is_empty());
    }
}
#[test]
fn test_templates_fail_explicitly_before_claiming_engine_independent_coverage() {
    for attrs in [
        "",
        "/",
        " shadowrootmode=\"open\"",
        " shadowrootmode=\"closed\"",
    ] {
        for body in [
            "<img src=\"missing.png\">",
            "<!-- fa-lint: allow all -->",
            "<script>never run</script>",
            "</body><template>nested</template>",
        ] {
            let error = ParsedHtml::parse(&format!("<html><template{attrs}>{body}</template>كي"))
                .unwrap_err();
            assert!(error.to_string().contains("static"));
        }
    }
}
#[test]
fn test_plaintext_is_explicitly_unsupported_but_rcdata_examples_are_safe() {
    for tag in ["<plaintext>", "<plaintext/>"] {
        invalid(&format!("{tag}<!-- fa-lint: allow all -->كي"));
    }
    assert!(
        live("<textarea><template>literal</template><plaintext>literal</textarea>كي")
            .html
            .image_references()
            .is_empty()
    );
}
#[test]
fn test_nonvoid_html_slash_does_not_end_an_isolate() {
    for tag in ["span", "div", "bdi"] {
        let m = live(&format!("<{tag} dir=\"ltr\"/>125</{tag}>كي"));
        assert!(m.is_protected(m.html.text.find("125").unwrap()));
    }
}
#[test]
fn test_void_html_slash_does_not_capture_following_prose() {
    for tag in ["br", "hr", "input"] {
        live(&format!("<{tag}/>كي"));
    }
}
#[test]
fn test_foreign_self_closing_elements_remain_self_closing() {
    for markup in [
        "<svg/>",
        "<math/>",
        "<svg><path/></svg>",
        "<math><mspace/></math>",
        "<svg><foreignObject/></svg>",
    ] {
        live(&format!("{markup}كي"));
    }
    let m = live("<svg><foreignObject><span dir=\"ltr\"/>125</span></foreignObject></svg>كي");
    assert!(m.is_protected(m.html.text.find("125").unwrap()));
}
#[test]
fn test_unterminated_raw_context_fails_instead_of_certifying_hidden_tail() {
    for opening in ["<textarea>", "<textarea/>", "<title>", "<xmp>", "<style>"] {
        invalid(&format!("{opening}literal<!-- fa-lint: allow all -->كي"));
    }
}
#[test]
fn test_real_comments_still_allow_only_the_requested_check() {
    let m = model("<!-- fa-lint: allow arabic-letters -->كي");
    let p = m.html.text.rfind("كي").unwrap();
    assert!(m.suppressed(p, "arabic-letters"));
    assert!(!m.suppressed(p, "unisolated-number"));
    assert!(!m.is_protected(p));
}
#[test]
fn test_comment_terminator_width_does_not_protect_following_prose() {
    for c in ["<!-- comment -->", "<!-- comment --!>", "<!-->", "<!--->"] {
        live(&format!("{c}كي"));
    }
}
#[test]
fn test_whitespace_comment_end_does_not_expose_a_renderer_hidden_tail() {
    let m = model("<!-- comment -- >كي<img src=\"fake.png\">");
    assert!(m.is_protected(m.html.text.rfind("كي").unwrap()));
    assert!(m.html.image_references().is_empty());
}
#[test]
fn test_live_active_content_remains_denied() {
    for markup in [
        "<script>active</script>",
        "<iframe></iframe>",
        "<object/>",
        "<base href=\"https://example.invalid/\">",
        "<a rel=\"attachment\">x</a>",
    ] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("doc.html");
        fs::write(&p, format!("<html>{markup}</html>")).unwrap();
        assert!(ResourcePolicy::new(&p).is_err(), "{markup}");
    }
}
#[test]
fn test_character_reference_text_cannot_become_a_node() {
    let m = live(
        "<textarea>&lt;img src=\"fake.png\"&gt;</textarea><span dir=\"ltr\">&#49;&#50;&#53;</span>كي",
    );
    assert!(m.html.image_references().is_empty());
    assert!(m.is_protected(m.html.text.find("125").unwrap()));
}
#[test]
fn test_rcdata_isolate_preserves_literal_tags_instead_of_stripping_them() {
    for b in [
        "<textarea dir=\"ltr\"><A>Alpha</A></textarea>",
        "<span dir=\"ltr\"><textarea><A>Alpha</A></textarea></span>",
    ] {
        let m = model(b);
        assert!(
            m.html
                .isolates
                .iter()
                .any(|i| i.body.trim() == "<A>Alpha</A>")
        );
        assert!(!m.html.nodes.iter().any(|n| n.tag == "a"));
    }
}
#[test]
fn test_literal_transform_text_is_not_executable_mirroring_css() {
    assert!(
        !findings("<textarea dir=\"ltr\">scaleX(-1)</textarea>")
            .iter()
            .any(|f| f.check == "mirrored-image")
    );
    assert!(
        findings("<style>img {transform: scaleX(-1)}</style>")
            .iter()
            .any(|f| f.check == "mirrored-image")
    );
}
#[test]
fn test_raw_end_tag_attributes_remain_entirely_nonprose() {
    let m =
        live("<textarea dir=\"ltr\">Alpha</textarea data-value=\">\" data-ignore=\"NotProse\">كي");
    assert!(m.is_protected(m.html.text.find("NotProse").unwrap()));
}
#[test]
fn test_unquoted_end_attribute_quotes_do_not_capture_following_markup() {
    for end in [
        "</textarea x=a'>",
        "</textarea x=a\">",
        "</textarea x=\"a>b\">",
        "</textarea x='a>b'>",
    ] {
        let m = live(&format!("<textarea>literal{end}كي<img src=\"real.png\">"));
        assert_eq!(
            m.html
                .image_references()
                .iter()
                .map(|r| r.1.as_str())
                .collect::<Vec<_>>(),
            ["real.png"]
        );
        assert!(m.html.comments.is_empty());
    }
}
#[test]
fn test_foreign_breakout_preserves_html_isolate_and_neighbor_checks() {
    for foreign in ["svg", "math"] {
        for (tag, attrs) in [
            ("span", "dir=\"ltr\""),
            ("p", "dir=\"ltr\""),
            ("font", "color=\"red\" dir=\"ltr\""),
        ] {
            let m = live(&format!("<{foreign}><{tag} {attrs}/>125</{tag}>كي"));
            assert!(m.is_protected(m.html.text.find("125").unwrap()));
            assert_eq!(m.html.nodes.last().unwrap().namespace, "html");
        }
    }
}
#[test]
fn test_public_lint_keeps_a_real_error_after_a_fake_waiver() {
    assert!(
        findings("<textarea/><!-- fa-lint: allow all --></textarea>كي")
            .iter()
            .any(|f| f.check == "arabic-letters")
    );
}
#[test]
fn test_paragraph_boundaries_end_language_hidden_and_isolate_scope() {
    for attrs in ["lang=\"en\"", "hidden", "dir=\"ltr\"", "class=\"en\""] {
        for block in ["p", "div", "section", "table", "h2", "ul"] {
            let tail = if block == "table" {
                "<tr><td>كي</td></tr>"
            } else {
                "كي"
            };
            live(&format!("<p {attrs}>English<{block}>{tail}</{block}>"));
        }
    }
}
#[test]
fn test_list_and_definition_item_boundaries_are_scoped() {
    for (a, b, w) in [
        ("li", "li", "ul"),
        ("li", "li", "ol"),
        ("dt", "dd", "dl"),
        ("dd", "dt", "dl"),
    ] {
        live(&format!("<{w}><{a} lang=\"en\">English<{b}>كي</{w}>"));
    }
}
#[test]
fn test_nested_lists_preserve_outer_scope_but_end_inner_item_scope() {
    live("<ul><li><ul><li lang=\"en\">English<li>كي</ul></li></ul>");
    let m = model("<ul><li lang=\"en\"><ul><li>كي</li></ul></li></ul>");
    assert!(m.is_protected(m.html.text.find("كي").unwrap()));
}
#[test]
fn test_table_cells_rows_and_groups_do_not_leak_language() {
    for (a, b) in [
        ("<td lang=\"en\">English", "<td>كي"),
        ("<th lang=\"en\">English", "<td>كي"),
        ("<td lang=\"en\">English", "<tr><td>كي"),
        ("<td lang=\"en\">English", "<tbody><tr><td>كي"),
    ] {
        live(&format!("<table><tbody><tr>{a}{b}</table>"));
    }
    live("<table><tbody lang=\"en\"><tr><td>English<tbody><tr><td>كي</table>");
}
#[test]
fn test_optional_head_end_does_not_protect_body() {
    for b in [
        "<head><title>English title</title><body><p>كي</p></body>",
        "<head><title>English title</title><p>كي</p>",
    ] {
        let m = HtmlSource::from_text(
            &PathBuf::from("/tmp/doc.html"),
            &format!("<html>{b}</html>"),
        )
        .unwrap();
        assert!(!m.is_protected(m.html.text.find("كي").unwrap()));
    }
}
#[test]
fn test_options_do_not_inherit_previous_option_language() {
    live("<select><option lang=\"en\">English<option>كي</select>");
    live("<select><optgroup lang=\"en\"><option>English<optgroup><option>كي</select>");
}
#[test]
fn test_heading_siblings_do_not_inherit_previous_heading_language() {
    live("<h1 lang=\"en\">English<h2>كي</h2>");
}
#[test]
fn test_misnested_formatting_requires_review_instead_of_silent_reconstruction() {
    for b in [
        "<p><b lang=\"en\">English<p>كي",
        "<b lang=\"en\"><i>English</b>كي</i>",
        "<a href=\"#a\">A<a href=\"#b\">B</a>",
        "<button>One<button>Two</button>",
        "<form>One<form>Two</form>",
    ] {
        invalid(b);
    }
}
#[test]
fn test_table_foster_parenting_and_ignored_select_children_fail_closed() {
    for b in [
        "<table lang=\"en\">كي<tr><td>Cell</td></tr></table>",
        "<table><div lang=\"en\">كي</div></table>",
        "<select><span lang=\"en\">كي</span></select>",
    ] {
        invalid(b);
    }
}
#[test]
fn test_formatting_end_across_special_node_still_refuses_adoption() {
    invalid("<b lang=\"en\"><p>A</b></p><p>كي</p>");
    live("<p><b lang=\"en\">A</b></p><p>كي</p>");
}
#[test]
fn test_special_start_and_end_barriers_preserve_inherited_state() {
    for b in [
        "<ul><li lang=\"en\"><section>A<li>كي</section></ul>",
        "<dl><dt lang=\"en\"><section>A<dd>كي</section></dl>",
        "<span lang=\"en\"><p>A</span><p>كي</p>",
        "<div lang=\"en\"><table><tr><td>A</div>كي</td></tr></table>",
    ] {
        let m = model(b);
        assert!(m.is_protected(m.html.text.find("كي").unwrap()), "{b}");
    }
    for b in [
        "<form hidden><div>A</form>كي</div>",
        "<form><div lang=\"en\">A</form>كي</div>",
    ] {
        invalid(b);
    }
    live("<form lang=\"en\">English</form><p>كي</p>");
}
#[test]
fn test_explicit_well_nested_equivalent_has_same_live_scopes() {
    let a = live("<p lang=\"en\">English<p>كي");
    let b = live("<p lang=\"en\">English</p><p>كي</p>");
    assert_eq!(
        a.html
            .nodes
            .iter()
            .filter(|n| n.tag == "p")
            .map(|n| &n.language)
            .collect::<Vec<_>>(),
        b.html
            .nodes
            .iter()
            .filter(|n| n.tag == "p")
            .map(|n| &n.language)
            .collect::<Vec<_>>()
    );
}
#[test]
fn test_render_policy_uses_same_structure_gate_and_preserves_input() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("doc.html");
    let bytes = b"<html><body><table>fostered text</table></body></html>";
    fs::write(&p, bytes).unwrap();
    assert!(ResourcePolicy::new(&p).is_err());
    assert_eq!(fs::read(&p).unwrap(), bytes);
}
#[test]
fn test_caption_colgroup_and_select_separator_boundaries() {
    for (a, b) in [
        ("<caption lang=\"en\">English", "<tr><td>كي"),
        ("<colgroup lang=\"en\"><col>", "<tbody><tr><td>كي"),
    ] {
        live(&format!("<table>{a}{b}</table>"));
    }
    invalid("<select><optgroup lang=\"en\"><option>English<hr>كي</select>");
}
#[test]
fn test_body_end_does_not_drop_scopes_for_browser_reprocessed_tail() {
    for attrs in ["lang=\"en\"", "hidden", "dir=\"ltr\""] {
        let m = HtmlSource::from_text(
            &PathBuf::from("doc.html"),
            &format!("<html><body {attrs}>English</body>كي</html>"),
        )
        .unwrap();
        assert!(m.is_protected(m.html.text.find("كي").unwrap()));
    }
}
#[test]
fn test_out_of_scope_item_end_does_not_pop_an_outer_list() {
    let m = model("<ul><li lang=\"en\"><ul><li>X</li></li>كي</ul></ul>");
    assert!(m.is_protected(m.html.text.find("كي").unwrap()));
}
#[test]
fn test_mismatched_heading_and_duplicate_root_are_explicit_errors() {
    for b in [
        "<h1 lang=\"en\">English</h2>كي",
        "English<body lang=\"en\">كي",
        "<html lang=\"en\">كي",
    ] {
        invalid(b);
    }
}
#[test]
fn test_table_parts_outside_a_table_do_not_create_fake_exemptions() {
    for tag in [
        "td", "th", "tr", "tbody", "thead", "tfoot", "col", "colgroup", "caption",
    ] {
        invalid(&format!("<{tag} lang=\"en\">كي</{tag}>"));
    }
}
fn oracle_language(text: &str, target: &str) -> String {
    let dom = scraper::Html::parse_document(text);
    let selector = scraper::Selector::parse(target).unwrap();
    let element = dom.select(&selector).next().unwrap();
    if let Some(language) = element.value().attr("lang") {
        return language.into();
    }
    for node in element.ancestors() {
        if let Some(e) = scraper::ElementRef::wrap(node)
            && let Some(language) = e.value().attr("lang")
        {
            return language.into();
        }
    }
    "fa".into()
}
#[test]
fn test_bounded_sibling_matrix_matches_or_explicitly_refuses_html5_repair() {
    let openers = [
        "p", "h1", "li", "dt", "dd", "td", "th", "tr", "tbody", "thead", "tfoot", "caption",
        "colgroup", "option", "optgroup",
    ];
    let followers = [
        "p", "div", "li", "dt", "dd", "td", "th", "tr", "tbody", "caption", "h1", "h2", "option",
        "optgroup", "hr", "span",
    ];
    let (mut accepted, mut refused) = (0, 0);
    for opener in openers {
        let wrapper = if [
            "td", "th", "tr", "tbody", "thead", "tfoot", "caption", "colgroup",
        ]
        .contains(&opener)
        {
            "table"
        } else if opener == "li" {
            "ul"
        } else if ["dt", "dd"].contains(&opener) {
            "dl"
        } else if ["option", "optgroup"].contains(&opener) {
            "select"
        } else {
            "div"
        };
        for follower in followers {
            let lead = if opener == "colgroup" {
                "<col>"
            } else if ["tbody", "thead", "tfoot"].contains(&opener) {
                "<tr><td>A"
            } else if opener == "tr" {
                "<td>A"
            } else {
                "A"
            };
            let child = if follower == "tr" {
                "<td>كي"
            } else if follower == "tbody" {
                "<tr><td>كي"
            } else {
                "كي"
            };
            let text = format!(
                "<html lang=\"fa\"><body><{wrapper}><{opener} lang=\"en\">{lead}<{follower} id=\"target\">{child}</{follower}></{wrapper}></body></html>"
            );
            let Ok(m) = ParsedHtml::parse(&text) else {
                refused += 1;
                continue;
            };
            let actual = &m
                .nodes
                .iter()
                .find(|n| n.attr("id") == "target")
                .unwrap()
                .language;
            assert_eq!(
                actual,
                &oracle_language(&text, "#target"),
                "{opener}/{follower}: {text}"
            );
            accepted += 1;
        }
    }
    assert_eq!((accepted, refused), (176, 64));
}
#[test]
fn test_special_barriers_match_independent_html5_tree() {
    for body in [
        "<ul><li lang=\"en\"><section>A<li id=\"target\">كي</section></ul>",
        "<dl><dt lang=\"en\"><section>A<dd id=\"target\">كي</section></dl>",
        "<span lang=\"en\"><p>A</span><p id=\"target\">كي</p>",
        "<div lang=\"en\"><table><tr><td>A</div><span id=\"target\">كي</span></table>",
    ] {
        let text = format!("<html lang=\"fa\"><body>{body}</body></html>");
        let m = ParsedHtml::parse(&text).unwrap();
        let expected = oracle_language(&text, "#target");
        assert_eq!(expected, "en");
        assert_eq!(
            m.nodes
                .iter()
                .find(|n| n.attr("id") == "target")
                .unwrap()
                .language,
            expected
        );
    }
    for body in [
        "<form hidden><div>A</form>كي</div>",
        "<form><div lang=\"en\">A</form>كي</div>",
    ] {
        invalid(body);
    }
}
#[test]
fn test_implicit_scope_vectors_match_independent_html5_tree() {
    for body in [
        "<p lang=\"en\">English<p id=\"target\">كي",
        "<ul><li lang=\"en\">English<li id=\"target\">كي</ul>",
        "<table><tr><td lang=\"en\">English<td id=\"target\">كي</table>",
        "<head><title>English</title><body><p id=\"target\">كي",
        "<select><option lang=\"en\">English<option id=\"target\">كي</select>",
    ] {
        let text = format!("<html lang=\"fa\">{body}</html>");
        let m = ParsedHtml::parse(&text).unwrap();
        assert_eq!(
            m.nodes
                .iter()
                .find(|n| n.attr("id") == "target")
                .unwrap()
                .language,
            oracle_language(&text, "#target")
        );
    }
}
#[test]
fn test_html5_oracle_keeps_markup_inside_textarea_as_text() {
    let source = "<!doctype html><html lang=\"fa\" dir=\"rtl\"><body><textarea/><!-- fa-lint: allow all --><img src=\"missing.png\"></textarea><span dir=\"ltr\"/>125</span></body></html>";
    let dom = scraper::Html::parse_document(source);
    let select = |s: &str| scraper::Selector::parse(s).unwrap();
    assert_eq!(dom.select(&select("img")).count(), 0);
    assert_eq!(
        dom.select(&select("textarea"))
            .next()
            .unwrap()
            .text()
            .collect::<String>(),
        "<!-- fa-lint: allow all --><img src=\"missing.png\">"
    );
    assert_eq!(
        dom.select(&select("span"))
            .next()
            .unwrap()
            .text()
            .collect::<String>(),
        "125"
    );
    let m = ParsedHtml::parse(source).unwrap();
    assert!(m.comments.is_empty());
    assert!(m.image_references().is_empty());
    let p = m.text.find("125").unwrap();
    assert!(m.protected.iter().any(|&(a, b)| a <= p && p < b));
}
#[test]
fn test_bounded_tokenizer_vectors_match_independent_html5_text_and_namespaces() {
    let mut vectors = vec![
        (
            "<textarea>literal</textarea x=a'>كي<img src=\"real.png\">".into(),
            "textarea",
        ),
        (
            "<textarea>literal</textarea x=a\">كي<img src=\"real.png\">".into(),
            "textarea",
        ),
    ];
    for foreign in ["svg", "math"] {
        for (tag, attrs) in [
            ("span", "dir=\"ltr\""),
            ("p", "dir=\"ltr\""),
            ("font", "color=\"red\" dir=\"ltr\""),
        ] {
            vectors.push((format!("<{foreign}><{tag} {attrs}/>125</{tag}>كي"), tag));
        }
    }
    for (body, tag) in vectors {
        let text = format!("<!doctype html><html lang=\"fa\"><body>{body}</body></html>");
        let dom = scraper::Html::parse_document(&text);
        let m = ParsedHtml::parse(&text).unwrap();
        let selector = scraper::Selector::parse(tag).unwrap();
        let e = dom.select(&selector).next().unwrap();
        assert_eq!(e.value().name(), tag);
        assert_eq!(
            m.nodes.iter().find(|n| n.tag == tag).unwrap().namespace,
            "html"
        );
        assert_eq!(
            dom.select(&scraper::Selector::parse("img").unwrap())
                .count(),
            m.image_references().len()
        );
        if tag != "textarea" {
            assert_eq!(e.text().collect::<String>(), "125");
        }
    }
}
#[test]
fn test_comment_terminators_match_html5_including_unclosed_tail() {
    for (ending, visible) in [
        ("-->", true),
        ("--!>", true),
        (">", true),
        ("->", true),
        ("comment -- >", false),
    ] {
        let text = format!("<!doctype html><body><!--{ending}كي<img src=\"real.png\">");
        let dom = scraper::Html::parse_document(&text);
        let m = ParsedHtml::parse(&text).unwrap();
        assert_eq!(
            dom.select(&scraper::Selector::parse("img").unwrap())
                .count(),
            usize::from(visible)
        );
        assert_eq!(m.image_references().len(), usize::from(visible));
        let p = m.text.rfind("كي").unwrap();
        assert_eq!(m.protected.iter().any(|&(a, b)| a <= p && p < b), !visible);
    }
}
#[test]
#[ignore = "requires sandboxed Chromium and Poppler; scientific CI executes actual two-page pixel equivalence"]
fn test_two_page_render_matches_explicit_equivalent_markup() -> anyhow::Result<()> {
    let d = tempfile::tempdir()?;
    let head = "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><style>@page {size: A5; margin: 18mm;} body {font-family: sans-serif;} .next {page-break-before: always;} textarea {width: 100%; height: 25mm;}</style></head><body>";
    let actual = format!(
        "{head}<p><span dir=\"ltr\"/>125</span></p><textarea><!-- literal --><img src=\"missing.png\"></textarea><p class=\"next\" dir=\"ltr\">Unchanged second page: 23.5 C.</p></body></html>"
    );
    let expected = actual
        .replace("dir=\"ltr\"/>125", "dir=\"ltr\">125")
        .replace(
            "<!-- literal --><img src=\"missing.png\">",
            "&lt;!-- literal --&gt;&lt;img src=\"missing.png\"&gt;",
        );
    let original = d.path().join("original.html");
    fs::write(&original, &actual)?;
    let browser = revayat_scientific::render::discover_browser(None)?;
    for (label, source) in [("actual", &actual), ("expected", &expected)] {
        let p = d.path().join(format!("{label}.html"));
        fs::write(&p, source)?;
        revayat_scientific::render::render_html(
            &p,
            &d.path().join(format!("{label}.pdf")),
            &browser,
            None,
        )?;
    }
    let a = d.path().join("actual.pdf");
    let b = d.path().join("expected.pdf");
    for path in [&a, &b] {
        assert_eq!(
            revayat_scientific::pdf::page_ids(&revayat_scientific::pdf::open_pdf(path, false)?)?
                .len(),
            2
        );
    }
    for page in 1..=2 {
        let a_png = d.path().join(format!("a-{page}.png"));
        let b_png = d.path().join(format!("b-{page}.png"));
        revayat_scientific::pdf::render_page(&a, page, 100, &a_png)?;
        revayat_scientific::pdf::render_page(&b, page, 100, &b_png)?;
        assert_eq!(
            image::open(a_png)?.to_rgba8(),
            image::open(b_png)?.to_rgba8()
        );
    }
    assert!(revayat_scientific::pdf::pdf_text(&a)?.contains("125"));
    assert!(revayat_scientific::pdf::pdf_text(&a)?.contains("Unchanged second page"));
    assert_eq!(fs::read_to_string(original)?, actual);
    Ok(())
}

#[test]
fn protected_comments_cannot_waive_neighboring_live_prose() {
    for (start, end) in [
        ("<pre>", "</pre>"),
        ("<code>", "</code>"),
        ("<q>", "</q>"),
        ("<span dir=\"ltr\">", "</span>"),
        ("<div hidden>", "</div>"),
        ("<p lang=\"en\">", "</p>"),
    ] {
        let m = model(&format!("{start}<!-- fa-lint: allow all -->{end}كي"));
        let p = m.html.text.rfind("كي").unwrap();
        assert!(!m.suppressed(p, "arabic-letters"), "{start}");
        assert!(!m.is_protected(p));
    }
}

#[test]
fn foreign_unquoted_attribute_slash_is_a_value_not_a_false_closer() {
    for tag in ["svg", "math"] {
        let text = format!("<html lang=fa><body><{tag} lang=en/>كي");
        let m = ParsedHtml::parse(&text).unwrap();
        let node = m.nodes.iter().find(|n| n.tag == tag).unwrap();
        let oracle = scraper::Html::parse_document(&text);
        let selector = scraper::Selector::parse(tag).unwrap();
        let element = oracle.select(&selector).next().unwrap();
        assert_eq!(node.attr("lang"), element.value().attr("lang").unwrap());
        assert_eq!(node.attr("lang"), "en/");
        assert!(
            m.protected
                .iter()
                .any(|&(a, b)| a <= m.text.find("كي").unwrap() && m.text.find("كي").unwrap() < b)
        );
    }
}
