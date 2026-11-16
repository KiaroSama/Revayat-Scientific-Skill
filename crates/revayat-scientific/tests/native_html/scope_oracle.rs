// Independent HTML5 tree comparisons for implicit scope repair.
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
        let path = PathBuf::from("/tmp/document.html");
        let source = HtmlSource::from_text(&path, &text).unwrap();
        let position = source.html.text.rfind("كي").unwrap();
        assert!(!source.is_protected(position), "{body}");
        assert!(!source.suppressed(position, "arabic-letters"), "{body}");
        assert_eq!(source.path, path);
        assert_eq!(
            source.html.nodes
                .iter()
                .find(|n| n.attr("id") == "target")
                .unwrap()
                .language,
            oracle_language(&text, "#target")
        );
    }
}
