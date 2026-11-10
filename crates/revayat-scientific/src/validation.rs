//! Repository text, metadata, links and skill layout validation in Rust.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};
pub fn validate_family_layout(root: &Path) -> Result<()> {
    let badges = regex::Regex::new(r"\[!\[([^]]+)\]\(([^)]+)\)\]\(([^)]+)\)")?;
    let centered = regex::Regex::new(r#"(?s)<div align="center">\n\n(.*?)\n\n</div>"#)?;
    for (name, sections) in [
        (
            "README.md",
            vec![
                "Install",
                "Use",
                "Without a shell",
                "How it works",
                "What it is honest about",
                "Documentation",
                "Development",
                "Donate",
                "Author",
                "License",
            ],
        ),
        (
            "README.fa.md",
            vec![
                "نصب",
                "استفاده",
                "بدون پوسته",
                "معماری",
                "آنچه صادقانه باید گفت",
                "مستندات",
                "توسعه",
                "حمایت مالی",
                "نویسنده",
                "مجوز",
            ],
        ),
    ] {
        let source = fs::read_to_string(root.join(name))?;
        let headings: Vec<_> = source
            .lines()
            .filter_map(|l| l.strip_prefix("## "))
            .collect();
        ensure!(
            headings.len() == sections.len() + 1 && headings[1..] == sections,
            "{name}: Revayat section order changed"
        );
        ensure!(
            source.matches("<div ").count() == source.matches("</div>").count(),
            "{name}: unbalanced direction/alignment containers"
        );
        let header = source.split("## ").next().unwrap();
        let found: Vec<_> = badges.captures_iter(header).collect();
        let urls: std::collections::HashSet<_> = found.iter().map(|b| b[2].to_owned()).collect();
        ensure!(
            (12..=16).contains(&found.len())
                && urls.len() == found.len()
                && centered
                    .captures(header)
                    .is_some_and(|c| badges.captures_iter(&c[1]).count() == found.len()),
            "{name}: requires 12-16 distinct centered badges"
        );
        let donation = if name == "README.md" {
            "#donate"
        } else {
            "README.md#donate"
        };
        ensure!(
            found.iter().any(|b| &b[1] == "Support donations"
                && &b[2] == "https://img.shields.io/badge/Support-donations-d04a9a"
                && &b[3] == donation),
            "{name}: missing canonical donation badge"
        );
    }
    let persian = fs::read_to_string(root.join("README.fa.md"))?;
    ensure!(
        persian.starts_with("<div dir=\"rtl\">") && persian.contains("<div dir=\"ltr\">"),
        "Persian README requires RTL prose and LTR command blocks"
    );
    let skill = fs::read_to_string(root.join("skills/revayat-scientific/SKILL.md"))?;
    let steps: Vec<_> = skill
        .lines()
        .filter_map(|l| {
            l.strip_prefix("## Step ")
                .and_then(|s| s.split_whitespace().next())
        })
        .collect();
    ensure!(
        steps == ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
        "skill requires nine ordered Revayat stages"
    );
    for command in [
        "translate-paper.md",
        "revayat-scientific-resume.md",
        "revayat-scientific-qa.md",
    ] {
        ensure!(
            root.join("commands").join(command).is_file(),
            "missing workflow command {command}"
        );
    }
    Ok(())
}
fn validate_source_length(filename: &str, source: &str) -> Result<()> {
    ensure!(
        Path::new(filename)
            .extension()
            .and_then(|value| value.to_str())
            != Some("rs")
            || source.lines().count() <= 799,
        "{filename}: exceeds 799 lines"
    );
    Ok(())
}

pub fn validate_repository(root: &Path) -> Result<()> {
    let listing = crate::distribution_paths::git_result(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    ensure!(
        listing.success() && !listing.stdout.is_empty(),
        "no repository files to validate"
    );
    let links = regex::Regex::new(r"\]\(([^)]+)\)")?;
    for filename in listing.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let filename = std::str::from_utf8(filename)?;
        let path = root.join(filename);
        if !path.exists() {
            continue;
        }
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        ensure!(
            !["py", "pyc", "sh", "ps1", "cs", "c", "cpp", "js", "ts"].contains(&extension),
            "{filename}: implementation must be native Rust"
        );
        if ![
            "rs", "toml", "lock", "md", "json", "yaml", "yml", "tex", "html", "tsv", "txt",
        ]
        .contains(&extension)
        {
            continue;
        }
        let bytes = fs::read(&path)?;
        let source = std::str::from_utf8(&bytes)
            .with_context(|| format!("{filename}: invalid UTF-8"))?
            .trim_start_matches('\u{feff}');
        validate_source_length(filename, source)?;
        if extension == "json" {
            let _: serde_json::Value = serde_json::from_str(source)
                .with_context(|| format!("{filename}: invalid JSON"))?;
        }
        if extension == "md" {
            let mut fenced = None;
            for line in source.lines() {
                let content = line.trim_start_matches(' ');
                let indent = line.len() - content.len();
                if indent <= 3
                    && let Some(marker) = content.chars().next().filter(|c| *c == '`' || *c == '~')
                {
                    let length = content.chars().take_while(|c| *c == marker).count();
                    if length >= 3 {
                        match fenced {
                            Some((opened, count))
                                if opened == marker
                                    && length >= count
                                    && content[length..].trim().is_empty() =>
                            {
                                fenced = None
                            }
                            None => fenced = Some((marker, length)),
                            _ => {}
                        }
                        continue;
                    }
                }
                if fenced.is_some() {
                    continue;
                }
                for capture in links.captures_iter(line) {
                    let target = capture[1].split('#').next().unwrap_or("");
                    if !target.is_empty()
                        && !target.contains("://")
                        && !["mailto:", "$", "<"].iter().any(|p| target.starts_with(p))
                    {
                        ensure!(
                            path.parent().unwrap().join(target).exists(),
                            "{filename}: missing local link {target}"
                        );
                    }
                }
            }
        }
    }
    validate_family_layout(root)?;
    Ok(())
}
pub fn cli(args: &[String]) -> Result<i32> {
    ensure!(args.is_empty(), "usage: validate");
    validate_repository(&crate::distribution::repository_root()?)?;
    println!("Repository UTF-8, metadata, file lengths, local links and Revayat layout are valid.");
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn rust_source_limit_accepts_799_and_refuses_800_lines() {
        for newline in ["\n", "\r\n"] {
            assert!(
                super::validate_source_length(
                    "fixture.rs",
                    &format!("fn item() {{}}{newline}").repeat(799)
                )
                .is_ok()
            );
            assert!(
                super::validate_source_length(
                    "fixture.rs",
                    &format!("fn item() {{}}{newline}").repeat(800)
                )
                .is_err()
            );
        }
        assert!(super::validate_source_length("fixture.md", &"text\n".repeat(800)).is_ok());
    }
}
