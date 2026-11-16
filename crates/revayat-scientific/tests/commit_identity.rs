use revayat_scientific::ci_tools::{
    APPROVED_EMAIL as OWNER, DEPENDABOT_EMAIL as BOT, inspect_identities,
};
use revayat_scientific::runtime::{self, CommandSpec};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    author_name: String,
    committer_name: String,
}
impl Fixture {
    fn new() -> Self {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".scratch");
        fs::create_dir_all(&scratch).unwrap();
        let temp = tempfile::tempdir_in(scratch).unwrap();
        let f = Self {
            root: temp.path().to_owned(),
            _temp: temp,
            author_name: "Synthetic Fixture".into(),
            committer_name: "Synthetic Fixture".into(),
        };
        f.git(&["init", "--quiet"], OWNER, OWNER);
        f
    }
    fn git(&self, args: &[&str], author: &str, committer: &str) -> String {
        let hooks = self.root.join("empty-hooks");
        fs::create_dir_all(&hooks).unwrap();
        let mut spec = CommandSpec::new("git")
            .args(["-c", &format!("core.hooksPath={}", hooks.display())])
            .args(args.iter().copied());
        spec.cwd = Some(self.root.clone());
        spec.timeout = Duration::from_secs(20);
        spec.max_output = 1024 * 1024;
        for (key, value) in [
            ("GIT_CONFIG_NOSYSTEM", "1"),
            (
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            ),
            ("GIT_CONFIG_COUNT", "0"),
            ("GIT_AUTHOR_NAME", self.author_name.as_str()),
            ("GIT_COMMITTER_NAME", self.committer_name.as_str()),
            ("GIT_AUTHOR_EMAIL", author),
            ("GIT_COMMITTER_EMAIL", committer),
        ] {
            spec.env.insert(key.into(), value.into());
        }
        let out = runtime::run(&spec).unwrap();
        assert!(out.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }
    fn commit(&self, author: &str, committer: &str) -> String {
        self.git(
            &[
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "Synthetic identity fixture, never published",
            ],
            author,
            committer,
        );
        self.git(&["rev-parse", "HEAD"], OWNER, OWNER)
    }
    fn inspect(&self) -> revayat_scientific::ci_tools::IdentityReport {
        inspect_identities(&self.root, "HEAD", None).unwrap()
    }
    fn shallow(&self) -> PathBuf {
        let clone = self.root.join("shallow-clone");
        let url = url::Url::from_directory_path(&self.root)
            .unwrap()
            .to_string();
        self.git(
            &[
                "clone",
                "--quiet",
                "--depth",
                "1",
                &url,
                clone.to_str().unwrap(),
            ],
            OWNER,
            OWNER,
        );
        clone
    }
}
#[test]
fn test_matching_complete_history_passes() {
    let f = Fixture::new();
    f.commit(OWNER, OWNER);
    f.commit(OWNER, OWNER);
    assert_eq!(f.inspect(), (2, vec![]));
}
#[test]
fn test_exact_service_identities_pass_in_permitted_roles() {
    let f = Fixture::new();
    for (a, c) in [
        (BOT, OWNER),
        (OWNER, BOT),
        (BOT, BOT),
        (OWNER, "noreply@github.com"),
        (BOT, "noreply@github.com"),
    ] {
        f.commit(a, c);
    }
    assert_eq!(f.inspect(), (5, vec![]));
}
#[test]
fn test_github_service_identity_is_committer_only() {
    let f = Fixture::new();
    let first = f.commit("noreply@github.com", OWNER);
    let second = f.commit("noreply@github.com", "noreply@github.com");
    assert_eq!(
        f.inspect(),
        (
            2,
            vec![
                (second, vec!["author".into()]),
                (first, vec!["author".into()])
            ]
        )
    );
}
#[test]
fn test_service_names_lookalikes_and_mailmap_cannot_hide_other_role() {
    let mut f = Fixture::new();
    f.author_name = "dependabot[bot]".into();
    f.committer_name = "GitHub".into();
    fs::write(
        f.root.join(".mailmap"),
        format!("<{BOT}> <fixture-only@example.invalid>\n"),
    )
    .unwrap();
    let mut expected = BTreeMap::new();
    for email in [
        "fixture-only@example.invalid",
        "12345+other-bot[bot]@users.noreply.github.com",
        "dependabot[bot]@users.noreply.github.com",
        "49699333+dependabot[bot]@users.noreply.github.com.invalid",
        "49699333+DEPENDABOT[bot]@users.noreply.github.com",
        "noreply@github.com.invalid",
        "NOREPLY@github.com",
    ] {
        expected.insert(f.commit(email, "noreply@github.com"), vec!["author".into()]);
        expected.insert(f.commit(BOT, email), vec!["committer".into()]);
    }
    let (count, found) = f.inspect();
    assert_eq!(count, 14);
    assert_eq!(found.into_iter().collect::<BTreeMap<_, _>>(), expected);
}
#[test]
fn test_author_and_committer_are_checked_independently() {
    let f = Fixture::new();
    let first = f.commit("fixture-only@example.invalid", OWNER);
    let second = f.commit(OWNER, "fixture-only@example.invalid");
    let third = f.commit(
        "fixture-only@example.invalid",
        "fixture-only@example.invalid",
    );
    let (count, found) = f.inspect();
    assert_eq!(count, 3);
    assert_eq!(
        found.into_iter().collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            (first, vec!["author".into()]),
            (second, vec!["committer".into()]),
            (third, vec!["author".into(), "committer".into()])
        ])
    );
}
#[test]
fn test_introduced_range_does_not_claim_legacy_history_passed() {
    let f = Fixture::new();
    let base = f.commit("fixture-only@example.invalid", OWNER);
    let head = f.commit(OWNER, OWNER);
    assert_eq!(
        inspect_identities(&f.root, &head, Some(&base)).unwrap(),
        (1, vec![])
    );
    assert_eq!(f.inspect().1.len(), 1);
}
#[test]
fn test_mailmap_cannot_hide_stored_identity_mismatch() {
    let f = Fixture::new();
    let bad = f.commit("fixture-only@example.invalid", OWNER);
    fs::write(
        f.root.join(".mailmap"),
        format!("<{OWNER}> <fixture-only@example.invalid>\n"),
    )
    .unwrap();
    assert_eq!(f.inspect().1, vec![(bad, vec!["author".into()])]);
}
#[test]
fn test_empty_introduced_range_and_invalid_refs_are_distinct() {
    let f = Fixture::new();
    let head = f.commit(OWNER, OWNER);
    assert_eq!(
        inspect_identities(&f.root, &head, Some(&head)).unwrap(),
        (0, vec![])
    );
    for (head, base) in [
        ("missing", None),
        ("HEAD", Some("missing")),
        ("--all", None),
    ] {
        assert!(inspect_identities(&f.root, head, base).is_err());
    }
}
#[test]
fn test_email_comparison_is_exact() {
    let f = Fixture::new();
    let bad = f.commit(&OWNER.to_lowercase(), OWNER);
    assert_eq!(f.inspect().1, vec![(bad, vec!["author".into()])]);
}
#[test]
fn test_replacement_refs_cannot_hide_stored_author_identity() {
    let f = Fixture::new();
    let bad = f.commit("fixture-only@example.invalid", OWNER);
    let good = f.commit(OWNER, OWNER);
    f.git(&["replace", &bad, &good], OWNER, OWNER);
    assert_eq!(
        inspect_identities(&f.root, &bad, None).unwrap(),
        (1, vec![(bad.clone(), vec!["author".into()])])
    );
    assert_eq!(f.git(&["replace", "-l"], OWNER, OWNER), bad);
}
#[test]
fn test_shallow_history_never_passes_as_complete_history() {
    let f = Fixture::new();
    f.commit("fixture-only@example.invalid", OWNER);
    f.commit(OWNER, OWNER);
    let clone = f.shallow();
    assert!(
        inspect_identities(&clone, "HEAD", None)
            .unwrap_err()
            .to_string()
            .contains("shallow")
    );
}
#[test]
fn test_complete_history_and_introduced_range_remain_available() {
    let f = Fixture::new();
    let bad = f.commit("fixture-only@example.invalid", OWNER);
    let good = f.commit(OWNER, OWNER);
    assert_eq!(
        inspect_identities(&f.root, &good, Some(&bad)).unwrap(),
        (1, vec![])
    );
    assert_eq!(f.inspect(), (2, vec![(bad, vec!["author".into()])]));
}
#[test]
fn test_legacy_grafts_cannot_hide_bad_ancestors() {
    let f = Fixture::new();
    let bad = f.commit("fixture-only@example.invalid", OWNER);
    let head = f.commit(OWNER, OWNER);
    let grafts = f.root.join(".git/info/grafts");
    fs::write(&grafts, format!("{head}\n")).unwrap();
    let before = fs::read(&grafts).unwrap();
    assert!(
        inspect_identities(&f.root, "HEAD", None)
            .unwrap_err()
            .to_string()
            .contains("grafts")
    );
    assert_eq!(fs::read(&grafts).unwrap(), before);
    fs::remove_file(grafts).unwrap();
    assert_eq!(f.inspect(), (2, vec![(bad, vec!["author".into()])]));
}
#[test]
fn test_environment_selected_grafts_are_rejected_without_removal() {
    let f = Fixture::new();
    f.commit("fixture-only@example.invalid", OWNER);
    let head = f.commit(OWNER, OWNER);
    let grafts = f.root.join("custom-grafts");
    fs::write(&grafts, format!("{head}\n")).unwrap();
    let mut spec =
        CommandSpec::new(env!("CARGO_BIN_EXE_revayat-scientific")).args(["check-commit-identity"]);
    spec.cwd = Some(f.root.clone());
    spec.timeout = Duration::from_secs(30);
    spec.max_output = 1024 * 1024;
    spec.env
        .insert("REVAYAT_REPOSITORY".into(), f.root.as_os_str().to_owned());
    spec.env
        .insert("GIT_GRAFT_FILE".into(), grafts.as_os_str().to_owned());
    let output = runtime::run(&spec).unwrap();
    assert!(!output.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("grafts"));
    assert_eq!(fs::read_to_string(grafts).unwrap(), format!("{head}\n"));
}
#[test]
fn test_shallow_range_also_requires_complete_ancestry() {
    let f = Fixture::new();
    f.commit("fixture-only@example.invalid", OWNER);
    let head = f.commit(OWNER, OWNER);
    let clone = f.shallow();
    assert!(
        inspect_identities(&clone, &head, Some(&head))
            .unwrap_err()
            .to_string()
            .contains("shallow")
    );
}
