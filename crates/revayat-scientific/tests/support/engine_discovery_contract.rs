//! Original six discovery checks, carried by the existing integration test.
use super::*;

pub(super) fn run() -> Result<()> {
    use revayat_scientific::engine_discovery::{self, Probes};
    // These are the six authored Check-EngineDiscovery.ps1 cases, executed
    // against the production discovery controller with per-call boundaries.
    // They require no installed browser, TeX runtime or external WeasyPrint.
    struct Discovery {
        calls: Vec<&'static str>,
        browser_present: bool,
        chromium_ready: bool,
    }
    impl Probes for Discovery {
        type Tex = &'static str;
        type Browser = &'static str;
        type Weasyprint = &'static str;
        fn tex(&mut self) -> Result<Option<Self::Tex>> {
            self.calls.push("tex");
            Ok(Some("fixed-tex-runtime"))
        }
        fn browser(&mut self) -> Result<Option<Self::Browser>> {
            self.calls.push("browser");
            Ok(self.browser_present.then_some("fixed-browser"))
        }
        fn chromium(&mut self, browser: &Self::Browser) -> Result<bool> {
            assert_eq!(*browser, "fixed-browser", "unexpected discovery executable");
            self.calls.push("chromium");
            Ok(self.chromium_ready)
        }
        fn weasyprint(&mut self) -> Result<Option<Self::Weasyprint>> {
            self.calls.push("weasyprint");
            Ok(Some("fixed-weasyprint-adapter"))
        }
    }
    const OWNER: &str = "crates/revayat-scientific/test/runtime_build_integration::test_explicit_engine_discovery_does_not_probe_other_backends";
    const INVOKED: &str = "crates/revayat-scientific/src/engine_discovery.rs::available_engines";
    type DiscoveryCase = (
        &'static str,
        &'static str,
        bool,
        bool,
        &'static [&'static str],
        &'static [&'static str],
    );
    let cases: [DiscoveryCase; 6] = [
        (
            "explicit-chromium",
            "chromium",
            true,
            true,
            &["chromium"],
            &["browser", "chromium"],
        ),
        ("explicit-tex", "tex", true, true, &["tex"], &["tex"]),
        (
            "explicit-weasyprint",
            "weasyprint",
            true,
            true,
            &["weasyprint"],
            &["weasyprint"],
        ),
        (
            "auto-ordered-discovery",
            "auto",
            true,
            true,
            &["tex", "chromium", "weasyprint"],
            &["tex", "browser", "chromium", "weasyprint"],
        ),
        (
            "unavailable-explicit-chromium",
            "chromium",
            true,
            false,
            &[],
            &["browser", "chromium"],
        ),
        (
            "absent-browser-no-import",
            "chromium",
            false,
            false,
            &[],
            &["browser"],
        ),
    ];
    let mut events = Vec::new();
    for (index, (id, requested, browser_present, chromium_ready, engines, calls)) in
        cases.into_iter().enumerate()
    {
        let mut probes = Discovery {
            calls: Vec::new(),
            browser_present,
            chromium_ready,
        };
        let available = engine_discovery::available_engines(Some(requested), &mut probes)?;
        assert_eq!(available.engines, engines, "{id}: returned engines");
        assert_eq!(probes.calls, calls, "{id}: ordered probes / no fallback");
        assert_eq!(
            available.tex,
            engines.contains(&"tex").then_some("fixed-tex-runtime")
        );
        assert_eq!(
            available.browser,
            engines.contains(&"chromium").then_some("fixed-browser")
        );
        assert_eq!(
            available.weasyprint,
            engines
                .contains(&"weasyprint")
                .then_some("fixed-weasyprint-adapter")
        );
        // Reached only after this requested production-controller invocation and
        // both original assertions. This journal never reads the census, and
        // the child cannot certify the outer harness's process-tree cleanup.
        events.push(serde_json::json!({
            "case_id":format!("tests/Check-EngineDiscovery.ps1::{id}"),
            "parent_id":OWNER, "sequence":index + 1,
            "invokes_ids":[INVOKED], "obligation_ids":[format!("ENGINE-{:03}", index + 1)],
            "source":"execution", "outcome":"passed", "exit":0,
            "cleanup_complete":false, "assertions_complete":true,
            "variants":[], "check_results":[]
        }));
    }
    let mut untouched = Discovery {
        calls: Vec::new(),
        browser_present: true,
        chromium_ready: true,
    };
    assert!(engine_discovery::available_engines(Some("unknown"), &mut untouched).is_err());
    assert!(untouched.calls.is_empty());
    let f = Fixture::new()?;
    // Independently exercise the real bounded native executable boundary. The
    // six original discovery checks above remain pure adapter/controller checks.
    let tool = Path::new(env!("CARGO_BIN_EXE_revayat-test-tool"));
    assert!(engine_discovery::probe_executable(tool, ["echo-input"])?);
    assert!(!engine_discovery::probe_executable(tool, ["diagnostics"])?);
    assert!(engine_discovery::probe_executable(tool, ["flood"]).is_err());
    assert!(!engine_discovery::probe_executable(
        &f.root.join("missing-probe"),
        ["--version"]
    )?);
    assert!(
        engine_discovery::probe_executable(Path::new("relative-probe"), ["--version"]).is_err()
    );
    let selection = build::select_source(
        &f.source,
        Some("chromium"),
        Some(env!("CARGO_BIN_EXE_revayat-test-tool")),
    )?;
    assert_eq!(selection.engine, "chromium");
    assert!(selection.container.is_none());
    assert!(selection.browser.unwrap().is_absolute());
    if let Some(directory) = std::env::var_os("REVAYAT_ENGINE_EVENT_DIR") {
        use std::io::Write;
        let directory = std::path::PathBuf::from(directory);
        assert!(directory.is_absolute());
        assert_eq!(directory.canonicalize()?, directory);
        let mut stage = tempfile::NamedTempFile::new_in(&directory)?;
        serde_json::to_writer(
            &mut stage,
            &serde_json::json!({
                "schema":1, "population":"engine", "owner_case_id":OWNER, "events":events
            }),
        )?;
        stage.flush()?;
        stage.as_file().sync_all()?;
        stage.persist_noclobber(directory.join("engine-observations.json"))?;
    }
    Ok(())
}
