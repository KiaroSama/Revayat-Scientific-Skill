//! Explicit equipped inventory; unreviewed ignored cases fail closed.
use super::*;

const CROPS: &[&str] = &[
    "test_explicit_edge_crop_and_late_failures_preserve_batch",
    "test_selected_crop_admission_preserves_source",
    "test_crop_preserves_source_sampling_and_rotation",
];
const WINDOWS_RENDER: &str = "test_windows_build_preserves_destination_on_failure";
const NOTICE_TARGET: &str = "crates/revayat-scientific/bin/license-notices";
const NOTICE_CASES: &[&str] = &[
    "expression_tests::all_observed_locked_expressions_include_the_exact_constant_time_eq_terms",
    "expression_tests::compound_admission_keeps_every_shipped_notice_and_declared_expression",
    "dedup::tests::shared_bodies_expand_to_every_original_byte_and_attribution",
    "dedup::tests::retained_budget_checks_boundaries_overflow_and_duplicate_occurrences_before_mutation",
    "dedup::tests::stale_hash_or_same_hash_with_different_bytes_fails_before_reference",
];

const WINDOWS_NATIVE_TARGET: &str = "crates/revayat-scientific/test/windows_standalone";
const WINDOWS_NATIVE_CASES: &[&str] = &[
    "native_opc_consumer_recognizes_case_variant_relationship_part",
    "junction_destination_admission_preserves_owned_controls",
    "junction_publication_refuses_and_preserves_stage_and_sentinels",
    "ordinary_publication_commits_exact_bytes",
    "public_build_junction_refusal_precedes_lint_and_renderer",
];

/// Required actual case outcomes. This is not native qualification or nested-stage proof.
pub(super) fn required_outcomes(report: &CollectedExecution) -> Result<()> {
    let (target, cases) = match (report.tier.as_str(), report.platform.as_str()) {
        ("portable", _) => (NOTICE_TARGET, NOTICE_CASES),
        ("native", "windows") => (WINDOWS_NATIVE_TARGET, WINDOWS_NATIVE_CASES),
        _ => return Ok(()),
    };
    let binary = report
        .binaries
        .iter()
        .find(|binary| binary.target == target)
        .context("required regression harness missing")?;
    ensure!(
        cases
            .iter()
            .all(|case| binary.cases.get(*case) == Some(&CaseOutcome::Passed)),
        "required regression did not pass"
    );
    Ok(())
}

const EQUIPPED: &[(&str, &[&str])] = &[
    ("crop_native", CROPS),
    (
        "runtime_build_integration",
        &[
            "test_css_only_preview_resource_is_preserved_and_cannot_replace_working_pdf",
            "test_noverify_does_not_reserve_unused_preview_paths",
            "test_successful_three_to_one_page_rebuild_refreshes_every_preview_role",
            "test_late_raster_failure_preserves_entire_previous_preview_batch",
            "test_real_chromium_resource_denial_preserves_previous_delivery",
            "test_multipart_geometry_images_math_and_verified_delivery",
            "test_container_host_sentinel_and_shortened_internal_deadline",
            "test_surviving_owner_reaps_container_after_controller_is_killed",
            "test_native_html_resource_denial_preserves_previous_output",
        ],
    ),
    (
        "native_html",
        &["test_two_page_render_matches_explicit_equivalent_markup"],
    ),
    (
        "include_token_contract",
        &["test_real_compiler_and_source_closure_agree_on_numeric_input"],
    ),
    (
        "tex_command_boundaries",
        &["test_real_tex_linebreak_then_input_agrees_with_closure"],
    ),
    (
        "tex_lexical_regions",
        &[
            "test_real_tex_ignores_post_document_tail",
            "test_real_tex_accepts_literal_graphics_and_keeps_parent_after_eof_comment",
        ],
    ),
    (
        "text_order_sources",
        &["test_real_two_page_pdf_matches_source_tokens"],
    ),
    (
        "docx_native",
        &[
            "docx_story_render::test_two_page_renamed_header_footer_matches_independent_expected_render",
            "native_docx_creation::native_created_sections_tables_and_images_render_at_requested_geometry",
        ],
    ),
    (
        "upstream_native",
        &[
            "build_uses_actual_isolated_controller",
            "monospace_font_contract_renders_actual_code",
            "monospace_selection_uses_embedded_code_font",
        ],
    ),
    (
        "pdf_ocr_painting",
        &[
            "test_valid_invisible_text_keeps_every_pixel_and_source_byte",
            "test_rotation_and_nonzero_crop_keep_geometry_and_pixels",
        ],
    ),
    (
        "standalone_security",
        &[
            "tex_output_real_xelatex_no_shell",
            "tex_output_two_permitted_output_files",
            "tex_output_ordinary_pdf",
        ],
    ),
    (
        "workflow_lint",
        &[
            "equipped_actionlint_rejects_missing_callee_input",
            "test_original_filename_and_failed_linter_exit_are_preserved",
        ],
    ),
];

fn inventory(target: Option<&str>, platform: &str) -> BTreeSet<String> {
    let cases = EQUIPPED
        .iter()
        .find(|(name, _)| Some(*name) == target)
        .map_or(&[][..], |(_, cases)| *cases);
    let mut cases: BTreeSet<String> = cases.iter().map(|case| (*case).into()).collect();
    if target == Some("runtime_build_integration") {
        if platform == "windows" {
            cases.insert(WINDOWS_RENDER.into());
        }
        if platform == "linux" {
            cases.insert(
                "test_production_launch_enforces_isolation_and_cleans_owned_container".into(),
            );
        }
    }
    cases
}

/// Check before launching any harness, using the same catalogue as per-case selection.
/// Every known suite must remain discoverable even if this platform selects no cases from it.
pub(super) fn validate_equipped_targets(artifacts: &[Artifact]) -> Result<()> {
    ensure!(
        EQUIPPED.iter().all(|(required, _)| artifacts
            .iter()
            .any(|artifact| artifact.mapping_target.as_deref() == Some(*required))),
        "required equipped test target missing"
    );
    Ok(())
}

pub(super) fn validate_collection_targets(
    artifacts: &[Artifact],
    report: &mut CollectedExecution,
    output: &Path,
) -> Result<()> {
    let missing = match report.tier.as_str() {
        "scientific" if validate_equipped_targets(artifacts).is_err() => {
            Some("required equipped test target missing")
        }
        "portable"
            if !artifacts
                .iter()
                .any(|artifact| artifact.target == NOTICE_TARGET) =>
        {
            Some("required notice regression harness missing")
        }
        _ => None,
    };
    if let Some(error) = missing {
        report.error = Some(error.into());
        return write_execution_report(output, report);
    }
    Ok(())
}

/// Portable retains ordinary libtest semantics. Scientific cases run with --ignored --exact.
/// Native stage witnesses need their actual producer, never a generic ignored-test sweep.
pub fn select_equipped_cases(
    tier: &str,
    platform: &str,
    target: Option<&str>,
    ignored: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    ensure!(tier == "scientific", "native execution adapter unavailable");
    ensure!(
        ["linux", "macos", "windows"].contains(&platform),
        "unsupported equipped platform"
    );
    ensure!(
        *ignored == inventory(target, platform),
        "equipped inventory changed or requires review"
    );
    Ok(match (platform, target) {
        (_, Some("crop_native")) => ignored.clone(),
        ("windows", Some("runtime_build_integration")) => [WINDOWS_RENDER.into()].into(),
        (_, Some("workflow_lint" | "windows_standalone")) => BTreeSet::new(), // Quality/native owners, not scientific execution.
        ("linux", _) => ignored.clone(),
        _ => BTreeSet::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crop_all_platforms_and_windows_renderer_are_not_optional() {
        for platform in ["linux", "macos", "windows"] {
            let crops = inventory(Some("crop_native"), platform);
            assert_eq!(
                select_equipped_cases("scientific", platform, Some("crop_native"), &crops).unwrap(),
                crops
            );
            assert!(
                select_equipped_cases(
                    "scientific",
                    platform,
                    Some("crop_native"),
                    &BTreeSet::new()
                )
                .is_err()
            );
        }
        let mixed = inventory(Some("runtime_build_integration"), "windows");
        assert_eq!(
            select_equipped_cases(
                "scientific",
                "windows",
                Some("runtime_build_integration"),
                &mixed
            )
            .unwrap(),
            [WINDOWS_RENDER.into()].into()
        );
        let office = inventory(Some("docx_native"), "macos");
        assert!(
            select_equipped_cases("scientific", "macos", Some("docx_native"), &office)
                .unwrap()
                .is_empty()
        );
        for platform in ["linux", "macos", "windows"] {
            assert!(
                select_equipped_cases("scientific", platform, Some("unreviewed"), &mixed).is_err()
            );
        }
        assert!(
            select_equipped_cases(
                "native",
                "windows",
                Some("runtime_build_integration"),
                &mixed
            )
            .is_err()
        );
        let mut changed = inventory(Some("native_html"), "linux");
        changed.insert("unreviewed_case".into());
        assert!(
            select_equipped_cases("scientific", "linux", Some("native_html"), &changed).is_err()
        );
    }

    #[test]
    fn standalone_tex_cases_execute_only_in_linux_scientific_selection() {
        let cases = [
            "tex_output_real_xelatex_no_shell",
            "tex_output_two_permitted_output_files",
            "tex_output_ordinary_pdf",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            select_equipped_cases("scientific", "linux", Some("standalone_security"), &cases)
                .unwrap(),
            cases
        );
        for platform in ["macos", "windows"] {
            assert!(
                select_equipped_cases("scientific", platform, Some("standalone_security"), &cases)
                    .unwrap()
                    .is_empty()
            );
        }
        let mut missing = cases.clone();
        missing.remove("tex_output_ordinary_pdf");
        assert!(
            select_equipped_cases("scientific", "linux", Some("standalone_security"), &missing)
                .is_err()
        );
    }

    #[test]
    fn removal_of_each_entire_known_suite_preserves_a_failure_report_before_launch() {
        let mut artifacts: Vec<_> = EQUIPPED
            .iter()
            .map(|(name, _)| Artifact {
                target: format!("crates/revayat-scientific/test/{name}"),
                mapping_target: Some((*name).into()),
                executable: "never-launched".into(),
                directory: ".".into(),
            })
            .collect();
        assert!(validate_equipped_targets(&artifacts).is_ok());
        let root = tempfile::tempdir().unwrap();
        for index in 0..artifacts.len() {
            let removed = artifacts.remove(index);
            assert!(validate_equipped_targets(&artifacts).is_err());
            let mut report = CollectedExecution {
                schema: 1,
                tested_sha: "0".repeat(40),
                run_id: "1".into(),
                run_attempt: "1".into(),
                repository: "example/project".into(),
                workflow_ref: "fixture".into(),
                job: "portable".into(),
                platform: "macos".into(),
                tier: "scientific".into(),
                profile: "debug".into(),
                ignored_only: true,
                binaries: Vec::new(),
                error: None,
                discovery_exit: None,
                final_parity_verified: false,
            };
            let path = root.path().join(format!("missing-{index}.json"));
            let error = validate_collection_targets(&artifacts, &mut report, &path).unwrap_err();
            assert!(
                error
                    .downcast_ref::<TestExecutionFailure>()
                    .unwrap()
                    .report_published
            );
            let saved: CollectedExecution =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(
                saved.error.as_deref(),
                Some("required equipped test target missing")
            );
            assert!(saved.binaries.is_empty() && !saved.final_parity_verified);
            artifacts.insert(index, removed);
        }
        let mut portable = CollectedExecution {
            schema: 1,
            tested_sha: "0".repeat(40),
            run_id: "1".into(),
            run_attempt: "1".into(),
            repository: "example/project".into(),
            workflow_ref: "fixture".into(),
            job: "portable".into(),
            platform: "linux".into(),
            tier: "portable".into(),
            profile: "debug".into(),
            ignored_only: false,
            binaries: Vec::new(),
            error: None,
            discovery_exit: None,
            final_parity_verified: false,
        };
        let path = root.path().join("missing-notice-harness.json");
        assert!(validate_collection_targets(&artifacts, &mut portable, &path).is_err());
        let saved: CollectedExecution = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(
            saved.error.as_deref(),
            Some("required notice regression harness missing")
        );
        artifacts.push(Artifact {
            target: NOTICE_TARGET.into(),
            mapping_target: None,
            executable: "never-launched".into(),
            directory: ".".into(),
        });
        portable.error = None;
        assert!(
            validate_collection_targets(
                &artifacts,
                &mut portable,
                &root.path().join("no-report.json")
            )
            .is_ok()
        );
        assert!(!root.path().join("no-report.json").exists());
    }
}
