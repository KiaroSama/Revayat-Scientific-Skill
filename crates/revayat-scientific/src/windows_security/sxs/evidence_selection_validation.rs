use super::fixture::{self, need, private, stage};
use anyhow::Result;
pub(super) fn check_selection_validation() -> Result<()> {
    let manifest = "F:\\private-selection-sentinel\\_ctypes.pyd";
    let first = fixture::block(
        manifest,
        "ERROR: Cannot resolve reference Microsoft.Windows.Common-Controls.",
    );
    let second = fixture::block(manifest, "ERROR: Access is denied.");
    let first_flags = "unresolved_reference=True access_denied=False manifest_parse=False activation_failed=False common_controls=True vc_crt=False";
    let second_flags = "unresolved_reference=False access_denied=True manifest_parse=False activation_failed=False common_controls=False vc_crt=False";
    let expected = format!(
        "evidence-selected-count selected_observed=2 total_matches=unknown first_qualified=True first_flags=[{first_flags}] second_qualified=False second_flags=[{second_flags}] second_unsupported=False further_blocks_examined=False"
    );
    for suffix in [
        String::new(),
        first.clone(),
        format!("{}\n{}\n", fixture::BEGIN, fixture::BEGIN),
    ] {
        let caught = super::failure_evidence(
            &fixture::utf8(&(first.clone() + &second + &suffix)),
            manifest,
        )
        .expect_err("second selection must fail");
        need(
            stage(&caught)? == expected
                && caught.to_string().len() < 1024
                && stage(private(&caught)?.original())? == "evidence-selected-count",
        )?;
        fixture::withheld(&caught)?;
        let sanitized = crate::windows_security::policy::registry_comparison::wire::sanitize(
            crate::windows_security::activation::Failures {
                errors: vec![caught],
            }
            .into(),
        );
        need(!format!("{sanitized:?}").contains("sentinel"))?;
    }
    for unsupported in [false, true] {
        let current = second.replace(
            "ERROR: Access is denied.",
            if unsupported {
                "ERROR: private-unknown-sentinel"
            } else {
                "INFO: benign"
            },
        );
        let caught = super::failure_evidence(&fixture::utf8(&(first.clone() + &current)), manifest)
            .expect_err("unqualified second selection must fail");
        need(stage(&caught)?==expected.replace(second_flags,"unresolved_reference=False access_denied=False manifest_parse=False activation_failed=False common_controls=False vc_crt=False").replace("second_unsupported=False",if unsupported{"second_unsupported=True"}else{"second_unsupported=False"}))?;
    }
    let caught = super::failure_evidence(&fixture::utf16(&(first.clone() + &second)), manifest)
        .expect_err("UTF16 second selection must fail");
    need(stage(&caught)? == expected)?;
    for value in [
        first.replace(
            "Microsoft.Windows.Common-Controls",
            "private-reference-sentinel",
        ) + &second,
        first.replace(
            "ERROR: Cannot resolve reference Microsoft.Windows.Common-Controls.",
            "INFO: benign",
        ) + &second,
        format!("{}\n{first}{second}", fixture::BEGIN),
        format!("{first}{second}\0"),
        format!("{first}{second}{}", "x".repeat(2049)),
    ] {
        let caught = super::failure_evidence(&fixture::utf8(&value), manifest)
            .expect_err("earlier evidence failure must win");
        need(!stage(&caught)?.contains("selected_observed"))?;
        fixture::withheld(&caught)?;
    }
    Ok(())
}
