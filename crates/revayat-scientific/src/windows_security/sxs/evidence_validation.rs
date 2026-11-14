//! Complete original callable parser/report validators; never collector execution evidence.
use super::{
    evidence as core,
    fixture::{self, need, private, stage},
};
use crate::windows_security::{activation::Failures, sxs::PrivateFailure};
use anyhow::Result;

fn original_kind(mut error: &anyhow::Error) -> bool {
    for _ in 0..8 {
        if let Some(value) = error.downcast_ref::<PrivateFailure>() {
            error = value.original();
        } else if let Some(value) = error.downcast_ref::<Failures>() {
            let Some(first) = value.errors.first() else {
                return false;
            };
            error = first;
        } else {
            return error.is::<core::ContractFailure>()
                || error.is::<std::string::FromUtf16Error>()
                || error.is::<std::str::Utf8Error>();
        }
    }
    false
}
/// Original SxsTraceEvidence.CheckValidation body, through the production parser.
pub fn check_evidence_validation() -> Result<()> {
    let manifest = "F:\\python\\DLLs\\_ctypes.pyd";
    let block = fixture::block(
        manifest,
        "ERROR: Cannot resolve reference Microsoft.Windows.Common-Controls,type=\"win32\",version=\"6.0.0.0\".\nERROR: Activation Context generation failed.",
    );
    let result = super::failure_evidence(&fixture::utf16(&block), manifest)?;
    need(
        result.contains("unresolved_reference=True")
            && result.contains("common_controls=True")
            && !result.contains(manifest),
    )?;
    need(
        super::failure_evidence(
            &fixture::utf16(&block.replace(
                fixture::END,
                &format!(
                    "INFO: Reference: Microsoft.Windows.Common-Controls,type=\"win32\"\n{}",
                    fixture::END
                ),
            )),
            manifest,
        )?
        .contains("common_controls=True"),
    )?;
    for bytes in [
        vec![],
        block.as_bytes().to_vec(),
        fixture::utf16(&block.replace(fixture::END, "")),
        fixture::utf16(&(block.clone() + &block)),
        fixture::utf16(&block.replace(manifest, "private-path-sentinel")),
        fixture::utf16(&block.replace(
            "Microsoft.Windows.Common-Controls",
            "private-dependency-sentinel",
        )),
        fixture::utf16(&"x".repeat(2049)),
        fixture::utf16(&block.replace(
            "ERROR: Cannot resolve reference Microsoft.Windows.Common-Controls",
            "ERROR: private-error-sentinel",
        )),
        fixture::utf16(&block.replace(
            fixture::END,
            &format!(
                "INFO: Reference: private-reference-sentinel\n{}",
                fixture::END
            ),
        )),
        fixture::utf16(&fixture::block(manifest, "INFO: benign observation")),
        [fixture::utf16(&block), vec![0, 216]].concat(),
    ] {
        let caught = super::failure_evidence(&bytes, manifest)
            .expect_err("invalid original evidence fixture must fail");
        need(original_kind(&caught))?;
        fixture::withheld(&super::super::safe(caught, "parse"))?;
    }
    Ok(())
}

fn refuse(bytes: Option<&[u8]>, manifest: &str, label: &str) -> Result<()> {
    let caught = super::failure_evidence_optional(bytes, manifest)
        .expect_err("invalid original reporting fixture must fail");
    fixture::withheld(&caught)?;
    let retained = if label == "selected-count" {
        private(&caught)?.original()
    } else {
        &caught
    };
    let prefix = if label.starts_with("length-input-shape") || label == "bom" {
        let absent = bytes.is_none_or(|bytes| bytes.is_empty());
        let count = bytes.map_or(0, |bytes| bytes.len().min(3));
        format!(
            " evidence-prefix status=array signature={} transferred_bytes={count}",
            if absent { "absent" } else { "other" }
        )
    } else {
        String::new()
    };
    need(stage(retained)? == format!("evidence-{label}{prefix}"))
}
fn reporting_body() -> Result<()> {
    super::length_validation::check_length_validation()?;
    super::stream::check_prefix_validation()?;
    super::codec_validation::check_codec_validation()?;
    super::selection_validation::check_selection_validation()?;
    let empty = super::failure_evidence(&[], "private-manifest-sentinel")
        .expect_err("empty evidence must fail");
    need(
        stage(&empty)?
            == "evidence-length-input-shape comparison=minimum observed_bytes=0 maximum_bytes=1048576 even=not-evaluated evidence-prefix status=array signature=absent transferred_bytes=0",
    )?;
    fixture::withheld(&empty)?;
    let manifest = "F:\\private-manifest-sentinel\\_ctypes.pyd";
    let block = fixture::block(manifest, "ERROR: Activation Context generation failed.");
    need(
        super::failure_evidence(&fixture::utf16(&block), manifest)?
            .contains("activation_failed=True")
            && super::failure_evidence(&fixture::utf8(&block), manifest)?
                == super::failure_evidence(&fixture::utf16(&block), manifest)?,
    )?;
    refuse(
        None,
        manifest,
        "length-input-shape comparison=present observed_bytes=absent maximum_bytes=1048576 even=not-evaluated",
    )?;
    for (bytes, label) in [
        (
            vec![0; 1],
            "length-input-shape comparison=minimum observed_bytes=1 maximum_bytes=1048576 even=not-evaluated",
        ),
        (
            vec![0; 1_048_578],
            "length-input-shape comparison=maximum observed_bytes=1048578 maximum_bytes=1048576 even=not-evaluated",
        ),
        (vec![0; 3], "bom"),
        (vec![0; 1_048_576], "bom"),
        (vec![0; 2], "bom"),
        (fixture::utf16("\0"), "nul"),
        (fixture::utf16(&"\n".repeat(4096)), "line-count"),
        (
            fixture::utf16(&format!("\r\n{}", "x".repeat(2049))),
            "line-width",
        ),
        (
            fixture::utf16(&format!("\r\n\rx\n{}", "x".repeat(2049))),
            "cr",
        ),
        (fixture::utf16("private-framing-sentinel"), "framing"),
        (
            fixture::utf16(&format!("{}\n{block}", fixture::BEGIN)),
            "nested",
        ),
        (
            fixture::utf16(&format!("{}\n{}\n", fixture::BEGIN, fixture::END).repeat(65)),
            "block-count",
        ),
        (fixture::utf16(fixture::END), "end"),
        (fixture::utf16(&(block.clone() + &block)), "selected-count"),
        (
            fixture::utf16(&block.replace(
                "ManifestPath = ",
                &format!("ManifestPath = {manifest}\nManifestPath = "),
            )),
            "manifest-count",
        ),
        (
            fixture::utf16(&block.replace(
                "ERROR: Activation Context generation failed.",
                "ERROR: private-error-sentinel",
            )),
            "unsupported",
        ),
        (
            fixture::utf16(&block.replace(
                "ERROR: Activation Context generation failed.",
                "INFO: benign",
            )),
            "empty",
        ),
        (fixture::utf16(&block.replace(fixture::END, "")), "final"),
        (vec![255, 254, 0, 216], "utf16"),
    ] {
        refuse(Some(&bytes), manifest, label)?;
    }
    for index in 0..16 {
        let predicate = core::Predicate::from_index(index)?;
        core::check(true, predicate)?;
        let caught = core::check(false, predicate).expect_err("false fixed predicate must fail");
        need(stage(&caught)? == predicate.label())?;
    }
    for invalid in [-1, 16, i32::MAX] {
        need(core::Predicate::from_index(invalid).is_err())?;
    }
    Ok(())
}
/// Original Reporting -> Length, Prefix/ReadOwned, Codec, Selection and exact predicate matrices.
pub fn check_reporting_validation() -> Result<()> {
    reporting_body().map_err(|error| super::super::safe(error, "evidence-validation"))
}
