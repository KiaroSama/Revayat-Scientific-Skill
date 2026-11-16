use anyhow::{Result, bail};
use revayat_scientific::{
    build::{self, BuildGuard, DeliveryBoundary},
    publication::Boundary,
    render,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    private: PathBuf,
    record: PathBuf,
    source: PathBuf,
    terms: PathBuf,
    manifest: PathBuf,
    asset: PathBuf,
    working: PathBuf,
    output: PathBuf,
    samples: Vec<PathBuf>,
}
fn png(path: &Path) -> Result<()> {
    image::RgbImage::from_pixel(24, 24, image::Rgb([255, 255, 255])).save(path)?;
    Ok(())
}
#[path = "support/build_limits.rs"]
mod limits;
mod runtime_support;
use runtime_support::pdf;
impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let private = root.join("private");
        fs::create_dir(&private)?;
        let s = Self {
            _temp: temp,
            record: private.join("build.json"),
            source: root.join("doc.html"),
            terms: root.join("terms.tsv"),
            manifest: root.join("manifest.txt"),
            asset: root.join("figure.png"),
            working: root.join("work.pdf"),
            output: root.join("delivered.pdf"),
            samples: ["first", "last", "mid"]
                .into_iter()
                .map(|s| root.join(format!("verify-article-{s}.png")))
                .collect(),
            root,
            private,
        };
        fs::write(
            &s.source,
            b"<html lang=\"fa\" dir=\"rtl\"><body><img src=\"figure.png\"></body></html>",
        )?;
        fs::write(&s.terms, b"source\toutput\n")?;
        fs::write(&s.manifest, b"figure.png\n")?;
        png(&s.asset)?;
        fs::write(&s.working, b"previous working file")?;
        fs::write(&s.output, b"previous approved delivery")?;
        Ok(s)
    }
    fn inputs(&self) -> Result<Vec<PathBuf>> {
        build::document_inputs(
            &self.source,
            &[self.terms.clone(), self.manifest.clone()],
            None,
        )
    }
    fn outputs(&self) -> Vec<PathBuf> {
        [
            vec![self.working.clone(), self.output.clone()],
            self.samples.clone(),
        ]
        .concat()
    }
    fn create(&self) -> Result<BuildGuard> {
        BuildGuard::create(&self.record, &self.inputs()?, &self.outputs())
    }
    fn seal(&self) -> Result<()> {
        pdf(&self.working)?;
        BuildGuard::seal(
            &self.record,
            &self.working,
            &build::file_hash(&self.working)?,
        )
    }
    fn unchanged(&self) -> Result<()> {
        assert_eq!(fs::read(&self.output)?, b"previous approved delivery");
        Ok(())
    }
    fn stages(&self) -> Result<Vec<PathBuf>> {
        let mut result = vec![];
        for sample in &self.samples {
            let p = self.private.join(sample.file_name().unwrap());
            png(&p)?;
            result.push(p);
        }
        Ok(result)
    }
}
#[test]
fn test_plan_captures_explicit_inputs_assets_and_requested_fallback() -> Result<()> {
    let f = Fixture::new()?;
    let requested = f.root.join("original.tex");
    fs::write(&requested, b"retained sibling")?;
    let inputs = build::document_inputs(
        &f.source,
        &[f.terms.clone(), f.manifest.clone()],
        Some(&requested),
    )?;
    let g = BuildGuard::create(&f.record, &inputs, &f.outputs())?;
    assert_eq!(
        g.inputs
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [
            f.source.clone(),
            f.asset.clone(),
            f.terms.clone(),
            f.manifest.clone(),
            requested
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(g.outputs.len(), 5);
    let checked = BuildGuard::check(&f.record, None)?;
    assert_eq!(serde_json::to_value(&checked)?, serde_json::to_value(&g)?);
    Ok(())
}
#[test]
fn test_nested_tex_closure_is_captured_without_modifying_inputs() -> Result<()> {
    let f = Fixture::new()?;
    let source = f.root.join("doc.tex");
    let child = f.root.join("part.tex");
    fs::write(&source, b"\\input{part}\n\\includegraphics{figure.png}")?;
    fs::write(&child, b"child without newline")?;
    let before = fs::read(&child)?;
    let asset_before = fs::read(&f.asset)?;
    let inputs = build::document_inputs(&source, &[], None)?;
    assert!(inputs.contains(&child) && inputs.contains(&f.asset));
    assert_eq!(fs::read(&child)?, before);
    assert_eq!(
        fs::read(&source)?,
        b"\\input{part}\n\\includegraphics{figure.png}"
    );
    assert_eq!(fs::read(&f.asset)?, asset_before);
    Ok(())
}
#[test]
fn test_each_preview_collision_is_rejected_before_mutation() -> Result<()> {
    for role in ["first", "last", "mid"] {
        let f = Fixture::new()?;
        let sample = f.root.join(format!("verify-article-{role}.png"));
        png(&sample)?;
        fs::write(
            &f.source,
            format!(
                "<html><img src=\"{}\"></html>",
                sample.file_name().unwrap().to_string_lossy()
            ),
        )?;
        let before = fs::read(&sample)?;
        assert!(
            f.create()
                .unwrap_err()
                .to_string()
                .contains("protected source")
        );
        assert_eq!(fs::read(sample)?, before);
        assert!(!f.record.exists());
    }
    Ok(())
}
#[test]
fn test_pdf_destinations_cannot_overwrite_sidecars_or_vector_assets() -> Result<()> {
    for field in ["terms", "manifest", "asset"] {
        let f = Fixture::new()?;
        let target = f.root.join("reserved.pdf");
        if field == "asset" {
            pdf(&target)?;
            fs::write(&f.source, b"<html><img src=\"reserved.pdf\"></html>")?;
        } else {
            fs::write(&target, b"sidecar")?;
        }
        let mut inputs = f.inputs()?;
        if field != "asset" {
            inputs.push(target.clone());
        }
        let before = fs::read(&target)?;
        assert!(
            BuildGuard::create(&f.record, &inputs, &[f.working.clone(), target.clone()]).is_err()
        );
        assert_eq!(fs::read(target)?, before);
        assert!(!f.record.exists());
    }
    Ok(())
}
#[test]
fn test_symlink_hardlink_and_duplicate_output_aliases_are_rejected() -> Result<()> {
    let f = Fixture::new()?;
    let alias = f.root.join("alias.pdf");
    fs::hard_link(&f.terms, &alias)?;
    let terms_id = revayat_scientific::identity::path_object_id(&f.terms)?;
    assert!(
        BuildGuard::create(&f.record, &f.inputs()?, &[f.working.clone(), alias.clone()]).is_err()
    );
    assert_eq!(
        revayat_scientific::identity::path_object_id(&alias)?,
        terms_id
    );
    fs::remove_file(&alias)?;
    fs::hard_link(&f.working, &alias)?;
    assert!(
        BuildGuard::create(&f.record, &f.inputs()?, &[f.working.clone(), alias.clone()]).is_err()
    );
    assert!(
        BuildGuard::create(
            &f.record,
            &f.inputs()?,
            &[f.working.clone(), f.working.clone()]
        )
        .is_err()
    );
    fs::remove_file(&alias)?;
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&f.output, &alias);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&f.output, &alias);
    if linked.is_ok() {
        assert!(
            BuildGuard::create(&f.record, &f.inputs()?, &[f.working.clone(), alias.clone()])
                .is_err()
        );
        assert!(fs::symlink_metadata(&alias)?.file_type().is_symlink());
    } else {
        eprintln!("symlink capability unavailable; hardlink controls executed");
    }
    Ok(())
}
#[test]
fn test_changes_to_each_checked_input_invalidate_the_run() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    for path in [&f.source, &f.terms, &f.manifest, &f.asset] {
        let original = fs::read(path)?;
        fs::write(path, [original.clone(), b" changed".to_vec()].concat())?;
        assert!(BuildGuard::check(&f.record, None).is_err());
        fs::write(path, original)?;
        BuildGuard::check(&f.record, None)?;
    }
    f.unchanged()
}
#[test]
fn test_actual_runtime_resource_is_added_and_then_frozen() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    let css = f.root.join("style.css");
    fs::write(&css, b"body{}")?;
    let g = BuildGuard::check(
        &f.record,
        Some(&BTreeMap::from([(css.clone(), build::file_hash(&css)?)])),
    )?;
    assert!(g.inputs.contains_key(&css));
    fs::write(css, b"body{color:red}")?;
    assert!(BuildGuard::check(&f.record, None).is_err());
    Ok(())
}
#[test]
fn test_css_only_preview_dependency_is_not_a_publish_destination() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    png(&f.samples[0])?;
    let before = fs::read(&f.record)?;
    assert!(
        BuildGuard::check(
            &f.record,
            Some(&BTreeMap::from([(
                f.samples[0].clone(),
                build::file_hash(&f.samples[0])?
            )]))
        )
        .is_err()
    );
    assert_eq!(fs::read(&f.record)?, before);
    assert_eq!(fs::read(&f.samples[0])?, fs::read(&f.asset)?);
    Ok(())
}
#[test]
fn test_runtime_cannot_substitute_an_already_checked_revision() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    assert!(
        BuildGuard::check(
            &f.record,
            Some(&BTreeMap::from([(f.source.clone(), "0".repeat(64))]))
        )
        .is_err()
    );
    assert_eq!(fs::read(f.working)?, b"previous working file");
    Ok(())
}
#[test]
fn test_rendered_hash_prevents_delivering_another_builds_working_pdf() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    fs::write(&f.working, b"other build")?;
    assert!(BuildGuard::deliver(&f.record).is_err());
    f.unchanged()
}
#[test]
fn test_unsealed_or_wrong_target_delivery_cannot_pass() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    assert!(BuildGuard::deliver(&f.record).is_err());
    f.seal()?;
    assert!(BuildGuard::seal(&f.record, &f.output, &build::file_hash(&f.output)?).is_err());
    let other = f.root.join("other.pdf");
    let mut forged = serde_json::to_value(BuildGuard::check(&f.record, None)?)?;
    forged["rendered"] =
        serde_json::json!({other.display().to_string():build::file_hash(&f.working)?});
    fs::write(&f.record, serde_json::to_vec(&forged)?)?;
    assert!(BuildGuard::deliver(&f.record).is_err());
    assert!(!other.exists());
    f.unchanged()
}
#[test]
fn test_valid_delivery_is_byte_equal_to_the_sealed_renderer_output() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    let source = fs::read(&f.source)?;
    BuildGuard::deliver(&f.record)?;
    assert_eq!(fs::read(&f.output)?, fs::read(&f.working)?);
    assert_eq!(fs::read(&f.source)?, source);
    Ok(())
}
#[test]
fn test_delivery_uses_bounded_streaming_identity() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    pdf(&f.working)?;
    let file = fs::OpenOptions::new().write(true).open(&f.working)?;
    file.set_len(8 * 1024 * 1024)?;
    BuildGuard::seal(&f.record, &f.working, &build::file_hash(&f.working)?)?;
    let mut reads = 0;
    BuildGuard::deliver_with_identity(
        &f.record,
        build::MAX_FILE_BYTES,
        |_, _, _| Ok(()),
        |path, limit| {
            assert_eq!(limit, Some(build::MAX_FILE_BYTES));
            revayat_scientific::identity::file_identity_observed(path, limit, |boundary, _| {
                if let revayat_scientific::identity::ReadBoundary::BeforeRead(requested) = boundary
                {
                    assert!(requested <= revayat_scientific::identity::CHUNK_BYTES);
                    reads += 1;
                }
                Ok(())
            })
        },
    )?;
    assert!(
        reads > 8,
        "actual guarded delivery must stream through bounded read chunks"
    );
    assert_eq!(build::file_hash(&f.output)?, build::file_hash(&f.working)?);
    assert!(f.working.exists());
    Ok(())
}
#[test]
fn test_delivery_rejects_changed_staging_and_preserves_previous_output() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    let original = fs::read(&f.working)?;
    assert!(
        BuildGuard::deliver_observed(&f.record, |phase, _, stage| {
            if phase == DeliveryBoundary::AfterCopy {
                fs::write(stage, b"corrupted stage")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(&f.working)?, original);
    f.unchanged()
}
#[test]
fn test_delivery_rejects_a_source_revision_copied_as_a_new_baseline() -> Result<()> {
    limits::growing_delivery()?;
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    assert!(
        BuildGuard::deliver_observed(&f.record, |phase, source, _| {
            if phase == DeliveryBoundary::BeforeCopy {
                fs::write(source, b"new source revision")?;
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(&f.working)?, b"new source revision");
    f.unchanged()
}
#[test]
fn test_delivery_still_refuses_inputs_above_the_explicit_build_limit() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    fs::OpenOptions::new()
        .write(true)
        .open(&f.working)?
        .set_len(build::MAX_FILE_BYTES + 1)?;
    assert!(BuildGuard::deliver(&f.record).is_err());
    f.unchanged()?;
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    let original = fs::read(&f.working)?;
    assert!(
        BuildGuard::deliver_with_identity(
            &f.record,
            4,
            |_, _, _| Ok(()),
            revayat_scientific::identity::file_identity
        )
        .is_err()
    );
    assert_eq!(fs::read(&f.working)?, original);
    f.unchanged()?;
    assert!(!fs::read_dir(&f.root)?.any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-delivery-")
    }));
    Ok(())
}
#[test]
fn test_invalid_record_duplicate_keys_and_oversized_maps_fail_explicitly() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    let original = fs::read(&f.record)?;
    assert!(
        BuildGuard::load_with_limit(&f.record, 10)
            .unwrap_err()
            .to_string()
            .contains("bounded")
    );
    assert_eq!(
        BuildGuard::load_with_limit(&f.record, original.len() as u64)?.schema,
        1
    );
    for raw in [
        b"[]".as_slice(),
        b"{\"schema\":1,\"schema\":1}",
        b"{\"schema\":true,\"inputs\":{}}",
    ] {
        fs::write(&f.record, raw)?;
        assert!(BuildGuard::load(&f.record).is_err());
    }
    let correct: serde_json::Value = serde_json::from_slice(&original)?;
    for key in ["schema", "inputs", "outputs", "rendered"] {
        let mut wrong = correct.clone();
        wrong[key] = match key {
            "schema" => serde_json::json!(true),
            "inputs" => serde_json::json!([]),
            "outputs" => serde_json::json!([{}, f.output]),
            _ => serde_json::json!({f.output.display().to_string():"0".repeat(64)}),
        };
        fs::write(&f.record, serde_json::to_vec(&wrong)?)?;
        assert!(BuildGuard::check(&f.record, None).is_err(), "{key}");
    }
    let mut oversized = correct.clone();
    let map = oversized["inputs"].as_object_mut().unwrap();
    map.clear();
    for i in 0..=build::MAX_FILES {
        map.insert(
            f.root.join(format!("input-{i}")).display().to_string(),
            serde_json::json!("0".repeat(64)),
        );
    }
    fs::write(&f.record, serde_json::to_vec(&oversized)?)?;
    assert!(BuildGuard::check(&f.record, None).is_err());
    fs::write(&f.record, &original)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&f.record)?
        .set_len(build::MAX_RECORD_BYTES + 1)?;
    assert!(BuildGuard::load(&f.record).is_err());
    Ok(())
}
#[test]
fn test_existing_pending_record_is_never_deleted_on_exclusive_create_failure() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    let pending = f.record.with_file_name("build.json.pending");
    fs::write(&pending, b"another writer sentinel")?;
    let css = f.root.join("new.css");
    fs::write(&css, b"body{}")?;
    let before = fs::read(&f.record)?;
    assert!(
        BuildGuard::check(
            &f.record,
            Some(&BTreeMap::from([(css.clone(), build::file_hash(&css)?)]))
        )
        .is_err()
    );
    assert_eq!(fs::read(pending)?, b"another writer sentinel");
    assert_eq!(fs::read(&f.record)?, before);
    Ok(())
}
#[test]
fn test_missing_and_oversized_inputs_are_not_silently_fingerprinted() -> Result<()> {
    let f = Fixture::new()?;
    let huge = f.root.join("huge.dat");
    fs::File::create(&huge)?.set_len(build::MAX_FILE_BYTES + 1)?;
    assert!(BuildGuard::create(&f.record, &[huge], &f.outputs()).is_err());
    assert!(!f.record.exists());
    f.create()?;
    fs::remove_file(&f.asset)?;
    assert!(BuildGuard::check(&f.record, None).is_err());
    Ok(())
}
#[test]
fn test_sample_batch_validates_every_png_before_replacing_any_preview() -> Result<()> {
    limits::preview_admission()?;
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    for sample in &f.samples {
        fs::write(sample, b"previous preview")?;
    }
    let stages = f.stages()?;
    fs::write(&stages[1], b"not PNG")?;
    assert!(BuildGuard::publish_previews(&f.record, &stages).is_err());
    for sample in &f.samples {
        assert_eq!(fs::read(sample)?, b"previous preview");
    }
    Ok(())
}
#[test]
fn test_sample_publication_rolls_back_earlier_replacements() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    for sample in &f.samples {
        fs::write(sample, b"previous preview")?;
    }
    let stages = f.stages()?;
    assert!(
        BuildGuard::publish_previews_observed(&f.record, &stages, |phase, destination| {
            if phase == Boundary::BeforeCommit && destination == f.samples[1] {
                bail!("injected second-preview failure");
            }
            Ok(())
        })
        .is_err()
    );
    for sample in &f.samples {
        assert_eq!(fs::read(sample)?, b"previous preview");
    }
    assert!(!fs::read_dir(&f.root)?.any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".revayat-publish-")
    }));
    Ok(())
}
#[test]
fn test_sample_staging_cannot_consume_unplanned_or_outside_files() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    f.seal()?;
    let stages = f.stages()?;
    let outside = f.root.join(stages[0].file_name().unwrap());
    png(&outside)?;
    let before = fs::read(&outside)?;
    let mut selected = stages.clone();
    selected[0] = outside.clone();
    assert!(BuildGuard::publish_previews(&f.record, &selected).is_err());
    assert!(outside.exists());
    assert_eq!(fs::read(&outside)?, before);
    let unplanned = f.private.join("unplanned.png");
    png(&unplanned)?;
    let unplanned_before = fs::read(&unplanned)?;
    assert!(BuildGuard::publish_previews(&f.record, std::slice::from_ref(&unplanned)).is_err());
    assert_eq!(fs::read(&unplanned)?, unplanned_before);
    Ok(())
}
#[test]
fn test_partial_preview_set_and_duplicate_basenames_are_refused() -> Result<()> {
    let f = Fixture::new()?;
    let mut outputs = f.outputs();
    outputs[3] = f.private.join(outputs[2].file_name().unwrap());
    assert!(BuildGuard::create(&f.record, &f.inputs()?, &outputs).is_err());
    f.create()?;
    f.seal()?;
    let stages = f.stages()?;
    assert!(BuildGuard::publish_previews(&f.record, &stages[..2]).is_err());
    let duplicate = vec![stages[0].clone(), stages[0].clone(), stages[2].clone()];
    assert!(BuildGuard::publish_previews(&f.record, &duplicate).is_err());
    assert!(!f.samples.iter().any(|path| path.exists()));
    Ok(())
}
#[test]
fn test_html_actual_resources_block_a_late_collision_before_working_pdf_publication() -> Result<()>
{
    let f = Fixture::new()?;
    f.create()?;
    png(&f.samples[0])?;
    assert!(
        render::render_html_with(&f.source, &f.working, Some(&f.record), |policy, target| {
            policy.fetch(&format!(
                "https://revayat.invalid/{}",
                f.samples[0].file_name().unwrap().to_string_lossy()
            ))?;
            pdf(target)
        })
        .is_err()
    );
    assert_eq!(fs::read(&f.working)?, b"previous working file");
    f.unchanged()
}
#[test]
fn test_html_worker_cannot_deliver_after_a_terminology_revision_change() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    assert!(
        render::render_html_with(&f.source, &f.working, Some(&f.record), |_, target| {
            pdf(target)?;
            fs::write(&f.terms, b"new terminology")?;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(&f.working)?, b"previous working file");
    f.unchanged()
}
#[test]
fn test_html_seals_successful_output_and_does_not_allow_guard_on_worker_path() -> Result<()> {
    let f = Fixture::new()?;
    f.create()?;
    render::render_html_with(&f.source, &f.working, Some(&f.record), |_, target| {
        pdf(target)
    })?;
    let g = BuildGuard::check(&f.record, None)?;
    assert_eq!(
        g.rendered.get(&f.working),
        Some(&build::file_hash(&f.working)?)
    );
    assert!(
        render::cli_render(&[
            f.source.display().to_string(),
            f.working.display().to_string(),
            "--worker".into()
        ])
        .is_err()
    );
    Ok(())
}
