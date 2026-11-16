//! Host output admission and chunk integrity checks share the existing mount registration.
use super::config;
use anyhow::Result;
use revayat_scientific::{build::file_hash, tex_container as tex};
use serde_json::json;
use std::fs;

pub(super) fn bounded_output_delivery_admission() -> Result<()> {
    let run = "b".repeat(32);
    for (manifest, expected) in [
        (
            json!([{"name":"document.pdf","size":tex::MAX_OUTPUT_BYTES,"sha256":"a".repeat(64)}, {"name":"console-pass-1.log","size":1,"sha256":"a".repeat(64)}]),
            "aggregate delivery budget",
        ),
        (
            json!([{"name":"document.pdf","size":1,"sha256":"a".repeat(64)}, {"name":"document.pdf","size":1,"sha256":"a".repeat(64)}]),
            "duplicate",
        ),
        (
            json!([{"name":"../outside","size":1,"sha256":"a".repeat(64)}]),
            "unexpected",
        ),
        (
            json!([{"name":"document.pdf","size":1,"sha256":"a".repeat(64),"unapproved":true}]),
            "manifest",
        ),
        (
            json!([{"name":"document.pdf","size":1,"sha256":"invalid"}]),
            "artifact digest",
        ),
    ] {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("output"))?;
        fs::write(root.path().join("container.cid"), "a".repeat(64))?;
        let mut copied = false;
        let error = tex::copy_outputs_with(&config(), root.path(), &run, tex::OUTPUT_FILES, &mut |args, _| {
            if args.iter().any(|arg| arg == "inspect") {
                return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{tex::RUN_LABEL:run}}}]).to_string()));
            }
            if args.iter().any(|arg| arg == "--output-manifest") {
                return Ok((0,manifest.to_string()));
            }
            copied = true;
            anyhow::bail!("copy must not run after rejected admission")
        }).unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert!(!copied, "aggregate admission must precede every host copy");
        assert_eq!(fs::read_dir(root.path().join("output"))?.count(), 0);
    }
    for mismatch in ["label", "name", "cid"] {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("output"))?;
        fs::write(root.path().join("container.cid"), "a".repeat(64))?;
        let mut accessed = false;
        let result = tex::copy_outputs_with(
            &config(),
            root.path(),
            &run,
            tex::OUTPUT_FILES,
            &mut |args, _| {
                if args.iter().any(|arg| arg == "inspect") {
                    let mut row = json!({"Id":"a".repeat(64),"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{tex::RUN_LABEL:run}}});
                    match mismatch {
                        "label" => row["Config"]["Labels"][tex::RUN_LABEL] = json!("other"),
                        "name" => row["Name"] = json!("/foreign-container"),
                        _ => row["Id"] = json!("c".repeat(64)),
                    }
                    return Ok((0, json!([row]).to_string()));
                }
                accessed = true;
                anyhow::bail!("unowned exec/copy must not run")
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("matching ownership")
        );
        assert!(!accessed);
    }
    bounded_output_chunks()
}

fn bounded_output_chunks() -> Result<()> {
    use base64::Engine;
    let run = "b".repeat(32);
    for (payload, expected) in [
        ("!!!!", "encoding"),
        ("YQ==", "digest"),
        ("YWE=", "admitted length"),
        ("YQ", "read failed"),
    ] {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("output"))?;
        fs::write(root.path().join("container.cid"), "a".repeat(64))?;
        fs::write(root.path().join("expected"), b"b")?;
        fs::write(
            root.path().join("delivery.pdf"),
            b"previous approved delivery",
        )?;
        let digest = file_hash(&root.path().join("expected"))?;
        let error = tex::copy_outputs_with(&config(),root.path(),&run,tex::OUTPUT_FILES,&mut |args,_| {
            if args.iter().any(|arg| arg == "inspect") {
                return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{tex::RUN_LABEL:run}}}]).to_string()));
            }
            if args.iter().any(|arg| arg == "--output-manifest") {
                return Ok((0,json!([{"name":"document.pdf","size":1,"sha256":digest}]).to_string()));
            }
            let index = args.iter().position(|arg| arg == "--read-output").unwrap();
            assert_eq!(&args[index+1..],["document.pdf","0","1"]);
            Ok((0,payload.into()))
        }).unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert_eq!(
            fs::read(root.path().join("delivery.pdf"))?,
            b"previous approved delivery"
        );
    }
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("output"))?;
    fs::write(root.path().join("container.cid"), "a".repeat(64))?;
    let bytes = (0..tex::OUTPUT_CHUNK_BYTES + 7)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(root.path().join("expected"), &bytes)?;
    let digest = file_hash(&root.path().join("expected"))?;
    let mut offsets = Vec::new();
    tex::copy_outputs_with(
        &config(),
        root.path(),
        &run,
        tex::OUTPUT_FILES,
        &mut |args, _| {
            if args.iter().any(|arg| arg == "inspect") {
                return Ok((0,json!([{"Id":"a".repeat(64),"Name":format!("/revayat-tex-{run}"),"Config":{"Labels":{tex::RUN_LABEL:run}}}]).to_string()));
            }
            if args.iter().any(|arg| arg == "--output-manifest") {
                return Ok((
                    0,
                    json!([{"name":"document.pdf","size":bytes.len(),"sha256":digest}]).to_string(),
                ));
            }
            let index = args.iter().position(|arg| arg == "--read-output").unwrap();
            let offset: usize = args[index + 2].parse()?;
            let count: usize = args[index + 3].parse()?;
            offsets.push((offset, count));
            assert!(count as u64 <= tex::OUTPUT_CHUNK_BYTES);
            Ok((
                0,
                base64::engine::general_purpose::STANDARD.encode(&bytes[offset..offset + count]),
            ))
        },
    )?;
    assert_eq!(
        offsets,
        [
            (0, tex::OUTPUT_CHUNK_BYTES as usize),
            (tex::OUTPUT_CHUNK_BYTES as usize, 7)
        ]
    );
    assert_eq!(fs::read(root.path().join("output/document.pdf"))?, bytes);
    Ok(())
}
