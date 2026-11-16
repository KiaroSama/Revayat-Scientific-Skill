//! Original ActivationAssemblyAccess.CheckValidation's bounded-buffer and refusal assertions.
use super::*;
use std::{
    cell::{Cell, RefCell},
    mem::{offset_of, size_of},
};
pub fn check_assembly_contract(root: &str, windows: &str) -> Result<()> {
    ensure!(
        size_of::<usize>() == 8
            && size_of::<AssemblyInfo>() == 104
            && offset_of!(AssemblyInfo, path) == 72
            && offset_of!(AssemblyInfo, path_bytes) == 12
            && offset_of!(AssemblyInfo, path_type) == 8,
        "activation assembly ABI differs"
    );
    check_cleanup_validation()?;
    let mut bytes = vec![0u8; 65536];
    const START: u64 = 0x1000;
    let literal = "C:\\fixed\\python.exe"
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    bytes[104..104 + literal.len()].copy_from_slice(&literal);
    ensure!(
        decode_path(
            &bytes,
            START,
            104 + literal.len(),
            START + 104,
            literal.len() as u32 - 2
        )? == "C:\\fixed\\python.exe",
        "activation path literal differs"
    );
    require_path_type(2)?;
    let mut lines = Vec::new();
    for count in [0u32, 1, 2, 3, 4, u32::MAX] {
        bytes[8..12].copy_from_slice(&count.to_le_bytes());
        lines.clear();
        let result = read_count(&bytes, 64, &mut lines);
        ensure!(
            result.is_ok() == (1..=3).contains(&count)
                && (result.is_err() || result? == count)
                && lines
                    == [format!(
                        "WINDOWS_ACTIVATION_QUERY context=host class=2 returned_bytes=64 assembly_count={count} cause_claimed=False"
                    )],
            "activation query count/refusal metadata differs"
        );
    }
    lines.clear();
    ensure!(
        read_count(&bytes, 63, &mut lines).is_err()
            && read_count(&bytes, 65537, &mut lines).is_err()
            && lines.is_empty(),
        "activation unqualified query size was logged"
    );
    for (returned, pointer, length) in [
        (104, START + 104, 2),
        (65536, START, 2),
        (65536, START + 104, 3),
        (65536, 0, 2),
        (65536, START + 104, 0),
        (65536, START + 104, 2050),
        (65536, START + 65534, 2),
        (65536, START - 2, 2),
    ] {
        ensure!(
            decode_path(&bytes, START, returned, pointer, length).is_err(),
            "activation malformed path span accepted"
        );
    }
    ensure!(
        require_size(65537, 104).is_err() && require_size(103, 104).is_err(),
        "activation unqualified assembly span accepted"
    );
    for kind in [0, 1, 3, 4] {
        ensure!(
            require_path_type(kind).is_err(),
            "activation non-file path type accepted"
        );
    }
    for literal in [
        vec![0x41, 0, 0x42, 0],
        vec![0x41, 0, 0, 0, 0x42, 0, 0, 0],
        vec![0, 0xd8, 0, 0],
    ] {
        bytes.fill(0);
        bytes[104..104 + literal.len()].copy_from_slice(&literal);
        ensure!(
            decode_path(
                &bytes,
                START,
                104 + literal.len(),
                START + 104,
                literal.len() as u32 - 2
            )
            .is_err(),
            "activation malformed literal path accepted"
        );
    }
    let directory = format!("{windows}\\WinSxS\\Manifests");
    let controls = format!(
        "{directory}\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.0.0_none_fixed.manifest"
    );
    let resources = format!(
        "{directory}\\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.0.0_en-us_fixed.manifest"
    );
    ensure!(
        qualify_path(root, root, windows, 1)? == AssemblyLabel::Root,
        "activation root path fixture differs"
    );
    for index in [2, 3] {
        ensure!(
            qualify_path(&controls, root, windows, index)? == AssemblyLabel::CommonControls
                && qualify_path(&resources, root, windows, index)?
                    == AssemblyLabel::CommonControlsResources,
            "activation system manifest fixture differs"
        );
    }
    for labels in [
        &["python-root"][..],
        &["python-root", "common-controls-manifest"],
        &[
            "python-root",
            "common-controls-manifest",
            "common-controls-resources-manifest",
        ],
        &[
            "python-root",
            "common-controls-resources-manifest",
            "common-controls-manifest",
        ],
    ] {
        require_profile_names(labels, labels.len())?;
    }
    for (labels, count) in [
        (&[][..], 1),
        (
            &["python-root", "common-controls-resources-manifest"][..],
            2,
        ),
        (
            &[
                "python-root",
                "common-controls-manifest",
                "common-controls-manifest",
            ][..],
            3,
        ),
        (
            &[
                "common-controls-manifest",
                "python-root",
                "common-controls-resources-manifest",
            ][..],
            3,
        ),
        (
            &["python-root", "common-controls-manifest", "foreign"][..],
            3,
        ),
    ] {
        ensure!(
            require_profile_names(labels, count).is_err(),
            "activation incomplete/foreign profile accepted"
        );
    }
    ensure!(
        path_metadata("C:\\private\\canary.manifest", root, windows, 3, 104, 2)?
            == "WINDOWS_ACTIVATION_ASSEMBLY context=host class=3 index=3 returned_bytes=104 path_type=2 canonical=True python_root=False system_manifests=False common_controls=False common_controls_resources=False cause_claimed=False",
        "activation fixed path metadata differs"
    );
    for path in [
        "C:\\private\\canary.manifest".to_owned(),
        controls.replace("Manifests\\", "Manifests-sibling\\"),
        controls.replace("Manifests\\", "..\\Manifests\\"),
        controls.replace("fixed", "fíxed"),
        format!("{controls}:stream"),
        format!("{directory}\\x.manifest"),
        controls.replace(".manifest", ".dll"),
        format!("{directory}\\{}.manifest", "a".repeat(241)),
        "relative.manifest".into(),
        root.into(),
    ] {
        ensure!(
            qualify_path(&path, root, windows, 2).is_err(),
            "activation unqualified manifest path accepted"
        );
    }
    ensure!(
        qualify_path(&controls, root, windows, 1).is_err()
            && qualify_path(root, root, windows, 3).is_err()
            && qualify_path(&resources, root, windows, 1).is_err()
            && qualify_path(&resources, root, windows, 4).is_err(),
        "activation manifest index mismatch accepted"
    );
    bytes.fill(0);
    Ok(())
}
pub(crate) fn check_cleanup_validation() -> Result<()> {
    for primary in [false, true] {
        let order = RefCell::new(Vec::new());
        let operation = if primary {
            Err(anyhow::anyhow!("fixed assembly operation"))
        } else {
            Ok(())
        };
        let error = release(
            operation,
            vec![
                Box::new(|| {
                    order.borrow_mut().push(1);
                    anyhow::bail!("fixed assembly first release")
                }),
                Box::new(|| {
                    order.borrow_mut().push(2);
                    Ok(())
                }),
                Box::new(|| {
                    order.borrow_mut().push(3);
                    anyhow::bail!("fixed assembly second release")
                }),
            ],
        )
        .unwrap_err();
        let errors = &error
            .downcast_ref::<super::super::Failures>()
            .ok_or_else(|| anyhow::anyhow!("assembly release group missing"))?
            .errors;
        let expected: &[&str] = if primary {
            &[
                "fixed assembly operation",
                "fixed assembly first release",
                "fixed assembly second release",
            ]
        } else {
            &[
                "fixed assembly first release",
                "fixed assembly second release",
            ]
        };
        ensure!(
            *order.borrow() == [1, 2, 3]
                && errors.iter().map(ToString::to_string).collect::<Vec<_>>() == expected,
            "activation assembly independent release/error order differs"
        );
    }
    let released = Cell::new(0);
    let result: Result<()> = release(
        Err(anyhow::anyhow!("fixed assembly operation")),
        vec![
            Box::new(|| {
                released.set(released.get() + 1);
                Ok(())
            }),
            Box::new(|| {
                released.set(released.get() + 1);
                Ok(())
            }),
        ],
    );
    ensure!(
        released.get() == 2 && result.unwrap_err().to_string() == "fixed assembly operation",
        "activation independent release was skipped"
    );
    Ok(())
}
