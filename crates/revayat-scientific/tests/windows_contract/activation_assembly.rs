//! Bounded QueryActCtxW assembly buffers and fixed manifest-family ownership.
use revayat_scientific::windows_security::activation::assembly::*;
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn path_buffer() -> Vec<u8> {
    let mut bytes = vec![0; 256];
    let text = "C:\\fixed\\authority.exe";
    for (index, unit) in text.encode_utf16().chain(Some(0)).enumerate() {
        bytes[104 + index * 2..106 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes
}
#[test]
fn assembly_query_paths_are_inside_returned_span_with_strict_terminated_utf16() {
    let bytes = path_buffer();
    let path = "C:\\fixed\\authority.exe";
    let count = (path.encode_utf16().count() * 2) as u32;
    assert_eq!(
        decode_path(&bytes, 0x1000, 104 + count as usize + 2, 0x1068, count).unwrap(),
        path
    );
    for (size, address, count) in [
        (104, 0x1068, 2),
        (256, 0x1000, 2),
        (256, 0x1068, 3),
        (256, 0, 2),
        (256, 0x1068, 0),
        (256, 0x1068, 2050),
        (256, 0x10fe, 2),
        (256, 0xffe, 2),
        (257, 0x1068, 2),
    ] {
        assert!(decode_path(&bytes, 0x1000, size, address, count).is_err());
    }
    for literal in [
        vec![0x41, 0, 0x42, 0],
        vec![0x41, 0, 0, 0, 0x42, 0, 0, 0],
        vec![0, 216, 0, 0],
    ] {
        let mut bad = vec![0; 256];
        bad[104..104 + literal.len()].copy_from_slice(&literal);
        assert!(
            decode_path(
                &bad,
                0x1000,
                104 + literal.len(),
                0x1068,
                literal.len() as u32 - 2
            )
            .is_err()
        );
    }
    let mut count_buffer = vec![0; 64];
    for count in [0, 1, 2, 3, 4, u32::MAX] {
        put(&mut count_buffer, 8, count);
        assert_eq!(
            assembly_count(&count_buffer, 64).is_ok(),
            (1..=3).contains(&count)
        );
    }
    assert!(assembly_count(&count_buffer, 63).is_err());
    assert!(assembly_count(&count_buffer, 65537).is_err());
}
#[test]
fn fixed_root_and_system_manifest_families_preserve_index_and_complete_profile() {
    let root = "C:\\owned space\\authority.exe";
    let windows = "C:\\Windows";
    let controls = "C:\\Windows\\WinSxS\\Manifests\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.0.0_none_fixed.manifest";
    let resources = "C:\\Windows\\WinSxS\\Manifests\\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.0.0_en-us_fixed.manifest";
    assert_eq!(
        qualify_path(root, root, windows, 1).unwrap(),
        AssemblyLabel::Root
    );
    for index in [2, 3] {
        assert_eq!(
            qualify_path(controls, root, windows, index).unwrap(),
            AssemblyLabel::CommonControls
        );
        assert_eq!(
            qualify_path(resources, root, windows, index).unwrap(),
            AssemblyLabel::CommonControlsResources
        );
    }
    for labels in [
        vec![AssemblyLabel::Root],
        vec![AssemblyLabel::Root, AssemblyLabel::CommonControls],
        vec![
            AssemblyLabel::Root,
            AssemblyLabel::CommonControls,
            AssemblyLabel::CommonControlsResources,
        ],
        vec![
            AssemblyLabel::Root,
            AssemblyLabel::CommonControlsResources,
            AssemblyLabel::CommonControls,
        ],
    ] {
        require_profile(&labels, labels.len()).unwrap();
    }
    for labels in [
        vec![],
        vec![AssemblyLabel::Root, AssemblyLabel::CommonControlsResources],
        vec![
            AssemblyLabel::Root,
            AssemblyLabel::CommonControls,
            AssemblyLabel::CommonControls,
        ],
        vec![
            AssemblyLabel::CommonControls,
            AssemblyLabel::Root,
            AssemblyLabel::CommonControlsResources,
        ],
    ] {
        assert!(require_profile(&labels, labels.len()).is_err());
    }
    for path in [
        "C:\\private\\canary.manifest".to_owned(),
        controls.replace("Manifests\\", "Manifests-sibling\\"),
        controls.replace("Manifests\\", "WinSxS\\..\\Manifests\\"),
        controls.replace("fixed", "fíxed"),
        format!("{controls}:stream"),
        controls.replace(".manifest", ".dll"),
        "relative.manifest".to_owned(),
    ] {
        assert!(qualify_path(&path, root, windows, 2).is_err());
    }
    assert!(qualify_path(root, root, windows, 2).is_err());
    assert!(qualify_path(controls, root, windows, 1).is_err());
}
