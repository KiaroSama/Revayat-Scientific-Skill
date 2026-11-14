//! Portable format/ABI/receipt assertions, never an actual activation operation.
use super::*;
#[path = "../../native-fixtures/independent_id2.rs"]
mod independent_id2;
#[test]
fn explicit_id2_context_keeps_only_module_resource_flags_and_exact_x64_layout() {
    use std::mem::{offset_of, size_of};
    if size_of::<usize>() != 8 {
        return;
    }
    assert_eq!(size_of::<ActCtx>(), 56);
    assert_eq!(
        [
            offset_of!(ActCtx, size),
            offset_of!(ActCtx, flags),
            offset_of!(ActCtx, source),
            offset_of!(ActCtx, architecture),
            offset_of!(ActCtx, language),
            offset_of!(ActCtx, directory),
            offset_of!(ActCtx, resource),
            offset_of!(ActCtx, application),
            offset_of!(ActCtx, module)
        ],
        [0, 4, 8, 16, 18, 24, 32, 40, 48]
    );
    let context = ActCtx::explicit_id2(17).unwrap();
    assert_eq!(
        (
            context.size,
            context.flags,
            context.source,
            context.resource,
            context.module
        ),
        (56, 0x88, 0, 2, 17)
    );
    assert_eq!(
        (
            context.architecture,
            context.language,
            context.directory,
            context.application
        ),
        (0, 0, 0, 0)
    );
    for module in [0, usize::MAX] {
        assert!(ActCtx::explicit_id2(module).is_none());
    }
}
#[test]
fn resource_file_contains_one_null_header_and_one_exact_manifest_id2_language1033() {
    let bytes = resource::encode();
    assert_eq!(
        &bytes[..32],
        &[
            0, 0, 0, 0, 32, 0, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(
        u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize,
        MANIFEST.len()
    );
    assert_eq!(
        &bytes[36..48],
        &[32, 0, 0, 0, 255, 255, 24, 0, 255, 255, 2, 0]
    );
    assert_eq!(&bytes[52..56], &[0x30, 0x10, 9, 4]);
    assert_eq!(&bytes[64..64 + MANIFEST.len()], MANIFEST);
    assert_eq!(bytes.len() % 4, 0);
    assert!(bytes[64 + MANIFEST.len()..].iter().all(|byte| *byte == 0));
    assert!(
        std::str::from_utf8(MANIFEST)
            .unwrap()
            .contains("Scientific.Security.ExplicitId2")
    );
}
#[test]
fn explicit_receipt_preserves_pre_call_then_consistent_fixed_result_without_raw_data() {
    assert_eq!(PRE_CALL, b"EXPLICIT_ID2_BEFORE_CALL\n");
    assert_eq!(
        result(true, 0).unwrap(),
        "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=True win32_error=0x00000000\n"
    );
    assert_eq!(
        result(false, 5).unwrap(),
        "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created=False win32_error=0x00000005\n"
    );
    assert!(result(true, 5).is_none() && result(false, 0).is_none());
    assert!(PRE_CALL.len() + result(false, u32::MAX).unwrap().len() <= 128);
    for error in (0..=255u32).chain([0x01020304, 0x01234567, 0x89abcdef, 0xdeadbeef, u32::MAX]) {
        let mut hexadecimal = Vec::new();
        independent_id2::hexadecimal(error, |byte| hexadecimal.push(byte));
        assert_eq!(
            hexadecimal.len(),
            8,
            "native error field must have exactly eight bytes"
        );
        assert_eq!(hexadecimal, format!("{error:08X}").as_bytes());
        let hexadecimal = String::from_utf8(hexadecimal).unwrap();
        let created = error == 0;
        assert_eq!(
            format!(
                "WINDOWS_EXPLICIT_ID2_ACTIVATION entry_reached=True created={} win32_error=0x{hexadecimal}\n",
                if created { "True" } else { "False" }
            ),
            result(created, error).unwrap(),
        );
    }
    for command in [
        "\"D:\\owned work\\control.exe\"\0",
        "\"D:\\control.exe\" \t\0",
    ] {
        let units = command.encode_utf16().collect::<Vec<_>>();
        assert!(independent_id2::no_arguments(|index| units
            .get(index)
            .copied()));
    }
    for command in [
        "",
        "\0",
        "D:\\control.exe\0",
        "\"\"\0",
        "\"D:\\control.exe\0",
        "\"D:\\control.exe\"",
        "\"D:\\control.exe\" --oracle\0",
        "\"D:\\control.exe\" x\0",
        "\"D:\\control.exe\"\"\0",
        "\"D:\\control.exe\"x\0",
    ] {
        let units = command.encode_utf16().collect::<Vec<_>>();
        assert!(!independent_id2::no_arguments(|index| units
            .get(index)
            .copied()));
    }
    let mut calls = 0;
    assert!(!independent_id2::no_arguments(|index| {
        calls += 1;
        Some(if index == 0 {
            u16::from(b'"')
        } else {
            u16::from(b'x')
        })
    }));
    assert_eq!(calls, 32767);
}
#[test]
fn fixture_captures_error_immediately_and_build_links_only_the_fixed_binary_resource() {
    let source = include_str!("main.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<String>()
        .split_whitespace()
        .collect::<String>();
    let (_, after) = source
        .split_once("lethandle=unsafe{CreateActCtxW(&context)};")
        .unwrap();
    assert!(
        after.starts_with("leterror=ifhandleasusize==usize::MAX{unsafe{GetLastError()}}else{0};")
    );
    let build = include_str!("../build.rs");
    assert!(build.contains("cargo::rustc-link-arg-bin=startup-explicit-id2=/MANIFEST:NO"));
    assert!(build.contains("cargo::rustc-link-arg-bin=startup-explicit-id2=/ALLOWISOLATION:NO"));
    assert!(!build.contains("Command::") && !build.contains("cargo::rustc-link-arg="));
    let independent = include_str!("../../native-fixtures/independent_id2.rs");
    assert!(independent.contains("#![cfg_attr(not(test), no_std)]"));
    assert!(independent.contains("#![cfg_attr(not(test), no_main)]"));
    assert!(!independent.contains("std::"));
    assert!(!independent.contains("emit::Record") && !independent.contains("mod builtins"));
    let independent = independent.split_whitespace().collect::<String>();
    let (_, after) = independent
        .split_once("lethandle=unsafe{abi::CreateActCtxW(&context)};")
        .unwrap();
    assert!(
        after.starts_with(
            "leterror=ifhandleasusize==usize::MAX{unsafe{abi::GetLastError()}}else{0};"
        )
    );
}
