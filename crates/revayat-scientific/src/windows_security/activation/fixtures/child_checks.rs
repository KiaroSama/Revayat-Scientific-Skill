//! ChildActivationFixture.CheckValidation: immutable 4e24f3d lines202–288.
use super::*;
use std::fs;
pub fn check_child_validation(work: &Path) -> Result<()> {
    require_role(true, &[false; 4])?;
    for (preflight, others) in [
        (false, [false; 4]),
        (true, [true, false, false, false]),
        (true, [false, true, false, false]),
        (true, [false, false, true, false]),
        (true, [false, false, false, true]),
    ] {
        ensure!(
            require_role(preflight, &others).is_err(),
            "activation role overlap accepted"
        );
    }
    let abc = b"abc";
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    require_prepared(abc, 3, hash)?;
    ensure!(
        require_prepared(abc, 4, hash).is_err() && require_prepared(b"abd", 3, hash).is_err(),
        "activation identity drift accepted"
    );
    ensure!(
        numeric(&"A\"\\ی".encode_utf16().collect::<Vec<_>>())? == "65,34,92,1740,0",
        "activation numeric UTF16 differs"
    );
    for invalid in [vec![], vec![97, 0, 98], vec![0xd800], vec![97; 1025]] {
        ensure!(
            numeric(&invalid).is_err(),
            "activation malformed build input accepted"
        );
    }
    for value in [SUCCESS, DENIED] {
        ensure!(
            require_transport(0, Some(value), Some(""))? == value.trim_end_matches('\n'),
            "child activation literal result differs"
        );
        ensure!(
            compare_trace_result(Some(value), Some(value))?
                == "WINDOWS_ACTIVATION_COMPARISON returned_result_equal=True debug_equivalence_claimed=False cause_claimed=False",
            "activation comparison noncausal contract differs"
        );
    }
    for (first, second) in [(DENIED, SUCCESS), (SUCCESS, DENIED)] {
        ensure!(
            compare_trace_result(Some(first), Some(second))
                .unwrap_err()
                .to_string()
                == "fixed activation returned results differ",
            "activation result mismatch accepted or changed category"
        );
    }
    for (exit, text, errors) in [
        (0, SUCCESS, "\n"),
        (0, SUCCESS, " "),
        (1, SUCCESS, ""),
        (1, "private-sentinel", "private-sentinel"),
        (0, "private-sentinel", ""),
        (0, SUCCESS, "private-sentinel"),
    ] {
        let error = require_transport(exit, Some(text), Some(errors)).unwrap_err();
        ensure!(
            !error.to_string().contains("private-sentinel"),
            "activation transport leaked capture"
        );
    }
    for invalid in [
        String::new(),
        format!("{SUCCESS}{DENIED}"),
        SUCCESS.trim_end_matches('\n').into(),
        SUCCESS.replace("00000000", "00000005"),
        DENIED.replace("00000005", "00000000"),
        DENIED.replace("False", "false"),
        format!("{DENIED}private-sentinel"),
        "a".repeat(257),
    ] {
        let error = require_result(Some(&invalid)).unwrap_err();
        ensure!(
            !error.to_string().contains("private-sentinel"),
            "activation result refusal leaked payload"
        );
    }
    let fixture = tempfile::Builder::new()
        .prefix("activation-collision-")
        .tempdir_in(work)?;
    let sentinel = fixture.path().join("owned.txt");
    io::create(&sentinel, b"unchanged", 65536)?.close()?;
    ensure!(
        io::create(&sentinel, b"replacement", 65536).is_err()
            && fs::read(&sentinel)? == b"unchanged",
        "activation collision did not preserve sentinel"
    );
    let link = fixture.path().join("dangling");
    super::super::source::directory_link(&fixture.path().join("absent-owned"), &link)?;
    ensure!(
        io::missing(&link).is_err() && crate::identity::is_link(&link)?,
        "dangling activation collision was not preserved"
    );
    super::super::source::remove_directory_link(&link)?;
    crate::windows_security::image::check_child_activation_validation()
}
