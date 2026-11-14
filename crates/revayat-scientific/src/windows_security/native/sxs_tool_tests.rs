//! Fixed-tool input and raw capture bounds. No native execution in these fixtures.
use super::*;
#[test]
fn standard_tool_arguments_are_closed_and_never_use_a_shell_or_provider_override() {
    let root = Path::new(r"D:\sxs-trace-0123456789abcdef0123456789abcdef");
    assert_eq!(
        arguments(root, false).unwrap(),
        [
            "trace",
            "-logfile:D:\\sxs-trace-0123456789abcdef0123456789abcdef\\capture.etl",
            "-nostop"
        ]
    );
    assert_eq!(
        arguments(root, true).unwrap(),
        [
            "parse",
            "-logfile:D:\\sxs-trace-0123456789abcdef0123456789abcdef\\capture.etl",
            "-outfile:D:\\sxs-trace-0123456789abcdef0123456789abcdef\\capture.txt"
        ]
    );
    for bad in [
        r"D:\other",
        r"C:\sxs-trace-0123456789abcdef0123456789abcdef",
        r"D:\sxs-trace-0123456789abcdef0123456789abcdef\extra",
    ] {
        assert!(arguments(Path::new(bad), false).is_err());
    }
}
#[test]
fn raw_tool_output_counts_bytes_without_requiring_ascii_or_exposing_payload() {
    let mut output = Discard::default();
    output.accept(&[0xff, 0, 0xc3, 0xa9]).unwrap();
    assert_eq!(output.bytes, 4);
    output.bytes = 1_048_576;
    assert!(output.accept(&[0]).is_err());
    assert_eq!(output.bytes, 1_048_576);
    output.eof = true;
    assert!(output.accept(&[]).is_err());
}
