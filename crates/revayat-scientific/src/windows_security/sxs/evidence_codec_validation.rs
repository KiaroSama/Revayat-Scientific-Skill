use super::{
    evidence as core,
    fixture::{self, need, private, stage},
    stream,
};
use anyhow::Result;
pub(super) fn check_codec_validation() -> Result<()> {
    let manifest = "F:\\private-codec-sentinel\\_ctypes.pyd";
    let block = fixture::block(manifest, "ERROR: Activation Context generation failed.");
    let expected = super::failure_evidence(&fixture::utf16(&block), manifest)?;
    for value in [
        block.clone(),
        format!("{block}\n"),
        block.replace("ERROR:", "INFO: Ω\nERROR:"),
    ] {
        let bytes = fixture::utf8(&value);
        need(
            super::failure_evidence(&bytes, manifest)? == expected
                && super::failure_evidence(&fixture::utf16(&value), manifest)? == expected,
        )?;
        let mut source = stream::Stream::new(bytes);
        source.mode = 7;
        need(
            stream::read(&mut source, manifest)? == expected
                && source.lengths == 3
                && source.reads == 1
                && source.closes == 1
                && source.cleared,
        )?;
    }
    need(fixture::utf8(&block).len() % 2 != fixture::utf8(&(block.clone() + "\n")).len() % 2)?;
    for body in [
        vec![194],
        vec![128],
        vec![192, 175],
        vec![237, 160, 128],
        vec![244, 144, 128, 128],
        vec![226, 130],
    ] {
        let bytes = [vec![239, 187, 191], body].concat();
        let caught =
            super::failure_evidence(&bytes, manifest).expect_err("malformed UTF8 must fail");
        need(
            stage(&caught)? == "evidence-utf8"
                && private(&caught)?.original().is::<std::str::Utf8Error>(),
        )?;
        fixture::withheld(&caught)?;
        let mut source = stream::Stream::new(bytes);
        source.mode = 7;
        let read_failure =
            stream::read(&mut source, manifest).expect_err("malformed UTF8 stream must fail");
        need(stage(&read_failure)? == stage(&caught)? && source.closes == 1 && source.cleared)?;
    }
    for bytes in [
        vec![239, 187, 191],
        vec![255, 254],
        vec![255, 254, 0],
        vec![254, 255, 0, 65],
        vec![255, 254, 0, 0],
        vec![0, 0, 254, 255],
        block.as_bytes().to_vec(),
        fixture::utf8(&(block.clone() + &block)),
        fixture::utf8(&block.replace(manifest, "private-wrong-manifest")),
        fixture::utf8(&block.replace("ERROR:", "ERROR: private-unknown")),
        fixture::utf8("\0"),
        fixture::utf8(&"x".repeat(2049)),
        fixture::utf8(&"\n".repeat(4096)),
        fixture::utf8("\r"),
        vec![0; 1_048_577],
    ] {
        let caught = super::failure_evidence(&bytes, manifest)
            .expect_err("invalid codec/evidence must fail");
        fixture::withheld(&caught)?;
        if bytes == [255, 254, 0] {
            need(
                stage(&caught)?
                    == "evidence-length-utf16-shape comparison=even observed_bytes=3 maximum_bytes=1048576 even=False evidence-prefix status=array signature=utf16le-prefix transferred_bytes=3",
            )?;
        }
    }
    need(
        core::allocation_length(2)? == 2
            && core::allocation_length(core::TEXT_MAXIMUM)? == core::TEXT_MAXIMUM as usize,
    )?;
    let mut bytes = vec![32; core::TEXT_MAXIMUM as usize];
    bytes[..3].copy_from_slice(&[239, 187, 191]);
    let caught =
        super::failure_evidence(&bytes, manifest).expect_err("maximal wide line must fail");
    need(stage(&caught)?.contains("evidence-line-width"))?;
    Ok(())
}
