//! Callable frozen KernelImageActivationBoundary assertions; synthetic bytes are never admitted by hash.
use super::*;
use csr::put;

pub(super) fn fixture() -> Vec<u8> {
    let original = super::super::validation::activation_worker_validation_fixture();
    let mut bytes = vec![0; 0x5a00];
    bytes[..2048].copy_from_slice(&original[..2048]);
    for (at, value) in [
        (0x194, 0x22000),
        (0x190, 0x5800),
        (0x198, 0x5800),
        (0xa8, 0x22000),
        (0xd0, 0x28000),
    ] {
        put(&mut bytes, at, value);
    }
    for (&rva, encoding) in PROFILES[0].code.iter().zip(PROFILES[0].bytes) {
        let literal = decode(encoding).unwrap();
        let at = csr::raw(rva);
        bytes[at..at + literal.len()].copy_from_slice(&literal);
    }
    bytes
}
pub fn check_activation_boundary_validation() -> Result<()> {
    let bytes = fixture();
    let check = |b: &[u8]| activation_boundary_bytes(&PeImage::parse(b, 1)?, &PROFILES[0]);
    check(&bytes)?;
    ensure!(
        PROFILES[0].worker != PROFILES[0].code[13],
        "worker and funnel coincide"
    );
    // Exact literal byte mutations in KernelImageActivationBoundary.cs:36–76.
    for at in [
        0x2f20, 0x3c16, 0x3c19, 0x3c1a, 0x3c1d, 0x3c21, 0x3c27, 0x3a61, 0x3a64, 0x3a68, 0x3a6d,
        0x3a71, 0x3a76, 0x3ac4, 0x3ac5, 0x3ac9, 0x3acb, 0x3acf, 0x443a, 0x4457, 0x445a, 0x445e,
        0x4463, 0x4465, 0x4469, 0x54a6, 0x54a9, 0x54ad, 0x54b2, 0x54b6, 0x54bc, 0x54bd, 0x54c0,
        0x4b91, 0x4ba7, 0x4baa, 0x4bae, 0x4bb3, 0x4bb5, 0x4bb7, 0x4bbb, 0x4d3a, 0x4d3b, 0x4d65,
        0x4d6a, 0x4d6e, 0x4d70, 0x4d72, 0x4d76, 0x4dac, 0x4daf, 0x4db3, 0x4db8, 0x4dba, 0x4dbc,
        0x4dbf, 0x5987, 0x599c, 0x599f, 0x59a3, 0x59a8, 0x59aa, 0x59ae, 0x2dad, 0x2db9, 0x2de1,
        0x2dcf, 0x2dbd,
    ] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        ensure!(
            check(&bad).is_err(),
            "activation boundary mutation admitted at {at:x}"
        );
    }
    for length in [
        0x4264, 0x52b4, 0x49b4, 0x4b73, 0x4bb9, 0x57a9, 0x386f, 0x38ca, 0x3cec, 0x3a1b, 0x1be2,
    ] {
        for at in [0x190, 0x198] {
            let mut bad = bytes.clone();
            put(&mut bad, at, length);
            ensure!(check(&bad).is_err(), "partial boundary span admitted");
        }
    }
    let mut bad = bytes.clone();
    put(&mut bad, 0x1ac, 0x40000040);
    ensure!(check(&bad).is_err(), "non-executable boundary admitted");
    let identity = "phase=image-identity module=kernel32.dll sha256=347f1ac1b7dbec710cf06fb3f67d131bceebbc19076bc77daacd31cfe452b496 pe_timestamp=4227614027 image_size=823296 file_size=836208";
    select(identity)?;
    ensure!(
        select_nullable(None).is_err(),
        "null boundary identity admitted"
    );
    for bad in [
        String::new(),
        format!("{identity} "),
        identity.replace("347f", "047f"),
        identity.replace("836208", "836207"),
        identity.replace("4227614027", "4227614026"),
    ] {
        ensure!(select(&bad).is_err(), "boundary identity mutation admitted");
    }
    ensure!(
        PeImage::parse(&bytes, 1)?
            .require_activation_boundary_profile()
            .is_err(),
        "synthetic full hash admitted"
    );
    Ok(())
}
