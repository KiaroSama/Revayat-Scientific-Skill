//! Bounded serializer output identities computed from the bytes actually emitted.
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
};

struct Emission<W> {
    target: W,
    count: u64,
    maximum: u64,
    digest: Sha256,
}
impl<W: Write> Write for Emission<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.maximum - self.count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized PDF exceeds byte limit",
            ));
        }
        let count = self.target.write(bytes)?;
        self.digest.update(&bytes[..count]);
        self.count += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.target.flush()
    }
}

pub(super) fn save_document(
    doc: &mut lopdf::Document,
    destination: &Path,
    maximum: u64,
) -> Result<(u64, String)> {
    let mut output = Emission {
        target: BufWriter::new(File::create(destination)?),
        count: 0,
        maximum,
        digest: Sha256::new(),
    };
    doc.save_to(&mut output)?;
    output.flush()?;
    output.target.get_ref().sync_all()?;
    Ok((output.count, format!("{:x}", output.digest.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ShortWrites(Vec<u8>);
    impl Write for ShortWrites {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(3);
            self.0.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn emitted_digest_counts_partial_writes_and_enforces_the_exact_limit() {
        let mut output = Emission {
            target: ShortWrites(Vec::new()),
            count: 0,
            maximum: 7,
            digest: Sha256::new(),
        };
        output.write_all(b"PDFdata").unwrap();
        assert_eq!(output.count, 7);
        assert_eq!(output.target.0, b"PDFdata");
        assert_eq!(
            output.write_all(b"x").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(output.target.0, b"PDFdata");
        assert_eq!(
            format!("{:x}", output.digest.finalize()),
            crate::resource::sha256(b"PDFdata")
        );
    }
}
