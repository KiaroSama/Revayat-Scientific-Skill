//! One fixed Win32 .res record. This is not a general resource compiler.
pub const MANIFEST: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity type=\"win32\" version=\"1.0.0.0\" processorArchitecture=\"amd64\" name=\"Scientific.Security.ExplicitId2\"/></assembly>\n";
fn header(output: &mut Vec<u8>, length: u32, kind: u16, name: u16, flags: u16, language: u16) {
    output.extend(length.to_le_bytes());
    output.extend(32u32.to_le_bytes());
    for value in [0xffff, kind, 0xffff, name] {
        output.extend(value.to_le_bytes());
    }
    output.extend(0u32.to_le_bytes());
    output.extend(flags.to_le_bytes());
    output.extend(language.to_le_bytes());
    output.extend([0; 8]);
}
pub fn encode() -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + MANIFEST.len() + 3);
    header(&mut output, 0, 0, 0, 0, 0);
    header(&mut output, MANIFEST.len() as u32, 24, 2, 0x1030, 1033);
    output.extend(MANIFEST);
    output.resize(output.len().next_multiple_of(4), 0);
    output
}
