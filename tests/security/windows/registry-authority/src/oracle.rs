//! Independent migration oracle, expressed in Rust and executable on every host.
//!
//! Expected outcomes are enumerated independently of protocol predicates. This
//! fixture retains all 41 source-oracle cases from the original implementation.
use std::fmt::Write;

fn hex(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String write");
    }
    output
}

pub fn generate() -> String {
    let mut rows = String::new();
    for kind in 0..=2 {
        for elevated in 0..=1 {
            for restricted in 0..=1 {
                let passed = (kind, elevated, restricted) == (1, 0, 1);
                writeln!(
                    &mut rows,
                    "token\t{kind}\t{elevated}\t{restricted}\t{}",
                    u8::from(passed)
                )
                .expect("String write");
            }
        }
    }
    for status in [0u32, 1, 0xc0000022, u32::MAX] {
        for handle in [0, 4] {
            writeln!(
                &mut rows,
                "denied\t{status}\t{handle}\t{}",
                u8::from((status, handle) == (0xc0000022, 0))
            )
            .expect("String write");
        }
    }
    for (status, returned, attributes, access, passed) in [
        (0, 56, 0, 0x20019, 1),
        (1, 56, 0, 0x20019, 0),
        (0, 55, 0, 0x20019, 0),
        (0, 57, 0, 0x20019, 0),
        (0, 56, 1, 0x20019, 0),
        (0, 56, 0, 0x2001b, 0),
    ] {
        writeln!(
            &mut rows,
            "basic\t{status}\t{returned}\t{attributes}\t{access}\t{passed}"
        )
        .expect("String write");
    }
    // Includes the UTF-16 surrogate pair, embedded NUL, lone surrogate,
    // truncated headers, oversized return length, odd count, and short body.
    for (units, passed) in [
        (&[0x0041u16][..], 1),
        (&[82, 101, 103, 105, 115, 116, 114, 121][..], 1),
        (&[0xd83d, 0xde42][..], 1),
        (&[0][..], 0),
        (&[0xd800][..], 0),
    ] {
        let count = units.len() * 2;
        let mut data = (count as u32).to_le_bytes().to_vec();
        for unit in units {
            data.extend(unit.to_le_bytes());
        }
        writeln!(
            &mut rows,
            "identity\t0\t{}\t{}\t{count}\t{passed}",
            data.len(),
            hex(&data)
        )
        .expect("String write");
    }
    for (returned, data, count) in [
        (3, &[0u8, 0, 0, 0][..], 0),
        (4097, &[0, 0, 0, 0][..], 0),
        (6, &[4, 0, 0, 0, 65, 0][..], 4),
        (5, &[1, 0, 0, 0, 65][..], 1),
    ] {
        writeln!(
            &mut rows,
            "identity\t0\t{returned}\t{}\t{count}\t0",
            hex(data)
        )
        .expect("String write");
    }
    for role in ["primary", "descendant"] {
        for (subkeys, accessible) in [(0, 0), (2, 1), (256, 256)] {
            // Deliberately independent schema literal: do not call protocol::record.
            let wire = format!(
                "{{\"accessible\":{accessible},\"capabilities\":0,\"granted_access\":131097,\"lpac\":true,\"mutation_denied\":true,\"no_reparse\":true,\"read\":true,\"read_surface_approved\":false,\"restricted\":true,\"role\":\"{role}\",\"subkeys\":{subkeys},\"version\":1,\"x64\":true}}\n"
            );
            writeln!(
                &mut rows,
                "wire\t{role}\t{subkeys}\t{accessible}\t{}",
                hex(wire.as_bytes())
            )
            .expect("String write");
        }
    }
    rows
}
