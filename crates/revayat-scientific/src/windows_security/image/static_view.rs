//! Literal-byte qualified static disassembly and bounded redacted presentation.
use super::*;
impl PeImage<'_> {
    pub fn qualify_static(&self, text: &str, slice: StaticSlice) -> Result<StaticView> {
        ensure!(
            self.static_slice(slice.rva)? == slice && text.len() <= 1048576,
            "static input or slice differs"
        );
        let instruction = regex::Regex::new(
            r"^[ \t]*([0-9A-Fa-f]{16}):[ \t]+((?:[0-9A-Fa-f]{2} )*[0-9A-Fa-f]{2})[ \t]{2,}([a-z][a-z0-9]{0,15})(?:[ \t]+(.*))?$",
        )?;
        let continuation = regex::Regex::new(r"^(?:[0-9A-Fa-f]{2}[ \t]+)*[0-9A-Fa-f]{2}$")?;
        let mnemonic = regex::Regex::new(
            r"^(?:mov|movzx|movsx|movsxd|lea|push|pop|add|sub|adc|sbb|inc|dec|and|or|xor|test|cmp|neg|not|shl|shr|sar|sal|rol|ror|imul|mul|div|idiv|xchg|call|ret|jmp|j(?:e|ne|z|nz|a|ae|b|be|g|ge|l|le|s|ns|o|no|p|np|rcxz)|nop|int3|endbr64|leave|cdqe|cqo|cmov(?:e|ne|a|ae|b|be|g|ge|l|le|s|ns)|set(?:e|ne|a|ae|b|be|g|ge|l|le|s|ns))$",
        )?;
        let register = regex::Regex::new(
            r"^(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r(?:8|9|1[0-5])|eax|ebx|ecx|edx|esi|edi|ebp|esp|r(?:8|9|1[0-5])d|ax|bx|cx|dx|al|bl|cl|dl)(?:,(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r(?:8|9|1[0-5])|eax|ebx|ecx|edx|esi|edi|ebp|esp|r(?:8|9|1[0-5])d|ax|bx|cx|dx|al|bl|cl|dl|[01]h?))?$",
        )?;
        let summary = regex::Regex::new(r"^[0-9A-Fa-f]{1,8} \.[A-Za-z0-9_$]{1,16}$")?;
        let mut result = StaticView {
            text: String::new(),
            records: 0,
            unsupported: 0,
        };
        let mut pending = None;
        let mut previous = slice.start;
        for (line_index, line) in text.lines().enumerate() {
            ensure!(
                line_index < 4096 && line.len() <= 1024,
                "static line budget exceeded"
            );
            let trimmed = line.trim();
            if line
                .bytes()
                .any(|byte| !(32..=126).contains(&byte) && byte != b'\t')
                || continuation.is_match(trimmed)
            {
                pending = None;
                result.unsupported += 1;
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("Dump of file ")
                || matches!(trimmed, "File Type: DLL" | "Summary")
                || summary.is_match(trimmed)
            {
                append_record(&mut result, pending.take())?;
                continue;
            }
            let Some(capture) = instruction.captures(line) else {
                pending = None;
                result.unsupported += 1;
                continue;
            };
            append_record(&mut result, pending.take())?;
            let address = u64::from_str_radix(&capture[1], 16)?;
            let opcode = capture[2]
                .split(' ')
                .map(|byte| u8::from_str_radix(byte, 16))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure!(
                (1..=15).contains(&opcode.len())
                    && address >= previous
                    && address >= slice.start
                    && address < slice.start + u64::from(slice.length),
                "static opcode order/window differs"
            );
            previous = address + opcode.len() as u64;
            if opcode.len() as u64 > slice.start + u64::from(slice.length) - address
                || !mnemonic.is_match(&capture[3])
            {
                result.unsupported += 1;
                continue;
            }
            let raw = slice.raw + (address - slice.start) as usize;
            ensure!(
                span(self.bytes, raw, opcode.len())? == opcode,
                "static opcode differs from image"
            );
            let operands = capture.get(4).map_or("", |value| value.as_str());
            let mut safe = if operands.is_empty() {
                "none".to_owned()
            } else {
                "withheld".to_owned()
            };
            if operands.len() == 16 && operands.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                let value = u64::from_str_radix(operands, 16)?;
                let preferred = slice.start - u64::from(slice.rva);
                if value >= preferred && value - preferred < u64::from(self.image_size) {
                    safe = format!("rva:0x{:08X}", value - preferred);
                }
            }
            if safe == "withheld" && register.is_match(operands) {
                safe = operands.to_owned();
            }
            if safe == "withheld" {
                result.unsupported += 1;
            }
            let hex = opcode
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            pending = Some(format!(
                "rva=0x{:08X} bytes={hex} mnemonic={} operands={safe}\n",
                u64::from(slice.rva) + address - slice.start,
                &capture[3]
            ));
        }
        append_record(&mut result, pending)?;
        ensure!(
            result.records != 0,
            "static output has no qualified records"
        );
        Ok(result)
    }
}
fn append_record(view: &mut StaticView, record: Option<String>) -> Result<()> {
    if let Some(record) = record {
        view.text.push_str(&record);
        view.records += 1;
        ensure!(
            view.text.len() <= 65024 && view.records <= 4096,
            "static output budget exceeded"
        );
    }
    Ok(())
}
