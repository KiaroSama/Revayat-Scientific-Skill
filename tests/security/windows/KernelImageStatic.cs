using System;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        internal struct StaticSlice { internal ulong Start; internal uint Length; internal int Raw; }
        internal sealed class StaticView
        {
            internal readonly string Text;
            internal readonly int Records, Unsupported;
            internal StaticView(string text, int records, int unsupported) { Text = text; Records = records; Unsupported = unsupported; }
        }
        internal static KernelImage FromStatic(byte[] bytes) { return new KernelImage(bytes, 1, "kernelbase.dll"); }
        internal StaticSlice EntrySlice()
        {
            Need(Name == "kernelbase.dll" && Entry != 0);
            ulong optional = (ulong)U32(0x3C) + 24; Range(optional + 24, 8);
            ulong preferred = BitConverter.ToUInt64(data, (int)optional + 24);
            Need(preferred != 0 && preferred <= 0x7FFFFFFFFFFFFFFFUL - imageSize && U32(optional + 112 + 14 * 8) == 0 && U32(optional + 116 + 14 * 8) == 0);
            int matches = 0; uint length = 0;
            foreach (var section in sections) {
                ulong span = Math.Min(section.size, section.rawSize);
                if ((section.flags & 0x20000000) == 0 || Entry < section.rva || (ulong)Entry >= (ulong)section.rva + span) continue;
                Need(section.raw >= headers); matches++;
                length = (uint)Math.Min(4096UL, Math.Min((ulong)section.rva + span - Entry, (ulong)imageSize - Entry));
            }
            Need(matches == 1 && length != 0);
            return new StaticSlice { Start = preferred + Entry, Length = length, Raw = Map(Entry, length) };
        }
        internal StaticView QualifyStatic(string text)
        {
            Need(text != null && text.Length <= 1048576);
            var slice = EntrySlice(); var output = new StringBuilder(); int records = 0, unsupported = 0, lines = 0;
            ulong previousEnd = slice.Start;
            using (var reader = new System.IO.StringReader(text)) {
                string line;
                while ((line = reader.ReadLine()) != null) {
                    Need(++lines <= 4096 && line.Length <= 1024);
                    bool ascii = true; foreach (char c in line) if ((c < 32 && c != '\t') || c > 126) ascii = false;
                    if (!ascii) { unsupported++; continue; }
                    string trimmed = line.Trim();
                    Need(!Regex.IsMatch(trimmed, @"^(?:[0-9A-Fa-f]{2}[ \t]+)*[0-9A-Fa-f]{2}$", RegexOptions.CultureInvariant)); // Unframed continuation cannot qualify its preceding instruction.
                    if (trimmed.Length == 0 || trimmed.StartsWith("Dump of file ", StringComparison.Ordinal) ||
                        trimmed == "File Type: DLL" || trimmed == "Summary" ||
                        Regex.IsMatch(trimmed, @"^[0-9A-Fa-f]{1,8} \.[A-Za-z0-9_$]{1,16}$", RegexOptions.CultureInvariant)) continue;
                    Match instruction = Regex.Match(line, @"^[ \t]*([0-9A-Fa-f]{16}):[ \t]+((?:[0-9A-Fa-f]{2} )*[0-9A-Fa-f]{2})[ \t]{2,}([a-z][a-z0-9]{0,15})(?:[ \t]+(.*))?$", RegexOptions.CultureInvariant);
                    if (!instruction.Success || !Regex.IsMatch(instruction.Groups[3].Value,
                        @"^(?:mov|movzx|movsx|movsxd|lea|push|pop|add|sub|adc|sbb|inc|dec|and|or|xor|test|cmp|neg|not|shl|shr|sar|sal|rol|ror|imul|mul|div|idiv|xchg|call|ret|jmp|j(?:e|ne|z|nz|a|ae|b|be|g|ge|l|le|s|ns|o|no|p|np|rcxz)|nop|int3|endbr64|leave|cdqe|cqo|cmov(?:e|ne|a|ae|b|be|g|ge|l|le|s|ns)|set(?:e|ne|a|ae|b|be|g|ge|l|le|s|ns))$",
                        RegexOptions.CultureInvariant)) { unsupported++; continue; }
                    ulong address = UInt64.Parse(instruction.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                    string[] bytes = instruction.Groups[2].Value.Split(' ');
                    Need(bytes.Length >= 1 && bytes.Length <= 15 && address >= previousEnd && address >= slice.Start && address < slice.Start + slice.Length);
                    if ((ulong)bytes.Length > slice.Start + slice.Length - address) { unsupported++; continue; }
                    var hex = new StringBuilder();
                    for (int index = 0; index < bytes.Length; index++) {
                        byte value = Byte.Parse(bytes[index], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                        Need(value == data[slice.Raw + (int)(address - slice.Start) + index]); hex.Append(value.ToString("X2", CultureInfo.InvariantCulture));
                    }
                    string operands = instruction.Groups[4].Value, safe = operands.Length == 0 ? "none" : "withheld";
                    ulong operand;
                    if (Regex.IsMatch(operands, @"^[0-9A-Fa-f]{16}$", RegexOptions.CultureInvariant) &&
                        UInt64.TryParse(operands, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out operand)) {
                        ulong preferred = slice.Start - Entry;
                        if (operand >= preferred && operand - preferred < imageSize) safe = "rva:0x" + (operand - preferred).ToString("X8", CultureInfo.InvariantCulture);
                    }
                    if (safe == "withheld" && Regex.IsMatch(operands,
                        @"^(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r(?:8|9|1[0-5])|eax|ebx|ecx|edx|esi|edi|ebp|esp|r(?:8|9|1[0-5])d|ax|bx|cx|dx|al|bl|cl|dl)(?:,(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r(?:8|9|1[0-5])|eax|ebx|ecx|edx|esi|edi|ebp|esp|r(?:8|9|1[0-5])d|ax|bx|cx|dx|al|bl|cl|dl|[01]h?))?$",
                        RegexOptions.CultureInvariant)) safe = operands;
                    if (safe == "withheld") unsupported++;
                    output.Append("rva=0x").Append((Entry + address - slice.Start).ToString("X8", CultureInfo.InvariantCulture))
                        .Append(" bytes=").Append(hex).Append(" mnemonic=").Append(instruction.Groups[3].Value)
                        .Append(" operands=").Append(safe).Append('\n');
                    Need(output.Length <= 65024 && ++records <= 4096); previousEnd = address + (ulong)bytes.Length;
                }
            }
            Need(records != 0); return new StaticView(output.ToString(), records, unsupported);
        }
        static void CheckStaticValidation()
        {
            byte[] bytes = StaticFixture(); var image = FromStatic(bytes);
            var slice = image.EntrySlice();
            Need(slice.Start == 0x180001000UL && slice.Length == 1536 && slice.Raw == 512);
            var view = image.QualifyStatic("Dump of file C:\\private\\KernelBase.dll\r\nFile Type: DLL\r\n\r\n" +
                "  0000000180001000: B8 00 00 00 00     mov eax,0\r\n" +
                "  0000000180001005: C3                 ret\r\n");
            Need(view.Records == 2 && view.Unsupported == 0 && view.Text ==
                "rva=0x00001000 bytes=B800000000 mnemonic=mov operands=eax,0\n" +
                "rva=0x00001005 bytes=C3 mnemonic=ret operands=none\n");
            Need(!view.Text.Contains("private") && !view.Text.Contains("18000") && !view.Text.Contains("\\"));
            var partial = image.QualifyStatic("  0000000180001000: B8 00 00 00 00     mov eax,0\nunknown label:\n");
            Need(partial.Records == 1 && partial.Unsupported == 1);
            var branch = image.QualifyStatic("  0000000180001006: E8 F5 FF FF FF     call 0000000180001000\n");
            Need(branch.Unsupported == 0 && branch.Text == "rva=0x00001006 bytes=E8F5FFFFFF mnemonic=call operands=rva:0x00001000\n");
            var clipped = image.QualifyStatic("  0000000180001005: C3     ret\n  00000001800015FF: 00 00     mov al,al\n");
            Need(clipped.Records == 1 && clipped.Unsupported == 1 && clipped.Text == "rva=0x00001005 bytes=C3 mnemonic=ret operands=none\n");
            var privateOperand = image.QualifyStatic("  0000000180001005: C3     ret C:\\private\\secret.dll\n");
            Need(privateOperand.Unsupported == 1 && privateOperand.Text == "rva=0x00001005 bytes=C3 mnemonic=ret operands=withheld\n");
            var unsafeText = image.QualifyStatic("  0000000180001005: C3     ret\n" + (char)0x202E + "private\n  0000000180001006: E8 F5 FF FF FF     bogus\n");
            Need(unsafeText.Records == 1 && unsafeText.Unsupported == 2 && unsafeText.Text == "rva=0x00001005 bytes=C3 mnemonic=ret operands=none\n");
            foreach (string invalid in new [] {
                "", "Dump of file C:\\private\\KernelBase.dll\n", "  0000000180001000: C3     ret\n",
                "  0000000180001000: B8 00 00 00 00     mov\n  0000000180001000: B8     mov\n",
                "  0000000180001005: C3     ret\n  0000000180001000: B8 00 00 00 00     mov\n",
                "  0000000180001600: 00     nop\n", "  00000001800015FF: 00 00     nop\n",
                "  0000000180001000: B8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     mov\n",
                "  0000000180001000:     ret\n", "  0000000180001000: B8     ???\n",
                "  0000000180001000: B8 00 00 00 00     mov eax,0\n                    00\n",
                new string('x', 1048577), new string('\n', 4097)
            }) {
                bool refused = false;
                try { image.QualifyStatic(invalid); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Array.Clear(b, 0x98 + 24, 8),
                b => BitConverter.GetBytes(UInt64.MaxValue).CopyTo(b, 0x98 + 24),
                b => Put(b, 0x98 + 16, 0), b => Put(b, 0x188 + 8, 0),
                b => { Put(b, 0x188 + 8, 1); Put(b, 0x98 + 16, 0x1001); }, b => Put(b, 0x188 + 20, 0x100),
                b => Put(b, 0x188 + 36, 0x40000040)
            }) {
                byte[] bad = (byte[])bytes.Clone(); change(bad); bool refused = false;
                try { FromStatic(bad).EntrySlice(); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            byte[] shortVirtual = (byte[])bytes.Clone(); Put(shortVirtual, 0x188 + 8, 7);
            Need(FromStatic(shortVirtual).EntrySlice().Length == 7);
            byte[] larger = new byte[8192]; Array.Copy(bytes, larger, bytes.Length);
            Put(larger, 0x188 + 8, 6144); Put(larger, 0x188 + 16, 6144); Put(larger, 0x98 + 56, 12288);
            Need(FromStatic(larger).EntrySlice().Length == 4096);
            Array.Clear(larger, 0x200, 4096); var budget = new StringBuilder();
            for (int index = 0; index < 1300; index++) budget.Append("  ").Append((0x180001000UL + (uint)index).ToString("X16", CultureInfo.InvariantCulture)).Append(": 00     mov C:\\private\\secret.dll\n");
            bool budgetRefused = false;
            try { FromStatic(larger).QualifyStatic(budget.ToString()); } catch (InvalidOperationException) { budgetRefused = true; }
            Need(budgetRefused);
        }
        internal static byte[] StaticFixture()
        {
            byte[] bytes = IdentityFixture(); BitConverter.GetBytes(0x180000000UL).CopyTo(bytes, 0x98 + 24);
            new byte[] { 0xB8, 0, 0, 0, 0, 0xC3, 0xE8, 0xF5, 0xFF, 0xFF, 0xFF }.CopyTo(bytes, 0x200); return bytes;
        }
    }
}
