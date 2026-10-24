using System;
using System.Linq;
using System.Text;

namespace ScientificSecurity
{
    public sealed partial class KernelImage
    {
        static readonly string[] SelfActivationImports = { "CreateActCtxW", "ExitProcess", "GetLastError", "GetModuleHandleW", "GetStdHandle", "ReleaseActCtx", "WriteFile" };
        public static void CheckSelfActivationValidation()
        {
            byte[] bytes = Fixture(); Array.Resize(ref bytes, 4096);
            Put16(bytes, 0x96, 2); Put16(bytes, 0x98 + 68, 3);
            Put(bytes, 0x98 + 56, 0x3000); Put(bytes, 0x188 + 8, 0xE00); Put(bytes, 0x188 + 16, 0xE00);
            Array.Clear(bytes, 0x200, 0xE00);
            Put(bytes, 0x98 + 120, 0x1000); Put(bytes, 0x98 + 124, 40);
            Put(bytes, 0x200, 0x1080); Put(bytes, 0x20C, 0x1300); Put(bytes, 0x210, 0x1100);
            Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(bytes, 0x500);
            string[] names = { "CreateActCtxW", "ExitProcess", "GetLastError", "GetModuleHandleW", "GetStdHandle", "ReleaseActCtx", "WriteFile" };
            int text = 0x600;
            for (int index = 0; index < names.Length; index++) {
                ulong symbol = (ulong)(text + 0xE00);
                BitConverter.GetBytes(symbol).CopyTo(bytes, 0x280 + index * 8);
                BitConverter.GetBytes(symbol).CopyTo(bytes, 0x300 + index * 8);
                byte[] name = Encoding.ASCII.GetBytes(names[index] + "\0"); name.CopyTo(bytes, text + 2); text += name.Length + 2;
            }
            Put(bytes, 0x98 + 128, 0x1900); Put(bytes, 0x98 + 132, 0x100);
            Put16(bytes, 0xB0E, 1); Put(bytes, 0xB10, 24); Put(bytes, 0xB14, 0x80000020);
            Put16(bytes, 0xB2E, 1); Put(bytes, 0xB30, 2); Put(bytes, 0xB34, 0x80000040);
            Put16(bytes, 0xB4E, 1); Put(bytes, 0xB50, 1033); Put(bytes, 0xB54, 0x60);
            Put(bytes, 0xB60, 0x1980); Put(bytes, 0xB64, 4);
            byte[] payload = { 1, 2, 3, 4 }; payload.CopyTo(bytes, 0xB80);
            QualifySelfActivation(bytes, 1033, payload);
            byte[] explicitId2 = (byte[])bytes.Clone(); Put16(explicitId2, 0x98 + 70, 0x0200);
            QualifySelfActivation(explicitId2, 1033, payload, SelfActivationRole.ExplicitId2);
            ActivationBoundaryTrace.CheckEntryLifetimeValidation(new KernelImage(explicitId2, 0x10000000, "fixed-entry"));
            foreach (SelfActivationRole role in new [] { SelfActivationRole.Original, SelfActivationRole.Manual, SelfActivationRole.ExplicitId2 }) {
                byte[] wrong = (byte[])bytes.Clone();
                if (role == SelfActivationRole.Manual) Put(wrong, 0xB30, 101);
                Put16(wrong, 0x98 + 70, role == SelfActivationRole.ExplicitId2 ? (ushort)0 : (ushort)0x0200);
                bool refused = false;
                try { QualifySelfActivation(wrong, 1033, payload, role); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            foreach (int invalid in new [] { -1, 3, Int32.MaxValue }) {
                bool refused = false;
                try { QualifySelfActivation(bytes, 1033, payload, (SelfActivationRole)invalid); } catch (ArgumentException) { refused = true; }
                Need(refused);
            }
            foreach (uint resource in new uint[] { 1, 3, 16, 101, 65535 }) {
                byte[] wrong = (byte[])explicitId2.Clone(); Put(wrong, 0xB30, resource); bool refused = false;
                try { QualifySelfActivation(wrong, 1033, payload, SelfActivationRole.ExplicitId2); } catch (InvalidOperationException) { refused = true; }
                Need(refused);
            }
            byte[] wrongBit = (byte[])explicitId2.Clone(); Put16(wrongBit, 0x98 + 70, 0x1000);
            bool bitRefused = false;
            try { QualifySelfActivation(wrongBit, 1033, payload, SelfActivationRole.ExplicitId2); } catch (InvalidOperationException) { bitRefused = true; }
            Need(bitRefused);
            byte[] manual = (byte[])bytes.Clone(); Put(manual, 0xB30, 101);
            QualifySelfActivation(manual, 1033, payload, SelfActivationRole.Manual);
            foreach (uint resource in new uint[] { 1, 2, 3, 16, 100, 102, 65535 }) {
                byte[] wrong = (byte[])manual.Clone(); Put(wrong, 0xB30, resource); bool rejected = false;
                try { QualifySelfActivation(wrong, 1033, payload, SelfActivationRole.Manual); } catch (InvalidOperationException) { rejected = true; }
                Need(rejected);
            }
            bool crossRole = false;
            try { QualifySelfActivation(manual, 1033, payload); } catch (InvalidOperationException) { crossRole = true; }
            Need(crossRole); crossRole = false;
            try { ModuleManifest(manual, true); } catch (InvalidOperationException) { crossRole = true; }
            Need(crossRole); crossRole = false;
            try { DefaultManifest(manual, true); } catch (InvalidOperationException) { crossRole = true; }
            Need(crossRole);
            byte[] extra = (byte[])manual.Clone(); Put16(extra, 0xB2E, 2); Put(extra, 0xB30, 2); Put(extra, 0xB38, 101); Put(extra, 0xB3C, 0x80000040);
            crossRole = false;
            try { QualifySelfActivation(extra, 1033, payload, SelfActivationRole.Manual); } catch (InvalidOperationException) { crossRole = true; }
            Need(crossRole);
            foreach (Action<byte[]> change in new Action<byte[]>[] {
                b => Put16(b, 0x96, 0x2002), b => Put16(b, 0x98 + 68, 2), b => Put(b, 0x98 + 16, 0),
                b => b[0x500] ^= 1, b => b[0x602] ^= 1, b => b[0x300] ^= 1,
                b => { Array.Copy(b, 0x280, b, 0x288, 8); Array.Copy(b, 0x300, b, 0x308, 8); },
                b => { Array.Clear(b, 0x2B0, 8); Array.Clear(b, 0x330, 8); },
                b => Put(b, 0x98 + 124, 39), b => Put(b, 0x214, 1),
                b => Put(b, 0xB30, 1), b => Put(b, 0xB10, 23), b => b[0xB80] ^= 1,
                b => Put(b, 0xB50, 1034), b => Put16(b, 0xB4E, 2), b => Put(b, 0xB60, 0x1940),
                b => { Put16(b, 0xB2E, 2); Put(b, 0xB30, 1); Put(b, 0xB38, 2); Put(b, 0xB3C, 0x80000040); },
                b => Put(b, 0x98 + 112, 0x1000), b => Put(b, 0x98 + 112 + 9 * 8, 0x1000),
                b => Put(b, 0x98 + 112 + 13 * 8, 0x1000), b => Put(b, 0x98 + 112 + 14 * 8, 0x1000)
            }) {
                foreach (SelfActivationRole role in new [] { SelfActivationRole.Original, SelfActivationRole.Manual, SelfActivationRole.ExplicitId2 }) {
                    byte[] bad = (byte[])(role == SelfActivationRole.Manual ? manual : role == SelfActivationRole.ExplicitId2 ? explicitId2 : bytes).Clone(); change(bad); bool refused = false;
                    try { QualifySelfActivation(bad, 1033, payload, role); } catch (InvalidOperationException) { refused = true; }
                    Need(refused);
                }
            }
        }
        internal static KernelImage FromExplicitEntryCreation(IntPtr file, IntPtr imageBase, string expectedPath, string digest)
        {
            string actual = EventPath(file);
            Need(actual != null && System.IO.Path.GetFileName(expectedPath) == "startup-explicit-id2.exe" &&
                String.Equals(actual, expectedPath, StringComparison.OrdinalIgnoreCase));
            var image = ReadEventImage(file, imageBase, "fixed-explicit-entry");
            Need(Hash(image.data) == digest && image.FullExecutable(image.Entry, 1));
            SelfActivationFixture.RequireExplicitEntryImage(expectedPath, image.data);
            return image;
        }
        internal static void QualifySelfActivation(byte[] bytes, ushort language, byte[] expected, SelfActivationRole role = SelfActivationRole.Original)
        {
            SelfActivationFixture.RequireKnownRole(role);
            var image = new KernelImage(bytes, 1, "fixed-self-activation");
            image.ChildActivation(SelfActivationImports, true);
            Need(((image.U16((ulong)image.U32(0x3C) + 24 + 70) & 0x0200) != 0) == (role == SelfActivationRole.ExplicitId2));
            var manifest = role == SelfActivationRole.Manual ? ManualManifest(bytes) : ModuleManifest(bytes, true);
            try { Need(manifest.Item1 == language && manifest.Item2.SequenceEqual(expected)); }
            finally { Array.Clear(manifest.Item2, 0, manifest.Item2.Length); }
        }
    }
}
