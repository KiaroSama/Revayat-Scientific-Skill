using System;
using System.IO;

namespace ScientificSecurity
{
    // Internal hosted test fixture only; never a distributed app or Python admission substitute.
    public static class RegistryAuthorityFixture
    {
        static string prepared, digest;
        static int length;
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed Rust registry authority image differs"); }
        static byte[] Read(FileStream stream)
        { return ModuleActivationFixture.Read(stream, 8388608); }
        public static void Prepare(string windowsSource, string python)
        {
            Need(prepared == null);
            string source = Path.Combine(windowsSource, "registry-authority", "target", "x86_64-pc-windows-msvc", "release", "registry-authority.exe");
            string output = Path.Combine(Path.GetDirectoryName(python), "registry-authority.exe");
            DefaultActivationFixture.Missing(output); DefaultActivationFixture.NoOverrides(source); DefaultActivationFixture.NoOverrides(output);
            using (var held = ModuleActivationFixture.Open(source)) {
                byte[] bytes = Read(held);
                try {
                    KernelImage.QualifyRegistryAuthority(bytes);
                    using (var destination = new FileStream(output, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                        destination.Write(bytes, 0, bytes.Length); destination.Flush(true);
                        byte[] actual = Read(destination);
                        try { Need(ModuleActivationFixture.Digest(actual) == ModuleActivationFixture.Digest(bytes)); }
                        finally { Array.Clear(actual, 0, actual.Length); }
                    }
                    prepared = output; digest = ModuleActivationFixture.Digest(bytes); length = bytes.Length;
                }
                finally { Array.Clear(bytes, 0, bytes.Length); }
            }
        }
        internal static string Image(string python)
        {
            string image = Path.Combine(Path.GetDirectoryName(python), "registry-authority.exe");
            Need(prepared != null && image == prepared); DefaultActivationFixture.NoOverrides(image);
            return image;
        }
        internal static IDisposable Hold(string python)
        {
            var stream = ModuleActivationFixture.Open(Image(python));
            try {
                byte[] bytes = Read(stream);
                try { Need(bytes.Length == length && ModuleActivationFixture.Digest(bytes) == digest); KernelImage.QualifyRegistryAuthority(bytes); }
                finally { Array.Clear(bytes, 0, bytes.Length); }
                return stream;
            }
            catch { stream.Dispose(); throw; }
        }
    }
}
