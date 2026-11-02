using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ScientificSecurity
{
    // Correlation of owned objects only; neither attachment provenance nor checked-device causality.
    public sealed class ScratchAttachment : IDisposable
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
        [DllImport("ntdll.dll")]
        static extern int NtQuerySecurityObject(IntPtr handle, uint fields, IntPtr buffer, uint bytes, out uint returned);
        static ScratchAttachment current;
        IntPtr image;
        ScratchAccess.FileInformation identity;
        byte[] before;
        uint beforeStatus, disk, partition;
        string imagePath, root, run, state;
        ScratchAttachment() { }
        public static ScratchAttachment Capture(string run, string state)
        {
            Need(current == null && run != null && run.Length == 32 && Path.IsPathFullyQualified(state));
            foreach (char c in run) Need(c >= '0' && c <= '9' || c >= 'a' && c <= 'f');
            state = Path.GetFullPath(state);
            Need(Path.GetFileName(Path.TrimEndingDirectorySeparator(state)) == "security-windows-" + run);
            string path = Path.Combine(state, "scratch.vhdx"); NativeFixture.Plain(path);
            var result = new ScratchAttachment { imagePath = path, run = run, state = state };
            try {
                result.image = CreateFileW(path, 0x20080, 3, IntPtr.Zero, 3, 0x200000, IntPtr.Zero);
                Native.Check(Valid(result.image), "pin owned scratch image metadata");
                ScratchAccess.RequirePlain(result.image, false);
                result.identity = ScratchAccess.Identity(result.image);
                result.before = Read(result.image, out result.beforeStatus);
                current = result; return result;
            }
            catch (Exception error) { result.Close(error); throw; }
        }
        public void Bind(string scratch, uint diskNumber, uint partitionNumber)
        {
            Need(current == this && root == null && scratch != null && scratch.Length == 3 &&
                scratch[0] >= 'D' && scratch[0] <= 'Z' && scratch[1] == ':' && scratch[2] == '\\' && partitionNumber != 0);
            root = scratch; disk = diskNumber; partition = partitionNumber;
            IntPtr volume = IntPtr.Zero; Exception primary = null;
            try { RecheckImage(); volume = OpenVolume(); }
            catch (Exception error) { primary = error; }
            Release(primary, () => { if (Valid(volume)) RequireNumber(volume); },
                () => { if (Valid(volume)) Native.Check(Native.CloseHandle(volume), "close owned scratch binding handle"); });
        }
        internal static ScratchVolumePolicy Policy(string scratch, string package, bool supported = false)
        {
            var owner = current; Need(owner != null && owner.root == scratch && Valid(owner.image));
            owner.RecheckImage();
            return ScratchVolumePolicy.Begin(owner.run, owner.state, scratch, owner.disk, owner.partition, package, supported);
        }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        void RecheckImage()
        {
            NativeFixture.Plain(imagePath); ScratchAccess.RequirePlain(image, false);
            ScratchAccess.Same(identity, ScratchAccess.Identity(image));
        }
        IntPtr OpenVolume()
        {
            IntPtr handle = CreateFileW(@"\\.\" + root.Substring(0, 2), 0x20000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            Native.Check(Valid(handle), "open owned scratch volume metadata");
            try { RequireNumber(handle); return handle; }
            catch (Exception error) {
                Release(error, () => { }, () => Native.Check(Native.CloseHandle(handle), "close refused scratch volume handle"));
                throw;
            }
        }
        void RequireNumber(IntPtr handle)
        {
            IntPtr memory = Marshal.AllocHGlobal(12);
            try {
                uint returned;
                Native.Check(Native.DeviceIoControl(handle, 0x2D1080, IntPtr.Zero, 0, memory, 12, out returned, IntPtr.Zero),
                    "query owned scratch volume association");
                Need(returned == 12); var bytes = new byte[12]; Marshal.Copy(memory, bytes, 0, 12);
                Number(bytes, disk, partition);
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        static byte[] Read(IntPtr handle, out uint status)
        {
            IntPtr memory = Marshal.AllocHGlobal(65536); bool pending = false;
            try {
                uint returned; int result = NtQuerySecurityObject(handle, 0x17, memory, 65536, out returned);
                pending = result == 0x103;
                if (pending) Environment.FailFast("Scratch descriptor query remained pending; outer owner must recover.");
                status = unchecked((uint)result);
                if (result != 0) return null;
                Need(returned >= 20 && returned <= 65536);
                var bytes = new byte[returned]; Marshal.Copy(memory, bytes, 0, bytes.Length);
                Descriptor(bytes); return bytes;
            }
            finally { if (!pending) Marshal.FreeHGlobal(memory); }
        }
        internal static List<string> Observe(string scratch, IntPtr token, SecurityIdentifier user,
            SecurityIdentifier package, Action deadline)
        {
            var owner = current; Need(owner != null && owner.root == scratch && Valid(owner.image));
            var frames = new List<string>(); IntPtr volume = IntPtr.Zero; Exception primary = null;
            try {
                deadline(); owner.RecheckImage(); volume = owner.OpenVolume();
                uint imageStatus, volumeStatus;
                byte[] imageNow = Read(owner.image, out imageStatus); deadline();
                byte[] volumeNow = Read(volume, out volumeStatus); deadline();
                byte[][] descriptors = { owner.before, imageNow, volumeNow };
                uint[] statuses = { owner.beforeStatus, imageStatus, volumeStatus };
                string[] labels = { "image-before", "image-current", "volume-own" };
                for (int i = 0; i < descriptors.Length; i++) {
                    deadline(); var result = new ScratchAccess.Result();
                    if (descriptors[i] != null) ScratchAccess.ModelDescriptor(descriptors[i], token, user, package, result);
                    frames.Add(Frame(labels[i], statuses[i], result));
                }
                frames.Add(Pair("image-stable", owner.before, imageNow));
                frames.Add(Pair("image-volume", owner.before, volumeNow));
            }
            catch (Exception error) { primary = error; }
            Release(primary, () => { deadline(); owner.RecheckImage(); if (Valid(volume)) owner.RequireNumber(volume); },
                () => { if (Valid(volume)) Native.Check(Native.CloseHandle(volume), "close owned scratch policy handle"); });
            return frames;
        }
        static string Frame(string label, uint status, ScratchAccess.Result result)
        {
            Need(label == "image-before" || label == "image-current" || label == "volume-own");
            return "WINDOWS_SCRATCH_ATTACHMENT object=" + label + " descriptor_status=0x" + status.ToString("X8") +
                " model_completed=" + result.checkedAccess + " allowed=" + result.allowed + " granted=0x" + result.granted.ToString("X8") +
                " model_error=0x" + result.checkError.ToString("X8") + " " + result.policy +
                " checked_device_verified=False cause_claimed=False";
        }
        void Close(Exception primary)
        {
            IntPtr handle = image; image = IntPtr.Zero;
            Release(primary, () => {
                if (Valid(handle)) { NativeFixture.Plain(imagePath); ScratchAccess.Same(identity, ScratchAccess.Identity(handle)); }
            }, () => { if (Valid(handle)) Native.Check(Native.CloseHandle(handle), "close owned scratch image pin"); });
        }
        public void Dispose()
        {
            try { Close(null); }
            finally { if (current == this) current = null; before = null; }
        }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed scratch attachment observation is invalid"); }
        static void Number(byte[] bytes, uint disk, uint partition)
        {
            Need(bytes != null && bytes.Length == 12 && BitConverter.ToUInt32(bytes, 0) == 7 &&
                BitConverter.ToUInt32(bytes, 4) == disk && BitConverter.ToUInt32(bytes, 8) == partition && partition != 0);
        }
        static RawSecurityDescriptor Descriptor(byte[] bytes)
        {
            Need(bytes != null && bytes.Length >= 20 && bytes.Length <= 65536);
            var value = new RawSecurityDescriptor(bytes, 0);
            Need(value.Owner != null && value.Group != null &&
                (value.ControlFlags & ControlFlags.SelfRelative) != 0);
            Need(value.DiscretionaryAcl == null || value.DiscretionaryAcl.Count <= 256);
            Need(value.SystemAcl == null || value.SystemAcl.Count <= 16);
            return value;
        }
        static byte[] Binary(GenericAcl acl)
        {
            if (acl == null) return null;
            var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes;
        }
        static bool Equal(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
        static bool SamePolicy(byte[] a, byte[] b)
        {
            var first = Descriptor(a); var second = Descriptor(b);
            return first.Owner == second.Owner && first.Group == second.Group &&
                first.ControlFlags == second.ControlFlags && first.ResourceManagerControl == second.ResourceManagerControl &&
                Equal(Binary(first.DiscretionaryAcl), Binary(second.DiscretionaryAcl)) &&
                Equal(Binary(first.SystemAcl), Binary(second.SystemAcl));
        }
        static string Pair(string name, byte[] a, byte[] b)
        {
            Need(name == "image-stable" || name == "image-volume");
            bool known = a != null && b != null;
            return "WINDOWS_SCRATCH_ATTACHMENT_PAIR pair=" + name + " known=" + known +
                " equal=" + (known && SamePolicy(a, b)) + " attachment_input_verified=False checked_device_verified=False cause_claimed=False";
        }
        static void Release(Exception primary, Action recheck, Action close)
        {
            var failures = new List<Exception>();
            ScratchAccess.Attempt(failures, recheck); ScratchAccess.Attempt(failures, close);
            ScratchAccess.Finish(primary, failures);
        }
        public static void CheckValidation()
        {
            var number = new byte[12]; BitConverter.GetBytes(7U).CopyTo(number, 0);
            BitConverter.GetBytes(2U).CopyTo(number, 4); BitConverter.GetBytes(1U).CopyTo(number, 8);
            Number(number, 2, 1);
            foreach (Action invalid in new Action[] {
                () => Number(new byte[11], 2, 1), () => Number(number, 3, 1), () => Number(number, 2, 2),
                () => Number(new byte[12], 0, 0), () => Descriptor(new byte[19]), () => Descriptor(new byte[65537]) }) {
                bool refused = false; try { invalid(); } catch (InvalidOperationException) { refused = true; } Need(refused);
            }
            Func<string, byte[]> binary = text => {
                var value = new RawSecurityDescriptor(text); var bytes = new byte[value.BinaryLength];
                value.GetBinaryForm(bytes, 0); return bytes;
            };
            byte[] before = binary("O:SYG:SYD:P(A;;0x00100020;;;SY)S:(ML;;NW;;;LW)");
            Need(SamePolicy(before, binary("O:SYG:SYD:P(A;;0x00100020;;;SY)S:(ML;;NW;;;LW)")));
            foreach (string changed in new [] {
                "O:BAG:SYD:P(A;;0x00100020;;;SY)S:(ML;;NW;;;LW)",
                "O:SYG:BAD:P(A;;0x00100020;;;SY)S:(ML;;NW;;;LW)",
                "O:SYG:SYD:P(A;;0x00100021;;;SY)S:(ML;;NW;;;LW)",
                "O:SYG:SYD:P(A;;0x00100020;;;SY)S:(ML;;NW;;;ME)" }) Need(!SamePolicy(before, binary(changed)));
            Need(Pair("image-stable", before, before).Contains("known=True equal=True"));
            string unknown = Pair("image-volume", before, null);
            Need(unknown.Contains("known=False equal=False") && unknown.Length < 256 && !unknown.Contains("S-1-"));
            var original = new IOException("private-original"); var identity = new IOException("private-identity");
            var cleanup = new IOException("private-cleanup"); int closed = 0;
            try { Release(original, () => { throw identity; }, () => { closed++; throw cleanup; }); }
            catch (AggregateException error) {
                Need(error.InnerExceptions.Count == 3 && Object.ReferenceEquals(error.InnerExceptions[0], original) &&
                    Object.ReferenceEquals(error.InnerExceptions[1], identity) && Object.ReferenceEquals(error.InnerExceptions[2], cleanup));
            }
            Need(closed == 1);
        }
    }
}
