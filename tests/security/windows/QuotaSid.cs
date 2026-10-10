using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;

namespace ScientificSecurity
{
    // ABI order/signatures: Microsoft WinSDK DskQuota.h, win32metadata 76c04c2021ef.
    // IDiskQuotaControl inherits IConnectionPointContainer, not just IUnknown.
    [ComImport, Guid("7988B572-EC89-11CF-9C00-00AA00A14F56"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface DiskQuotaControl
    {
        [PreserveSig] int EnumConnectionPoints(out IEnumConnectionPoints enumerator);
        [PreserveSig] int FindConnectionPoint(ref Guid iid, out IConnectionPoint point);
        [PreserveSig] int Initialize([MarshalAs(UnmanagedType.LPWStr)] string path, [MarshalAs(UnmanagedType.Bool)] bool readWrite);
        [PreserveSig] int SetQuotaState(uint state);
        [PreserveSig] int GetQuotaState(out uint state);
        [PreserveSig] int SetQuotaLogFlags(uint flags);
        [PreserveSig] int GetQuotaLogFlags(out uint flags);
        [PreserveSig] int SetDefaultQuotaThreshold(long threshold);
        [PreserveSig] int GetDefaultQuotaThreshold(out long threshold);
        [PreserveSig] int GetDefaultQuotaThresholdText(IntPtr text, uint characters);
        [PreserveSig] int SetDefaultQuotaLimit(long limit);
        [PreserveSig] int GetDefaultQuotaLimit(out long limit);
        [PreserveSig] int GetDefaultQuotaLimitText(IntPtr text, uint characters);
        [PreserveSig] int AddUserSid(IntPtr sid, uint nameResolution, out DiskQuotaUser user);
        [PreserveSig] int AddUserName([MarshalAs(UnmanagedType.LPWStr)] string name, uint nameResolution, out DiskQuotaUser user);
        [PreserveSig] int DeleteUser(DiskQuotaUser user);
        [PreserveSig] int FindUserSid(IntPtr sid, uint nameResolution, out DiskQuotaUser user);
        [PreserveSig] int FindUserName([MarshalAs(UnmanagedType.LPWStr)] string name, out DiskQuotaUser user);
        [PreserveSig] int CreateEnumUsers(IntPtr sidArray, uint count, uint nameResolution, out IntPtr enumerator);
        [PreserveSig] int CreateUserBatch(out IntPtr batch);
        [PreserveSig] int InvalidateSidNameCache();
        [PreserveSig] int GiveUserNameResolutionPriority(DiskQuotaUser user);
        [PreserveSig] int ShutdownNameResolution();
    }

    [ComImport, Guid("7988B574-EC89-11CF-9C00-00AA00A14F56"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface DiskQuotaUser
    {
        [PreserveSig] int GetID(out uint id);
        [PreserveSig] int GetName(IntPtr container, uint containerCharacters, IntPtr name, uint nameCharacters,
                                  IntPtr display, uint displayCharacters);
        [PreserveSig] int GetSidLength(out uint length);
        [PreserveSig] int GetSid(IntPtr sid, uint length);
        [PreserveSig] int GetQuotaThreshold(out long threshold);
        [PreserveSig] int GetQuotaThresholdText(IntPtr text, uint characters);
        [PreserveSig] int GetQuotaLimit(out long limit);
        [PreserveSig] int GetQuotaLimitText(IntPtr text, uint characters);
        [PreserveSig] int GetQuotaUsed(out long used);
        [PreserveSig] int GetQuotaUsedText(IntPtr text, uint characters);
        [PreserveSig] int GetQuotaInformation(IntPtr information, uint bytes);
        [PreserveSig] int SetQuotaThreshold(long threshold, [MarshalAs(UnmanagedType.Bool)] bool writeThrough);
        [PreserveSig] int SetQuotaLimit(long limit, [MarshalAs(UnmanagedType.Bool)] bool writeThrough);
        [PreserveSig] int Invalidate();
        [PreserveSig] int GetAccountStatus(out uint status);
    }

    public static class QuotaSid
    {
        public static void SetPackageEntry(string volume, string packageSid)
        {
            if (String.IsNullOrEmpty(packageSid) || !packageSid.StartsWith("S-1-15-2-", StringComparison.Ordinal))
                throw new ArgumentException("quota entry must be the assigned AppContainer package SID");
            SetOwnerEntry(volume, packageSid);
        }
        public static void SetOwnerEntry(string volume, string ownerSid)
        {
            const long limit = 16777216;
            // Token-derived owner SIDs need no account-name resolution.
            var sid = new SecurityIdentifier(ownerSid);
            if (String.IsNullOrEmpty(volume) || volume.Length != 3 || volume[1] != ':' || volume[2] != '\\')
                throw new ArgumentException("quota entry requires the owned virtual disk drive root");
            byte[] bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            IntPtr buffer = IntPtr.Zero;
            object instance = null;
            DiskQuotaUser user = null;
            try
            {
                buffer = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, buffer, bytes.Length);
                Type type = Type.GetTypeFromCLSID(new Guid("7988B571-EC89-11CF-9C00-00AA00A14F56"), true);
                instance = Activator.CreateInstance(type);
                var control = (DiskQuotaControl)instance;
                Check(control.Initialize(volume, true), "initialize owned SID quota volume");
                // FindUserSid returns a default-backed user object even before a quota record
                // exists; write-through setters below persist it and also handle existing owners.
                Check(control.FindUserSid(buffer, 0, out user), "find owner SID quota without name resolution");
                if (user == null) throw new InvalidOperationException("SID quota API returned no user record");
                Check(user.SetQuotaThreshold(limit, true), "persist owner quota threshold");
                Check(user.SetQuotaLimit(limit, true), "persist owner quota limit");
                Check(user.Invalidate(), "invalidate owner quota cache before readback");
                long actualThreshold, actualLimit;
                Check(user.GetQuotaThreshold(out actualThreshold), "read back owner quota threshold");
                Check(user.GetQuotaLimit(out actualLimit), "read back owner quota limit");
                uint sidLength;
                Check(user.GetSidLength(out sidLength), "read owner quota identity length");
                if (sidLength != bytes.Length || actualThreshold != limit || actualLimit != limit)
                    throw new InvalidOperationException("persisted SID quota identity or bounds differ");
                Check(user.GetSid(buffer, sidLength), "read back owner quota SID");
                byte[] actual = new byte[sidLength]; Marshal.Copy(buffer, actual, 0, actual.Length);
                if (!new SecurityIdentifier(actual, 0).Equals(sid))
                    throw new InvalidOperationException("quota record belongs to a different SID");
                Console.Out.WriteLine("WINDOWS_PACKAGE_QUOTA limit_bytes=16777216 threshold_bytes=16777216 identity_verified=true");
                Console.Out.Flush();
            }
            finally
            {
                try { if (user != null && Marshal.IsComObject(user)) Marshal.FinalReleaseComObject(user); }
                finally
                {
                    try { if (instance != null && Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance); }
                    finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
                }
            }
        }
        static void Check(int result, string operation)
        {
            if (result != 0) throw new COMException(operation + " HRESULT=0x" + unchecked((uint)result).ToString("X8"), result);
        }
    }
}
