using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScientificSecurity
{
    // A disposable token scopes creation of fixed canary, ETL/text seeds and collector manifest data.
    internal static class SxsCanaryOwner
    {
        const int Capacity = 256;
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int kind, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr thread, uint access, bool asSelf, out IntPtr token);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        delegate bool QueryCall(IntPtr token, int kind, IntPtr buffer, uint capacity, out uint returned);
        static void Need(bool value) { SxsTraceSession.Need(value); }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != Native.InvalidHandle; }
        static void Clear(IntPtr buffer, int size)
        { for (int offset = 0; offset < size; offset++) Marshal.WriteByte(buffer, offset, 0); }
        static void Close(IntPtr handle)
        { if (Valid(handle)) Native.Check(Native.CloseHandle(handle), "close fixed canary token"); }
        static void Absent(bool opened, int error, IntPtr token)
        { Need(!opened && error == 1008 && token == IntPtr.Zero); }
        static void RequireNoThread()
        {
            IntPtr token = IntPtr.Zero; Exception primary = null;
            try {
                bool opened = OpenThreadToken(GetCurrentThread(), 8, true, out token);
                int error = opened ? 0 : Marshal.GetLastWin32Error(); Absent(opened, error, token);
            }
            catch (Exception error) { primary = error; throw; }
            finally {
                var failures = new List<Exception>();
                StartupActivationAccess.Attempt(failures, () => Close(token));
                StartupActivationAccess.Finish(primary, failures);
            }
        }
        static bool Within(ulong start, uint size, ulong address, uint bytes)
        { return address >= start && address - start <= size && bytes <= size - (address - start); }
        static uint Query(IntPtr token, int kind, IntPtr buffer, QueryCall query)
        {
            Need(kind == 1 || kind == 4 || kind == 8 || kind == 9);
            Clear(buffer, Capacity); uint returned;
            Native.Check(query(token, kind, buffer, Capacity, out returned), "query bounded canary token");
            Need(returned >= 4 && returned <= Capacity); return returned;
        }
        static SecurityIdentifier Sid(IntPtr buffer, uint returned, int kind)
        {
            uint header = kind == 1 ? 16U : 8U;
            Need((kind == 1 || kind == 4) && returned >= header && returned <= Capacity);
            IntPtr pointer = Marshal.ReadIntPtr(buffer);
            ulong start = unchecked((ulong)buffer.ToInt64()), address = unchecked((ulong)pointer.ToInt64());
            Need((address & 3) == 0 && Within(start, returned, address, 8) && address - start >= header);
            byte revision = Marshal.ReadByte(pointer), count = Marshal.ReadByte(pointer, 1);
            uint size = 8U + 4U * count; Need(revision == 1 && count <= 15 && Within(start, returned, address, size));
            var bytes = new byte[size];
            try { Marshal.Copy(pointer, bytes, 0, bytes.Length); return new SecurityIdentifier(bytes, 0); }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static uint Scalar(IntPtr buffer, uint returned)
        { Need(returned == 4); return unchecked((uint)Marshal.ReadInt32(buffer)); }
        static SecurityIdentifier ReadSid(IntPtr token, int kind, IntPtr buffer)
        { return Sid(buffer, Query(token, kind, buffer, Native.GetTokenInformation), kind); }
        static void Identity(SecurityIdentifier expected, SecurityIdentifier user, SecurityIdentifier owner,
                             uint type, uint level, bool duplicate, bool requireOwner)
        {
            Need(user.Equals(expected) && type == (duplicate ? 2U : 1U) && (!duplicate || level == 2));
            Need(!requireOwner || owner.Equals(expected));
        }
        static void RequireToken(IntPtr token, IntPtr buffer, SecurityIdentifier user, bool duplicate, bool owner)
        {
            SecurityIdentifier actualUser = ReadSid(token, 1, buffer);
            uint type = Scalar(buffer, Query(token, 8, buffer, Native.GetTokenInformation));
            uint level = duplicate ? Scalar(buffer, Query(token, 9, buffer, Native.GetTokenInformation)) : 0;
            Identity(user, actualUser, ReadSid(token, 4, buffer), type, level, duplicate, owner);
        }
        static void OwnerInput(IntPtr buffer, SecurityIdentifier user)
        {
            Clear(buffer, Capacity); byte[] bytes = new byte[user.BinaryLength];
            try {
                user.GetBinaryForm(bytes, 0); Need(bytes.Length <= Capacity - 8);
                Marshal.Copy(bytes, 0, IntPtr.Add(buffer, 8), bytes.Length); Marshal.WriteIntPtr(buffer, IntPtr.Add(buffer, 8));
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
        static void RequireEffective(IntPtr buffer, SecurityIdentifier user)
        {
            IntPtr token = IntPtr.Zero; Exception primary = null;
            try {
                Native.Check(OpenThreadToken(GetCurrentThread(), 8, true, out token), "open effective canary token");
                Need(Valid(token)); RequireToken(token, buffer, user, true, true);
            }
            catch (Exception error) { primary = error; throw; }
            finally {
                var failures = new List<Exception>();
                StartupActivationAccess.Attempt(failures, () => Close(token));
                StartupActivationAccess.Finish(primary, failures);
            }
        }
        static void Scope(Func<bool> enter, Action effective, Action body, Func<bool> revert,
                          Action absent, Action fatal, ref bool trusted)
        {
            bool entered = false;
            try {
                Native.Check(enter(), "enter fixed canary owner context");
                entered = true; trusted = false; effective(); body();
            }
            finally {
                if (entered) {
                    bool restored = false;
                    try { restored = revert(); if (restored) absent(); }
                    catch { restored = false; }
                    if (!restored) {
                        fatal();
                        throw new InvalidOperationException("fixed canary fatal restoration unexpectedly returned");
                    }
                    trusted = true;
                }
            }
        }
        static void Release(Exception primary, bool trusted, params Action[] actions)
        {
            if (!trusted) return;
            var failures = new List<Exception>();
            foreach (Action action in actions) StartupActivationAccess.Attempt(failures, action);
            StartupActivationAccess.Finish(primary, failures);
        }
        internal static void Run(SecurityIdentifier user, Action body)
        {
            Need(IntPtr.Size == 8 && user != null && user.Value != "S-1-5-18" && body != null);
            RequireNoThread(); IntPtr primary = IntPtr.Zero, duplicate = IntPtr.Zero, buffer = IntPtr.Zero;
            bool trusted = true; Exception original = null;
            try {
                buffer = Marshal.AllocHGlobal(Capacity);
                Native.Check(Native.OpenProcessToken(Native.GetCurrentProcess(), 0xA, out primary), "open canary host primary");
                Need(Valid(primary)); RequireToken(primary, buffer, user, false, false);
                Native.Check(DuplicateTokenEx(primary, 0x8C, IntPtr.Zero, 2, 2, out duplicate), "duplicate canary host primary");
                Need(Valid(duplicate) && duplicate != primary); RequireToken(duplicate, buffer, user, true, false);
                OwnerInput(buffer, user);
                Native.Check(Native.SetTokenInformation(duplicate, 4, buffer, 8), "set canary duplicate default owner");
                RequireToken(duplicate, buffer, user, true, true); RequireNoThread();
                Scope(() => ImpersonateLoggedOnUser(duplicate), () => RequireEffective(buffer, user), body,
                    RevertToSelf, RequireNoThread,
                    () => Environment.FailFast("Canary identity restoration uncertain; outer owner must recover."), ref trusted);
            }
            catch (Exception error) { original = error; throw; }
            finally {
                Release(original, trusted, () => Close(duplicate), () => { if (primary != duplicate) Close(primary); },
                    () => { if (buffer != IntPtr.Zero) Clear(buffer, Capacity); },
                    () => { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); });
            }
        }
        static void Refused(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
        internal static void CheckValidation()
        {
            Need(IntPtr.Size == 8);
            Absent(false, 1008, IntPtr.Zero);
            foreach (Action action in new Action[] { () => Absent(true, 0, new IntPtr(1)), () => Absent(false, 5, IntPtr.Zero),
                () => Absent(false, 1008, new IntPtr(1)), () => Absent(false, 1008, Native.InvalidHandle) }) Refused(action);
            var user = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
            var other = new SecurityIdentifier("S-1-5-18");
            Identity(user, user, other, 1, 0, false, false);
            Identity(user, user, user, 2, 2, true, true);
            foreach (Action action in new Action[] { () => Identity(user, other, user, 2, 2, true, true),
                () => Identity(user, user, other, 2, 2, true, true), () => Identity(user, user, user, 1, 2, true, true),
                () => Identity(user, user, user, 2, 1, true, true), () => Identity(user, user, user, 2, 0, false, false) }) Refused(action);
            IntPtr buffer = Marshal.AllocHGlobal(Capacity);
            try {
                OwnerInput(buffer, user); Need(Sid(buffer, 36, 4).Equals(user));
                Need(Marshal.ReadIntPtr(buffer) == IntPtr.Add(buffer, 8) && Marshal.ReadByte(buffer, 8) == 1 && Marshal.ReadByte(buffer, 9) == 5);
                byte[] expected = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 233, 3, 0, 0 };
                var actual = new byte[28]; Marshal.Copy(IntPtr.Add(buffer, 8), actual, 0, 28);
                Need(System.Linq.Enumerable.SequenceEqual(actual, expected));
                for (int kind = 0; kind < 9; kind++) {
                    OwnerInput(buffer, user); int corruption = kind;
                    Refused(() => {
                        uint returned = 36; int info = 4;
                        if (corruption == 0) returned = 7;
                        if (corruption == 1) returned = 257;
                        if (corruption == 2) Marshal.WriteIntPtr(buffer, IntPtr.Subtract(buffer, 4));
                        if (corruption == 3) Marshal.WriteIntPtr(buffer, IntPtr.Add(buffer, 9));
                        if (corruption == 4) Marshal.WriteByte(buffer, 8, 2);
                        if (corruption == 5) Marshal.WriteByte(buffer, 9, 16);
                        if (corruption == 6) returned = 35;
                        if (corruption == 7) info = 8;
                        if (corruption == 8) info = 1;
                        Sid(buffer, returned, info);
                    });
                }
                Marshal.WriteInt32(buffer, 2); Need(Scalar(buffer, 4) == 2);
                Refused(() => Scalar(buffer, 8));
                int queries = 0;
                QueryCall fake = delegate(IntPtr token, int kind, IntPtr data, uint capacity, out uint returned) {
                    queries++; Need(token == new IntPtr(1) && kind == 8 && capacity == 256);
                    for (int offset = 0; offset < Capacity; offset++) Need(Marshal.ReadByte(data, offset) == 0);
                    Marshal.WriteInt32(data, 2); returned = 4; return true;
                };
                Need(Scalar(buffer, Query(new IntPtr(1), 8, buffer, fake)) == 2 && queries == 1);
                Refused(() => Query(new IntPtr(1), 6, buffer, fake)); Need(queries == 1);
            }
            finally { try { Clear(buffer, Capacity); } finally { Marshal.FreeHGlobal(buffer); } }
            for (int mode = 0; mode < 10; mode++) {
                string order = ""; bool trusted = true; Exception caught = null;
                var operation = new InvalidOperationException("private-canary-operation");
                var cleanup = new InvalidOperationException("private-canary-close");
                var fatal = new InvalidOperationException("private-canary-fatal");
                try {
                    try {
                        Scope(() => { order += "e"; if (mode == 1) throw operation; return mode != 9; },
                            () => { order += "q"; if (mode == 2) throw operation; },
                            () => { order += "b"; if (mode == 3) throw operation; },
                            () => { order += "r"; if (mode == 4) throw operation; return mode != 5 && mode != 8; },
                            () => { order += "a"; if (mode == 6) throw operation; },
                            () => { order += "f"; if (mode != 8) throw fatal; }, ref trusted);
                    }
                    catch (Exception error) { caught = error; throw; }
                    finally { Release(caught, trusted, () => { order += "d"; if (mode == 7) throw cleanup; }, () => order += "p"); }
                }
                catch (Exception error) { caught = error; }
                Need(order == (mode == 1 || mode == 9 ? "edp" : mode == 2 ? "eqradp" : mode == 4 || mode == 5 || mode == 8 ? "eqbrf" : mode == 6 ? "eqbraf" : "eqbradp"));
                Need(trusted == (mode < 4 || mode == 7 || mode == 9));
                if (mode == 0) Need(caught == null);
                if (mode >= 1 && mode <= 3) Need(Object.ReferenceEquals(caught, operation));
                if (mode >= 4 && mode <= 6) Need(Object.ReferenceEquals(caught, fatal));
                if (mode == 7) Need(caught is AggregateException && Object.ReferenceEquals(((AggregateException)caught).InnerExceptions[0], cleanup));
                if (mode == 8 || mode == 9) Need(caught != null && !Object.ReferenceEquals(caught, operation));
            }
            var first = new InvalidOperationException("private-first");
            var second = new InvalidOperationException("private-second");
            Exception retained = null; int attempts = 0;
            try { Release(first, true, () => { attempts++; throw second; }, () => attempts++); }
            catch (AggregateException error) { retained = error; Need(error.InnerExceptions.Count == 2 && Object.ReferenceEquals(error.InnerExceptions[0], first) && Object.ReferenceEquals(error.InnerExceptions[1], second)); }
            Need(retained != null && attempts == 2 && Within(100, 16, 108, 8) && !Within(100, 16, 108, 9) && !Within(UInt64.MaxValue - 8, 8, 1, 1));
        }
    }
}
