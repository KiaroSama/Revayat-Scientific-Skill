using System;

namespace ScientificSecurity
{
    // One fixed caller-site pair; never reads the private CSR message or stack contents.
    internal sealed class CsrDispatchPair
    {
        internal readonly ulong Call, Post;
        internal bool Started { get; private set; }
        internal bool Paired { get; private set; }
        internal uint Result { get; private set; }
        internal int Generation { get; private set; }
        ulong stack;
        bool failed;
        internal CsrDispatchPair(ulong call, ulong post)
        {
            Need(call != 0 && post == call + 7 && call <= 0x7FFFFFFFFFFFFFF0UL);
            Call = call; Post = post;
        }
        static void Need(bool value)
        { if (!value) throw new InvalidOperationException("fixed CSR dispatch pair is inconclusive"); }
        internal void Begin(int generation, byte[] context)
        {
            if (Started || Paired || failed) { failed = true; Need(false); }
            Started = failed = true; // A mismatch consumes the only attempt.
            Need(generation >= 0 && context != null && context.Length == DebugContext.Size);
            ulong rsp = BitConverter.ToUInt64(context, 152);
            Need(rsp != 0 && rsp <= 0x7FFFFFFFFFFFUL && (rsp & 15) == 0 &&
                unchecked((uint)BitConverter.ToUInt64(context, 184)) == 0x1001001E &&
                unchecked((uint)BitConverter.ToUInt64(context, 192)) == 0x1F8);
            Generation = generation; stack = rsp; failed = false;
        }
        internal void End(int generation, byte[] context)
        {
            bool valid = Started && !Paired && !failed && generation == Generation && context != null &&
                context.Length == DebugContext.Size && BitConverter.ToUInt64(context, 152) == stack;
            if (!valid) { failed = true; Need(false); }
            Result = unchecked((uint)BitConverter.ToUInt64(context, 120)); Paired = true;
        }
        internal ulong[] Sites(int generation)
        {
            if (!Started) return new [] { Call, Post };
            return new [] { 0UL, !Paired && generation == Generation ? Post : 0UL };
        }
        internal void Destroyed() { stack = 0; }
        internal static void CheckValidation()
        {
            byte[] context = new byte[DebugContext.Size];
            BitConverter.GetBytes(0x8000UL).CopyTo(context, 152);
            BitConverter.GetBytes(0x1001001EUL).CopyTo(context, 184);
            BitConverter.GetBytes(0x1F8UL).CopyTo(context, 192);
            var pair = new CsrDispatchPair(0x1000, 0x1007);
            Need(pair.Sites(1)[0] == 0x1000 && pair.Sites(1)[1] == 0x1007);
            var early = new CsrDispatchPair(0x1000, 0x1007);
            Refuse(() => early.End(1, context));
            pair.Begin(1, context);
            Need(pair.Sites(1)[0] == 0 && pair.Sites(1)[1] == 0x1007 && pair.Sites(2)[0] == 0 && pair.Sites(2)[1] == 0);
            var repeated = new CsrDispatchPair(0x1000, 0x1007); repeated.Begin(1, context);
            Refuse(() => repeated.Begin(1, context)); Refuse(() => repeated.End(1, context));
            foreach (bool wrongGeneration in new [] { false, true }) {
                var mismatch = new CsrDispatchPair(0x1000, 0x1007); mismatch.Begin(1, context);
                byte[] nested = (byte[])context.Clone();
                if (!wrongGeneration) BitConverter.GetBytes(0x7F00UL).CopyTo(nested, 152);
                Refuse(() => mismatch.End(wrongGeneration ? 2 : 1, nested));
                Refuse(() => mismatch.End(1, context));
            }
            BitConverter.GetBytes(UInt64.MaxValue).CopyTo(context, 184); // Volatile inputs are not re-read as entry arguments.
            BitConverter.GetBytes(0UL).CopyTo(context, 192);
            BitConverter.GetBytes(0x12345678C0150002UL).CopyTo(context, 120);
            pair.End(1, context);
            Need(pair.Paired && pair.Result == 0xC0150002 && pair.Sites(1)[0] == 0 && pair.Sites(1)[1] == 0);
            Refuse(() => pair.End(1, context));
            foreach (int offset in new [] { 152, 184, 192 }) {
                byte[] bad = new byte[DebugContext.Size];
                BitConverter.GetBytes(0x8000UL).CopyTo(bad, 152);
                BitConverter.GetBytes(0x1001001EUL).CopyTo(bad, 184);
                BitConverter.GetBytes(0x1F8UL).CopyTo(bad, 192); bad[offset] ^= 1;
                var failed = new CsrDispatchPair(0x1000, 0x1007);
                Refuse(() => failed.Begin(1, bad)); Need(failed.Started && !failed.Paired);
                Refuse(() => failed.Begin(1, context));
            }
        }
        static void Refuse(Action action)
        { bool refused = false; try { action(); } catch (InvalidOperationException) { refused = true; } Need(refused); }
    }
}
