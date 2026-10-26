namespace ScientificSecurity
{
    // Closed observations share suspended preparation and cleanup, not a launch selector.
    internal abstract class RegistryDiagnostic
    {
        internal abstract int Expected { get; }
        internal abstract void RequireFresh();
        internal abstract void Prepare(byte[] primary, byte[] duplicate);
        internal abstract void RequirePolicy(byte[] primary, byte[] duplicate);
        internal abstract void ReadControl(int status);
        internal abstract void Stage(uint code, string text, string errors);
    }
}
