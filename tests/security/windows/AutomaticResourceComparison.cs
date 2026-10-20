using System;

namespace ScientificSecurity
{
    public static class AutomaticResourceComparison
    {
        public static void Run(string run, string state, string python, string root, string scratch, string powershell,
            string chromium, string moniker, string profileFolder, int tcpPort, int udpPort)
        {
            ExplicitEntryComparison.Execute(
                () => Sandbox.ObserveAutomaticResource(python, root, scratch, powershell, chromium, moniker, profileFolder, tcpPort, udpPort),
                () => ExplicitEntryComparison.Run(run, state, python, root, scratch, powershell, chromium, moniker, profileFolder, tcpPort, udpPort));
        }
        public static void CheckValidation()
        {
            ActivationBoundaryTrace.CheckAutomaticResourceValidation();
            ExplicitEntryComparison.CheckValidation();
            var resource = new InvalidOperationException("fixed resource diagnostic");
            var entry = new InvalidOperationException("fixed entry diagnostic");
            var undebugged = new InvalidOperationException("fixed undebugged diagnostic");
            int laterCalls = 0; AggregateException caught = null;
            try {
                ExplicitEntryComparison.Execute(() => {
                    throw ExplicitEntryComparison.FinishTrace(resource, new System.Collections.Generic.List<Exception>(), true, true, () => "fixed resource", _ => { });
                }, () => { laterCalls++;
                    ExplicitEntryComparison.Execute(() => {
                        throw ExplicitEntryComparison.FinishTrace(entry, new System.Collections.Generic.List<Exception>(), true, true, () => "fixed entry", _ => { });
                    }, () => { laterCalls++; throw undebugged; });
                });
            } catch (AggregateException failure) { caught = failure; }
            var inner = caught == null || caught.InnerExceptions.Count != 2 ? null : caught.InnerExceptions[1] as AggregateException;
            if (laterCalls != 2 || caught == null || caught.InnerExceptions.Count != 2 ||
                !Object.ReferenceEquals(caught.InnerExceptions[0], resource) || inner == null || inner.InnerExceptions.Count != 2 ||
                !Object.ReferenceEquals(inner.InnerExceptions[0], entry) || !Object.ReferenceEquals(inner.InnerExceptions[1], undebugged))
                throw new InvalidOperationException("resource/entry/undebugged failure precedence differs");
        }
    }
}
