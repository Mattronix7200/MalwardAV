namespace Malward.NetworkScanner;

public static class NetworkPolicies
{
    public static bool AnythingApplied() =>
        BrowserProxyGuard.HasPendingSnapshot()
        || DohGuard.HasPendingSnapshot()
        || DnsLeakGuard.RulesApplied();

    public static void ClearAll()
    {
        if (DnsLeakGuard.RulesApplied())
        {
            try { new DnsLeakGuard().Remove(); }
            catch (Exception ex) { Log.Warn("Service", $"foreign DNS rules: {ex.Message}"); }
        }

        if (BrowserProxyGuard.HasPendingSnapshot())
        {
            try { new BrowserProxyGuard().Restore(); }
            catch (Exception ex) { Log.Warn("Service", $"browser proxy policy: {ex.Message}"); }
        }

        if (DohGuard.HasPendingSnapshot())
        {
            try { new DohGuard().Restore(); }
            catch (Exception ex) { Log.Warn("Service", $"encrypted DNS policy: {ex.Message}"); }
        }
    }
}
