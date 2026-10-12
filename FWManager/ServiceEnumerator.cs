using System.ServiceProcess;

namespace Malward.FWManager;

public sealed class ServiceInfo
{
    public string Name { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string Status { get; init; } = "";
    public string StartType { get; init; } = "";

    public bool BlockedByMalward { get; init; }
}

public static class ServiceEnumerator
{
    public static List<ServiceInfo> EnumerateAll()
    {
        var list = new List<ServiceInfo>();
        try
        {
            var blockedByMfw = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var r in FirewallRules.List())
                {
                    if (!r.Allow && !string.IsNullOrEmpty(r.ServiceName) &&
                        (r.Grouping ?? "").StartsWith("Malward", StringComparison.OrdinalIgnoreCase))
                    {
                        blockedByMfw.Add(r.ServiceName);
                    }
                }
            }
            catch { }

            foreach (var s in ServiceController.GetServices())
            {
                try
                {
                    list.Add(new ServiceInfo
                    {
                        Name = s.ServiceName,
                        DisplayName = s.DisplayName,
                        Status = s.Status.ToString(),
                        StartType = TryGetStartType(s),
                        BlockedByMalward = blockedByMfw.Contains(s.ServiceName),
                    });
                }
                catch {  }
                finally { try { s.Dispose(); } catch { } }
            }
        }
        catch { }

        list.Sort((a, b) =>
        {
            int aR = a.Status == "Running" ? 0 : 1;
            int bR = b.Status == "Running" ? 0 : 1;
            if (aR != bR) return aR - bR;
            return string.Compare(a.DisplayName, b.DisplayName, StringComparison.OrdinalIgnoreCase);
        });
        return list;
    }

    private static string TryGetStartType(ServiceController s)
    {
        try { return s.StartType.ToString(); }
        catch { return "?"; }
    }
}
