using System.Collections.Concurrent;

namespace Malward.ResidentShield;

public static class RegistryWriters
{
    public const string FirewallPolicy = "firewallpolicy";

    public const string DnsInterfaces = "dns-interfaces";

    private static readonly (string Area, string Needle)[] Areas =
    {
        (FirewallPolicy, "firewallpolicy"),
        (DnsInterfaces, @"\parameters\interfaces"),
    };

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(2);

    public readonly record struct Author(int Pid, string Image, DateTime WhenUtc);

    private static readonly ConcurrentDictionary<string, Author> Last =
        new(StringComparer.OrdinalIgnoreCase);

    public static bool Matches(string? keyPath, out string area)
    {
        area = "";
        if (string.IsNullOrEmpty(keyPath)) return false;
        foreach (var (name, needle) in Areas)
        {
            if (keyPath.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) continue;
            area = name;
            return true;
        }
        return false;
    }

    public static void Note(string area, int pid, string? image)
    {
        if (string.IsNullOrEmpty(area) || pid <= 0) return;
        Last[area] = new Author(pid, image ?? "", DateTime.UtcNow);
    }

    public static Author? Recent(string area)
        => Last.TryGetValue(area, out var a) && DateTime.UtcNow - a.WhenUtc <= Window
           ? a : null;

    public static void Clear() => Last.Clear();
}
