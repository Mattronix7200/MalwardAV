using System.Collections.Concurrent;

namespace Malward.FWManager;

public sealed class TemporaryRuleManager : IDisposable
{
    private readonly ConcurrentDictionary<string, Timer> _timers = new(StringComparer.OrdinalIgnoreCase);

    public (bool ok, string name, string? error) AddAllowTemporary(string appPath, TimeSpan duration, int direction = 2)
    {
        string fname = System.IO.Path.GetFileName(appPath);
        var expiresAt = DateTime.Now.Add(duration);
        string name = $"Malward Temp Allow — {fname} (do {expiresAt:HH:mm})";

        var (ok, err) = FirewallRules.Add(new FirewallRule
        {
            Name = name,
            ApplicationName = appPath,
            Description = $"Malward — tymczasowa zgoda do {expiresAt:HH:mm:ss}",
            Protocol = 256,
            Direction = direction,
            Allow = true,
            Enabled = true,
            Grouping = "Malward-TempAllow",
        });
        if (!ok) return (false, name, err);

        var timer = new Timer(_ =>
        {
            try
            {
                FirewallRules.Remove(name);
                if (_timers.TryRemove(name, out var t)) t.Dispose();
            }
            catch { }
        }, null, duration, Timeout.InfiniteTimeSpan);

        if (_timers.TryRemove(name, out var oldTimer)) oldTimer.Dispose();
        _timers[name] = timer;
        return (true, name, null);
    }

    public void Dispose()
    {
        foreach (var t in _timers.Values) { try { t.Dispose(); } catch { } }
        _timers.Clear();
    }
}
