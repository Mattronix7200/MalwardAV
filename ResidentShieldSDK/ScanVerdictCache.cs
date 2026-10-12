using System.Collections.Concurrent;

namespace Malward.ResidentShield;

public sealed class ScanVerdictCache
{
    private readonly record struct Entry(ScanVerdict Verdict, string? Threat, string? Detail, long Ticks);

    private readonly ConcurrentDictionary<string, Entry> _map = new(StringComparer.OrdinalIgnoreCase);
    private readonly long _ttlTicks;
    private readonly int  _maxEntries;

    public ScanVerdictCache(TimeSpan ttl, int maxEntries = 20_000)
    {
        _ttlTicks   = ttl.Ticks;
        _maxEntries = Math.Max(256, maxEntries);
    }

    public bool TryGet(string sha256, out ScanResult cached, string filePath, string md5)
    {
        cached = null!;
        if (string.IsNullOrEmpty(sha256)) return false;
        if (!_map.TryGetValue(sha256, out var e)) return false;
        if (DateTime.UtcNow.Ticks - e.Ticks > _ttlTicks) { _map.TryRemove(sha256, out _); return false; }
        cached = new ScanResult(filePath, e.Verdict, e.Threat, e.Detail ?? "cache", sha256, md5);
        return true;
    }

    public void Set(string sha256, ScanResult result)
    {
        if (string.IsNullOrEmpty(sha256)) return;

        if (result.Verdict is not (ScanVerdict.Clean or ScanVerdict.Threat)) return;
        if (_map.Count >= _maxEntries) EvictOldest();
        _map[sha256] = new Entry(result.Verdict, result.ThreatName, result.Detail, DateTime.UtcNow.Ticks);
    }

    private void EvictOldest()
    {
        try
        {
            var drop = _map.OrderBy(kv => kv.Value.Ticks)
                           .Take(Math.Max(1, _maxEntries / 10))
                           .Select(kv => kv.Key).ToList();
            foreach (var k in drop) _map.TryRemove(k, out _);
        }
        catch {  }
    }
}
