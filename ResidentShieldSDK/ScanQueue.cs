using System.Collections.Concurrent;

namespace Malward.ResidentShield;

public enum ScanEventKind
{
    FileCreated,
    FileModified,
    ProcessStarted,
    ManualScan,
}

public sealed record ScanEvent(
    ScanEventKind  Kind,
    string         FilePath,
    int?           Pid,
    string?        ProcessName,
    DateTimeOffset Timestamp);

public sealed class ScanQueue
{
    private readonly ConcurrentDictionary<string, long> _recentPaths
        = new(StringComparer.OrdinalIgnoreCase);

    public int DedupWindowMs { get; }

    public ScanQueue(int dedupWindowMs = 8_000)
    {
        DedupWindowMs = dedupWindowMs;
    }

    public bool TryEnqueue(ScanEvent ev)
    {
        long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        if (_recentPaths.TryGetValue(ev.FilePath, out long seenMs)
            && nowMs - seenMs < DedupWindowMs)
            return false;

        _recentPaths[ev.FilePath] = nowMs;

        if (_recentPaths.Count > 5_000)
            PurgeOldEntries(nowMs);

        return true;
    }

    private void PurgeOldEntries(long nowMs)
    {
        foreach (var key in _recentPaths.Keys.ToArray())
        {
            if (_recentPaths.TryGetValue(key, out long ts) && nowMs - ts > DedupWindowMs * 10L)
                _recentPaths.TryRemove(key, out _);
        }
    }
}
