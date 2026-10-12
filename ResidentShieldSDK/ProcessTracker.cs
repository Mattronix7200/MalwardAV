using System.Collections.Concurrent;
using System.Linq;

namespace Malward.ResidentShield;

public enum ChangeKind
{
    FileCreate,
    FileModify,
    FileDelete,
    RegCreate,
    RegSet,
    RegDelete,
    RegAutostart,
    ServiceCreate,
    ScheduledTask,
}

public sealed record ProcessInfo(
    int    Pid,
    int    ParentPid,
    string Name,
    string ImagePath,
    string CommandLine,
    DateTimeOffset StartTime);

public sealed record ProcessChange(
    int    Pid,
    ChangeKind Kind,
    string Location,
    string? Extra,
    bool   IsAutostart,
    DateTimeOffset Timestamp);

public enum ProcRep
{
    Unknown = 0,
    Whitelisted,
    SystemTrusted,
    VpsBad,
}

public readonly record struct RepRecord(ProcRep Kind, string ImagePath, long Size, DateTime MtimeUtc);

public sealed class ProcessTracker
{
    private readonly ConcurrentDictionary<int, ProcessInfo>          _procs   = new();
    private readonly ConcurrentDictionary<int, List<ProcessChange>>  _changes = new();
    private readonly ConcurrentDictionary<int, RansomTrack>          _ransom  = new();

    private readonly ConcurrentDictionary<int, RepRecord>            _rep     = new();

    private const int MaxChangesPerProcess = 2000;

    public void SetReputation(int pid, RepRecord rec)
    {
        if (pid <= 0) return;
        _rep[pid] = rec;
        if (_rep.Count > 4096) PruneReputation();
    }

    public ProcRep GetReputation(int pid, string? imagePath)
    {
        if (pid <= 0 || !_rep.TryGetValue(pid, out var r)) return ProcRep.Unknown;
        if (!string.IsNullOrEmpty(imagePath)
            && !string.Equals(r.ImagePath, imagePath, StringComparison.OrdinalIgnoreCase))
            return ProcRep.Unknown;
        try
        {
            var fi = new FileInfo(r.ImagePath);
            if (!fi.Exists || fi.Length != r.Size || fi.LastWriteTimeUtc != r.MtimeUtc)
                return ProcRep.Unknown;
        }
        catch { return ProcRep.Unknown; }
        return r.Kind;
    }

    private void PruneReputation()
    {
        foreach (var pid in _rep.Keys)
            if (!_procs.ContainsKey(pid)) _rep.TryRemove(pid, out _);
    }

    public void Register(int pid, int parentPid, string name, string imagePath, string cmdLine)
    {
        bool reused = _procs.TryGetValue(pid, out var existing)
                   && existing.ImagePath.Length > 0 && imagePath.Length > 0
                   && !string.Equals(existing.ImagePath, imagePath, StringComparison.OrdinalIgnoreCase);

        var info = new ProcessInfo(pid, parentPid, name, imagePath, cmdLine, DateTimeOffset.UtcNow);

        if (existing == null)
        {
            _exited.TryRemove(pid, out _);
            _procs[pid] = info;
            _changes[pid] = new List<ProcessChange>();
        }
        else if (reused)
        {
            _procs[pid]   = info;
            _changes[pid] = new List<ProcessChange>();
            _ransom.TryRemove(pid, out _);
            _rep.TryRemove(pid, out _);
        }
        else
        {
            var merged = existing;
            if (string.IsNullOrEmpty(existing.ImagePath) && !string.IsNullOrEmpty(imagePath))
                merged = info;
            else if (string.IsNullOrEmpty(existing.CommandLine) && !string.IsNullOrEmpty(cmdLine))
                merged = existing with { CommandLine = cmdLine, ParentPid = parentPid };
            _procs[pid] = merged;
            _changes.TryAdd(pid, new List<ProcessChange>());
        }
    }

    public void Unregister(int pid)
    {
        _exited[pid] = DateTimeOffset.UtcNow;
        MaybeSweep();
    }

    private static readonly TimeSpan ExitedTtl = TimeSpan.FromMinutes(5);

    private const int MaxTracked = 6000;

    private readonly ConcurrentDictionary<int, DateTimeOffset> _exited = new();
    private DateTimeOffset _lastSweep = DateTimeOffset.MinValue;

    private void MaybeSweep()
    {
        var now = DateTimeOffset.UtcNow;
        bool nadSufit = _procs.Count > MaxTracked;
        if (!nadSufit && now - _lastSweep < TimeSpan.FromSeconds(30)) return;
        _lastSweep = now;

        foreach (var kv in _exited)
        {
            if (now - kv.Value <= ExitedTtl) continue;
            Forget(kv.Key);
        }

        if (_procs.Count > MaxTracked)
        {
            foreach (var kv in _exited.OrderBy(k => k.Value).Take(_procs.Count - MaxTracked))
                Forget(kv.Key);
        }
    }

    private void Forget(int pid)
    {
        _exited.TryRemove(pid, out _);
        _procs.TryRemove(pid, out _);
        _changes.TryRemove(pid, out _);
        _ransom.TryRemove(pid, out _);
        _rep.TryRemove(pid, out _);
    }

    public (int Tracked, int Exited) MemoryStats => (_procs.Count, _exited.Count);

    public void RecordFileOp(int pid, ChangeKind kind, string path)
    {
        Add(pid, new ProcessChange(pid, kind, path, null, false, DateTimeOffset.UtcNow));

        var track = _ransom.GetOrAdd(pid, _ => new RansomTrack());
        if (kind is ChangeKind.FileCreate)
            track.NoteCreated(path);
        else if (kind is ChangeKind.FileModify or ChangeKind.FileDelete)
            track.Add(path);
    }

    public void RecordRegistryOp(int pid, ChangeKind kind, string keyPath,
        string? valueName, bool isAutostart)
        => Add(pid, new ProcessChange(pid, kind, keyPath, valueName, isAutostart, DateTimeOffset.UtcNow));

    public void RecordServiceOp(int pid, string serviceName)
        => Add(pid, new ProcessChange(pid, ChangeKind.ServiceCreate, serviceName, null, false, DateTimeOffset.UtcNow));

    public void RecordScheduledTask(int pid, string taskName)
        => Add(pid, new ProcessChange(pid, ChangeKind.ScheduledTask, taskName, null, false, DateTimeOffset.UtcNow));

    private void Add(int pid, ProcessChange change)
    {
        if (!_changes.TryGetValue(pid, out var list)) return;
        lock (list)
        {
            if (list.Count >= MaxChangesPerProcess) return;
            list.Add(change);
        }
    }

    public ProcessInfo? GetProcess(int pid)
    {
        _procs.TryGetValue(pid, out var info);
        return info;
    }

    public IReadOnlyList<ProcessChange> GetChanges(int pid)
    {
        if (!_changes.TryGetValue(pid, out var list)) return [];
        lock (list) return list.ToArray();
    }

    public bool HasAutostartChanges(int pid)
    {
        if (!_changes.TryGetValue(pid, out var list)) return false;
        lock (list) return list.Any(c => c.IsAutostart);
    }

    public IEnumerable<ProcessInfo> AllProcesses => _procs.Values;

    public IReadOnlyList<int> FindProcessesTouchingFile(string path)
    {
        if (string.IsNullOrEmpty(path)) return [];
        var hits = new List<(int pid, DateTimeOffset ts)>();
        foreach (var kv in _changes)
        {
            ProcessChange[] snap;
            lock (kv.Value) snap = kv.Value.ToArray();
            DateTimeOffset best = default; bool found = false;
            foreach (var ch in snap)
            {
                if ((ch.Kind is ChangeKind.FileCreate or ChangeKind.FileModify)
                    && string.Equals(ch.Location, path, StringComparison.OrdinalIgnoreCase))
                { if (!found || ch.Timestamp > best) best = ch.Timestamp; found = true; }
            }
            if (found) hits.Add((kv.Key, best));
        }
        return hits.OrderByDescending(h => h.ts).Select(h => h.pid).ToList();
    }

    public int RansomwareScore(int pid, int windowMs)
        => _ransom.TryGetValue(pid, out var t) ? t.CountWithin(windowMs) : 0;

    public IEnumerable<ProcessInfo> GetChildren(int pid)
        => _procs.Values.Where(p => p.ParentPid == pid && p.Pid != pid);

    public IReadOnlyList<int> GetProcessTree(int pid)
    {
        var result = new HashSet<int>();
        CollectTree(pid, result);
        return result.ToArray();
    }

    private void CollectTree(int pid, HashSet<int> visited)
    {
        foreach (var child in GetChildren(pid))
            if (visited.Add(child.Pid))
                CollectTree(child.Pid, visited);
    }

    public bool IsAncestor(int ancestorPid, int childPid)
    {
        var seen = new HashSet<int>();
        int current = childPid;
        while (_procs.TryGetValue(current, out var info))
        {
            if (info.ParentPid == ancestorPid) return true;
            if (!seen.Add(info.ParentPid)) break;
            current = info.ParentPid;
        }
        return false;
    }

    private sealed class RansomTrack
    {
        private const int MaxOwnPaths = 8000;

        private readonly object _lock = new();
        private readonly Queue<(long ms, string path)> _q = new();

        private readonly HashSet<string> _own = new(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<string> _ownOrder = new();

        public void NoteCreated(string path)
        {
            lock (_lock)
            {
                if (_own.Add(path)) _ownOrder.Enqueue(path);
                while (_ownOrder.Count > MaxOwnPaths) _own.Remove(_ownOrder.Dequeue());
            }
        }

        public void Add(string path)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            lock (_lock)
            {
                if (_own.Contains(path)) return;
                _q.Enqueue((now, path));

                while (_q.Count > 500) _q.Dequeue();
            }
        }

        public int CountWithin(int windowMs)
        {
            long cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - windowMs;
            lock (_lock)
            {
                return _q.Where(e => e.ms >= cutoff)
                         .Select(e => e.path)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .Count();
            }
        }
    }
}
