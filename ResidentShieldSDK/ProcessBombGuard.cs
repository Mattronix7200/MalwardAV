using System.Collections.Concurrent;
using Malward.Engine.Util;

namespace Malward.ResidentShield;

public sealed class ProcessBombGuard
{
    private const int BurstThreshold = 12;

    private static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(20);

    private const int FreshBuildSeconds = 120;

    private static readonly TimeSpan TaintTtl = TimeSpan.FromMinutes(30);

    private sealed record TaintMark(string Reason, DateTimeOffset When, int RootPid);

    private readonly ConcurrentDictionary<int, TaintMark> _tainted = new();

    private readonly ConcurrentDictionary<string, DateTimeOffset> _taintedPaths =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<int, List<DateTimeOffset>> _spawns = new();

    private readonly ConcurrentDictionary<int, DateTimeOffset> _reported = new();

    private readonly ProcessTracker _tracker;

    public ProcessBombGuard(ProcessTracker tracker) => _tracker = tracker;

    public void MarkThreat(int pid, string? imagePath, string reason)
    {
        var now = DateTimeOffset.UtcNow;
        _tainted[pid] = new TaintMark(reason, now, pid);
        if (!string.IsNullOrWhiteSpace(imagePath))
        {
            _taintedPaths[imagePath] = now;

            try
            {
                var dir = Path.GetDirectoryName(imagePath);
                if (!string.IsNullOrEmpty(dir) && Hips.HipsTrust.InUserWritableArea(dir))
                    _taintedPaths[dir + Path.DirectorySeparatorChar] = now;
            }
            catch { }
        }
        Prune(now);
    }

    public readonly record struct Verdict(bool Block, string? Detection, string? Reason, bool KillLineage)
    {
        public static readonly Verdict Pass = new(false, null, null, false);
    }

    public Verdict Inspect(ProcessInfo proc)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            Prune(now);

            if (SystemGuard.IsOwnComponent(proc.ImagePath)) return Verdict.Pass;
            if (Hips.HipsSelfGuard.IsOwnProcessTree(proc.Pid)) return Verdict.Pass;

            bool zaufany = Hips.HipsTrust.IsTrustedProgram(proc.ImagePath)
                           && !Hips.HipsTrust.InUserWritableArea(proc.ImagePath);

            var (skazony, rootPid, powodRodowodu) = InheritedTaint(proc);

            if (skazony && !zaufany)
            {
                MarkTaint(proc, rootPid, now);
                int tempo = RecordSpawn(rootPid, now);
                bool lawina = tempo >= BurstThreshold;

                return new Verdict(
                    Block: true,
                    Detection: lawina ? "Behaviour.ProcessBomb" : "Behaviour.ThreatSpawn",
                    Reason: lawina
                        ? Loc.F("Lawina procesów tworzonych przez zagrożenie ({0} w {1:F0} s) — {2}", tempo, BurstWindow.TotalSeconds, powodRodowodu)
                        : Loc.F("Proces utworzony przez wykryte wcześniej zagrożenie — {0}", powodRodowodu),
                    KillLineage: lawina);
            }

            if (!zaufany && IsFreshBuild(proc.ImagePath) && Hips.HipsTrust.InUserWritableArea(proc.ImagePath))
            {
                int rodowod = LineageRoot(proc);
                int tempo = RecordSpawn(rodowod, now);
                if (tempo >= BurstThreshold)
                {
                    MarkTaint(proc, rodowod, now);
                    return new Verdict(true, "Behaviour.ProcessBomb",
                        Loc.F("Lawina świeżo zbudowanych programów ({0} w {1:F0} s) uruchamianych z katalogu zapisywalnego przez użytkownika", tempo, BurstWindow.TotalSeconds),
                        KillLineage: true);
                }
            }

            return Verdict.Pass;
        }
        catch { return Verdict.Pass; }
    }

    public Verdict InspectCompiler(ProcessInfo proc)
    {
        try
        {
            var nazwa = Path.GetFileName(proc.ImagePath ?? proc.Name ?? "").ToLowerInvariant();
            var kompilatory = Malward.Engine.Data.SignatureStore.List("onhost_compilers");
            if (kompilatory.Length == 0 || !kompilatory.Contains(nazwa, StringComparer.OrdinalIgnoreCase))
                return Verdict.Pass;

            var rodzic = _tracker.GetProcess(proc.ParentPid);
            if (rodzic == null) return Verdict.Pass;
            if (SystemGuard.IsOwnComponent(rodzic.ImagePath)) return Verdict.Pass;

            if (Hips.HipsTrust.IsTrustedProgram(rodzic.ImagePath)
                && !Hips.HipsTrust.InUserWritableArea(rodzic.ImagePath))
                return Verdict.Pass;

            var (skazony, _, powod) = InheritedTaint(rodzic);
            if (!skazony && !Hips.HipsTrust.InUserWritableArea(rodzic.ImagePath))
                return Verdict.Pass;

            MarkThreat(rodzic.Pid, rodzic.ImagePath, "kompilacja kodu przez niezaufany proces");
            return new Verdict(true, "Behaviour.OnHostBuild",
                skazony
                    ? Loc.F("Wykryte zagrożenie buduje na tym komputerze kolejny program ({0}) — {1}", nazwa, powod)
                    : Loc.F("Niezaufany program z katalogu użytkownika buduje kod na tym komputerze ({0})", nazwa),
                KillLineage: skazony);
        }
        catch { return Verdict.Pass; }
    }

    private (bool Tainted, int RootPid, string Reason) InheritedTaint(ProcessInfo proc)
    {
        if (!string.IsNullOrEmpty(proc.ImagePath))
        {
            if (_taintedPaths.ContainsKey(proc.ImagePath))
                return (true, proc.Pid, Loc.T("program z lokalizacji powiązanej z wykrytym zagrożeniem"));
            try
            {
                var dir = Path.GetDirectoryName(proc.ImagePath);
                if (!string.IsNullOrEmpty(dir)
                    && _taintedPaths.ContainsKey(dir + Path.DirectorySeparatorChar))
                    return (true, proc.Pid, Loc.T("program z katalogu powiązanego z wykrytym zagrożeniem"));
            }
            catch { }
        }

        int pid = proc.ParentPid;
        for (int i = 0; i < 8 && pid > 4; i++)
        {
            if (_tainted.TryGetValue(pid, out var t))
                return (true, t.RootPid, t.Reason);
            var p = _tracker.GetProcess(pid);
            if (p == null) break;
            pid = p.ParentPid;
        }
        return (false, proc.Pid, "");
    }

    private int LineageRoot(ProcessInfo proc)
    {
        int pid = proc.ParentPid, last = proc.Pid;
        for (int i = 0; i < 8 && pid > 4; i++)
        {
            var p = _tracker.GetProcess(pid);
            if (p == null) break;
            last = p.Pid;
            pid = p.ParentPid;
        }
        return last;
    }

    private void MarkTaint(ProcessInfo proc, int rootPid, DateTimeOffset now)
    {
        _tainted[proc.Pid] = new TaintMark(Loc.T("potomek zagrożenia"), now, rootPid);
        if (!string.IsNullOrWhiteSpace(proc.ImagePath))
            _taintedPaths[proc.ImagePath] = now;
    }

    private int RecordSpawn(int rootPid, DateTimeOffset now)
    {
        var lista = _spawns.GetOrAdd(rootPid, _ => new List<DateTimeOffset>());
        lock (lista)
        {
            lista.Add(now);
            lista.RemoveAll(t => now - t > BurstWindow);
            return lista.Count;
        }
    }

    private static bool IsFreshBuild(string? path)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            var fi = new FileInfo(path);
            var wiek = DateTime.UtcNow - fi.CreationTimeUtc;

            return wiek.TotalSeconds < FreshBuildSeconds;
        }
        catch { return false; }
    }

    public bool AlreadyReported(int rootPid)
    {
        var now = DateTimeOffset.UtcNow;
        if (_reported.TryGetValue(rootPid, out var t) && now - t < TimeSpan.FromMinutes(2)) return true;
        _reported[rootPid] = now;
        return false;
    }

    private DateTimeOffset _lastPrune = DateTimeOffset.MinValue;

    private void Prune(DateTimeOffset now)
    {
        if (now - _lastPrune < TimeSpan.FromMinutes(1)) return;
        _lastPrune = now;
        foreach (var kv in _tainted)
            if (now - kv.Value.When > TaintTtl) _tainted.TryRemove(kv.Key, out _);
        foreach (var kv in _taintedPaths)
            if (now - kv.Value > TaintTtl) _taintedPaths.TryRemove(kv.Key, out _);
        foreach (var kv in _spawns)
        {
            lock (kv.Value)
            {
                kv.Value.RemoveAll(t => now - t > BurstWindow);
                if (kv.Value.Count == 0) _spawns.TryRemove(kv.Key, out _);
            }
        }
        foreach (var kv in _reported)
            if (now - kv.Value > TimeSpan.FromMinutes(10)) _reported.TryRemove(kv.Key, out _);
    }

    public (int Tainted, int Paths, int Lineages) Stats =>
        (_tainted.Count, _taintedPaths.Count, _spawns.Count);
}
