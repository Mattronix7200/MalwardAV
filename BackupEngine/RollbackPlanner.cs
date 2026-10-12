namespace Malward.BackupEngine;

internal sealed class RollbackPlanner
{
    private readonly BkfFile _bkf;
    private readonly VolumeShadowCopy _vss;

    public RollbackPlanner(BkfFile bkf)
    {
        _bkf = bkf;
        _vss = new VolumeShadowCopy();
    }

    public RollbackReport Execute(IEnumerable<string> paths, DateTimeOffset since)
    {
        var pathSet = new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
        if (pathSet.Count == 0) return new RollbackReport();
        var cutoffMs = since.ToUnixTimeMilliseconds();
        var report = new RollbackReport();

        var preCutoffSnapshots = _bkf.Index
            .Where(e => e.Timestamp <= cutoffMs)
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        var remaining = new HashSet<string>(pathSet, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in preCutoffSnapshots)
        {
            if (remaining.Count == 0) break;
            SnapshotView snap;
            try { snap = _bkf.ReadSnapshot(entry.SnapId); }
            catch (Exception ex) { Log.Warn("Rollback", $"Snapshot {entry.SnapId} skip: {ex.Message}"); continue; }

            foreach (var f in snap.Files)
            {
                if (!remaining.Contains(f.Path)) continue;
                try
                {
                    var content = _bkf.ReadFileContent(snap, f);
                    Directory.CreateDirectory(Path.GetDirectoryName(f.Path)!);
                    File.WriteAllBytes(f.Path, content);
                    File.SetLastWriteTimeUtc(f.Path,
                        DateTimeOffset.FromUnixTimeMilliseconds(f.MtimeMs).UtcDateTime);
                    report.FromBkf++;
                    report.Restored++;
                    remaining.Remove(f.Path);
                }
                catch (Exception ex)
                {
                    Log.Warn("Rollback", $"BKF restore {f.Path}: {ex.Message}");
                    report.Failed++;
                }
            }
        }

        if (remaining.Count > 0)
        {
            var cutoffUtc = since.UtcDateTime;
            foreach (var path in remaining.ToList())
            {
                var shadow = _vss.FindShadowBefore(path, cutoffUtc);
                if (shadow == null)
                {
                    Log.Debug("Rollback", $"VSS: no shadow from before {cutoffUtc:HH:mm} for {path}");
                    report.Failed++;
                    continue;
                }
                if (_vss.RestoreFromShadow(shadow, path, path))
                {
                    report.FromVss++;
                    report.Restored++;
                    remaining.Remove(path);
                }
                else
                {
                    report.Failed++;
                }
            }
        }

        Log.Info("Rollback", $"Plan executed: restored={report.Restored} " +
                             $"(BKF={report.FromBkf}, VSS={report.FromVss}), failed={report.Failed}");
        return report;
    }
}

public sealed class RollbackReport
{
    public int Restored { get; set; }
    public int Failed { get; set; }
    public int FromBkf { get; set; }
    public int FromVss { get; set; }
}
