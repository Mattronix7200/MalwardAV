using System.Text.RegularExpressions;

namespace Malward.BackupEngine;

public sealed class BackupRunner : IDisposable
{
    private readonly BackupConfig _config;
    private readonly CryptoEnvelope _crypto;
    private BkfFile? _bkf;

    public BackupRunner(BackupConfig config)
    {
        _config = config;
        _crypto = CryptoEnvelope.LoadOrCreate();
    }

    private BkfFile Bkf(bool readOnly = false)
    {
        if (_bkf == null)
        {
            _bkf = new BkfFile(_config.ResolvedBkfPath(), _crypto);
            _bkf.Open(readOnly);
        }
        return _bkf;
    }

    private bool BkfExists() => File.Exists(_config.ResolvedBkfPath());

    public Guid DoBackup(BkfFormat.Trigger trigger)
        => DoBackup(trigger, null, CancellationToken.None);

    public Guid DoBackup(BkfFormat.Trigger trigger, Action<BackupProgress>? onProgress,
                         CancellationToken ct)
    {
        var bkf = Bkf();
        if (!EnsureDiskRoom(bkf)) return Guid.Empty;
        long maxBytes = (long)_config.MaxFileSizeMb * 1024 * 1024;

        var plan = Survey(maxBytes);

        var snapId = bkf.AppendSnapshotStreaming(
            plan.Paths,
            trigger,
            maxFileSizeBytes: (int)Math.Min(maxBytes, int.MaxValue),
            excludeFilter: IsExcluded,
            compression: _config.ResolvedCompression(),
            onProgress: onProgress,
            totalFiles: plan.Paths.Count,
            totalBytes: plan.Bytes,
            ct: ct);
        if (snapId != Guid.Empty) EnforceBackupSizeLimit(bkf);
        return snapId;
    }

    public sealed record BackupPlan(List<string> Paths, long Bytes);

    public BackupPlan Survey(long maxFileBytes)
    {
        var paths = new List<string>();
        long bytes = 0;
        foreach (var path in EnumerateWatchPaths())
        {
            if (IsExcluded(path)) continue;
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > maxFileBytes) continue;
                paths.Add(path);
                bytes += info.Length;
            }
            catch { }
        }
        return new BackupPlan(paths, bytes);
    }

    public object EstimateObject()
    {
        long maxBytes = (long)_config.MaxFileSizeMb * 1024 * 1024;
        var plan = Survey(maxBytes);

        if (plan.Bytes == 0)
            return new { files = plan.Paths.Count, bytes = 0L, rate_bps = 0L, eta_sec = 0L };

        double rate = MeasureReadRate(plan.Paths);
        double etaSec = rate > 1 ? plan.Bytes / rate : -1;

        return new
        {
            files = plan.Paths.Count,
            bytes = plan.Bytes,
            rate_bps = (long)rate,
            eta_sec = etaSec < 0 ? -1 : (long)Math.Ceiling(etaSec),
        };
    }

    private static double MeasureReadRate(List<string> paths)
    {
        if (paths.Count == 0) return 0;

        const int ProbeBudgetMs = 1500;
        const long ProbeCap = 64L * 1024 * 1024;

        var buf = new byte[256 * 1024];
        long read = 0;
        var clock = System.Diagnostics.Stopwatch.StartNew();

        int step = Math.Max(1, paths.Count / 24);
        for (int i = 0; i < paths.Count && read < ProbeCap && clock.ElapsedMilliseconds < ProbeBudgetMs; i += step)
        {
            try
            {
                using var fs = new FileStream(paths[i], FileMode.Open, FileAccess.Read, FileShare.Read,
                                              buf.Length, FileOptions.SequentialScan);
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    read += n;
                    if (read >= ProbeCap || clock.ElapsedMilliseconds >= ProbeBudgetMs) break;
                }
            }
            catch { }
        }

        clock.Stop();
        if (read < 64 * 1024 || clock.Elapsed.TotalSeconds < 0.002) return 0;

        double raw = Math.Min(read / clock.Elapsed.TotalSeconds, RateCeilingBps);
        return raw * PipelineFactor;
    }

    private const double RateCeilingBps = 600.0 * 1024 * 1024;

    private const double PipelineFactor = 0.6;

    public Guid DoBackupPaths(IEnumerable<string> paths, BkfFormat.Trigger trigger)
    {
        var bkf = Bkf();
        if (!EnsureDiskRoom(bkf)) return Guid.Empty;
        long maxBytes = (long)_config.MaxFileSizeMb * 1024 * 1024;
        var id = bkf.AppendSnapshotStreaming(
            paths, trigger,
            maxFileSizeBytes: (int)Math.Min(maxBytes, int.MaxValue),
            excludeFilter: IsExcluded,
            compression: _config.ResolvedCompression());
        EnforceBackupSizeLimit(bkf);
        return id;
    }

    private static long FreeSpace(string path)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            return string.IsNullOrEmpty(root) ? -1 : new DriveInfo(root).AvailableFreeSpace;
        }
        catch { return -1; }
    }

    private static Guid OldestSnap(BkfFile bkf)
    {
        Guid id = Guid.Empty; long best = long.MaxValue;
        foreach (var e in bkf.Index)
            if (e.Timestamp < best) { best = e.Timestamp; id = e.SnapId; }
        return id;
    }

    private void EnforceBackupSizeLimit(BkfFile bkf)
    {
        int pct = _config.BackupSizeLimitPercent;
        if (pct <= 0) return;
        long free = FreeSpace(bkf.Path);
        if (free < 0) return;

        long cap = (long)((free + bkf.FileSize) * (pct / 100.0));
        if (bkf.FileSize <= cap) return;

        long target = (long)(cap * 0.9);
        int guard = 0;
        while (bkf.FileSize > target && bkf.SnapshotCount > 1 && guard++ < 100000)
        {
            var oldest = OldestSnap(bkf);
            if (oldest == Guid.Empty || !bkf.DeleteSnapshot(oldest)) break;
            Log.Info("Runner", $"backup-limit: removed oldest restore point {oldest} (cap={cap}B, size={bkf.FileSize}B)");
        }
    }

    private bool EnsureDiskRoom(BkfFile bkf)
    {
        const long FLOOR = 256L * 1024 * 1024;
        long free = FreeSpace(bkf.Path);
        if (free < 0 || free >= FLOOR) return true;
        int guard = 0;
        while (free < FLOOR && bkf.SnapshotCount > 0 && guard++ < 100000)
        {
            var oldest = OldestSnap(bkf);
            if (oldest == Guid.Empty || !bkf.DeleteSnapshot(oldest)) break;
            free = FreeSpace(bkf.Path);
            Log.Warn("Runner", $"low disk space — removed oldest restore point {oldest}, free={free}B");
        }
        if (free < FLOOR) { Log.Warn("Runner", $"backup skipped — not enough disk space ({free}B < {FLOOR}B)"); return false; }
        return true;
    }

    public object StatusObject()
    {
        if (!BkfExists())
        {
            return new
            {
                bkf_path = _config.ResolvedBkfPath(),
                bkf_size = 0L,
                snap_count = 0,
                schedule = _config.Schedule,
                schedule_normalized = _config.NormalizedSchedule(),
                next_fire = ScheduleCalc.NextFire(_config.NormalizedSchedule()).ToString("yyyy-MM-dd HH:mm:ss"),
                compression_mode = _config.CompressionMode,
                watch_folders = _config.WatchFolders,
                on_file_change = _config.OnFileChange,
                degraded = false,
                last_error = (string?)null,
            };
        }
        var bkf = Bkf(readOnly: true);
        return new
        {
            bkf_path = bkf.Path,
            bkf_size = bkf.FileSize,
            snap_count = bkf.SnapshotCount,
            schedule = _config.Schedule,
            schedule_normalized = _config.NormalizedSchedule(),
            next_fire = ScheduleCalc.NextFire(_config.NormalizedSchedule()).ToString("yyyy-MM-dd HH:mm:ss"),
            compression_mode = _config.CompressionMode,
            watch_folders = _config.WatchFolders,
            on_file_change = _config.OnFileChange,
            degraded = false,
            last_error = (string?)null,
        };
    }

    public object[] ListObject()
        => (BkfExists() ? Bkf(readOnly: true).Index : (IReadOnlyList<BkfFormat.IndexEntry>)Array.Empty<BkfFormat.IndexEntry>())
        .Select(e => new
        {
            snap_id = e.SnapId.ToString(),
            timestamp = e.Timestamp,
            size = e.Size,
            trigger = (int)e.Trig,
            trigger_name = e.Trig.ToString(),
        }).ToArray();

    public object[] FilesObject(Guid snapId)
    {
        var snap = Bkf(readOnly: true).ReadSnapshot(snapId);
        return snap.Files.Select(f => new
        {
            path = f.Path,
            size = f.Size,
            mtime = f.MtimeMs,
            sha256 = Convert.ToHexString(f.Sha256),
        }).ToArray();
    }

    public (int Restored, int Failed) Restore(Guid snapId, IReadOnlyCollection<string>? paths, string? target)
    {
        var bkf = Bkf(readOnly: true);
        var snap = bkf.ReadSnapshot(snapId);
        var set = paths != null && paths.Count > 0
            ? new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase) : null;
        int restored = 0, failed = 0;
        foreach (var f in snap.Files)
        {
            if (set != null && !set.Contains(f.Path)) continue;
            try
            {
                var content = bkf.ReadFileContent(snap, f);
                var dest = string.IsNullOrEmpty(target)
                    ? f.Path
                    : Path.Combine(target!, Path.GetFileName(f.Path));
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.WriteAllBytes(dest, content);
                try { File.SetLastWriteTimeUtc(dest, DateTimeOffset.FromUnixTimeMilliseconds(f.MtimeMs).UtcDateTime); } catch { }
                restored++;
            }
            catch (Exception ex) { Log.Warn("Restore", $"{f.Path}: {ex.Message}"); failed++; }
        }
        return (restored, failed);
    }

    public bool Delete(Guid snapId) => Bkf().DeleteSnapshot(snapId);

    public void Export(Guid snapId, string outPath) => Bkf(readOnly: true).ExportSnapshot(snapId, outPath);

    public int Import(string inPath) => Bkf().ImportFromFile(inPath);

    public RollbackReport Rollback(IReadOnlyCollection<string> paths, DateTimeOffset since)
        => new RollbackPlanner(Bkf(readOnly: true)).Execute(paths, since);

    private IEnumerable<string> EnumerateWatchPaths()
    {
        var expanded = FileWatcher.ExpandWatchFolders(_config.WatchFolders);
        foreach (var folder in expanded)
        {
            if (!Directory.Exists(folder)) { Log.Debug("Runner", $"Folder missing: {folder}"); continue; }
            Log.Info("Runner", $"Scanning folder: {folder}");
            var enumOpts = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Hidden | FileAttributes.System,
            };
            IEnumerator<string>? it = null;
            try { it = Directory.EnumerateFiles(folder, "*", enumOpts).GetEnumerator(); }
            catch (Exception ex) { Log.Warn("Runner", $"enum {folder}: {ex.Message}"); continue; }
            using (it)
            {
                while (true)
                {
                    string? p = null;
                    try { if (!it.MoveNext()) break; p = it.Current; }
                    catch (Exception ex) { Log.Debug("Runner", $"enum step: {ex.Message}"); continue; }
                    if (p != null) yield return p;
                }
            }
        }
    }

    private bool IsExcluded(string fullPath)
    {
        var p = fullPath.Replace('\\', '/');
        foreach (var raw in _config.ExcludeGlobs)
        {
            var pattern = raw.Replace('\\', '/');
            if (pattern.Contains("**"))
            {
                var prefix = pattern[..pattern.IndexOf("**", StringComparison.Ordinal)];
                if (p.IndexOf(prefix, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            else
            {
                var rx = "^" + Regex.Escape(pattern).Replace("\\*", "[^/]*").Replace("\\?", "[^/]") + "$";
                if (Regex.IsMatch(p, rx, RegexOptions.IgnoreCase)) return true;
            }
        }
        return false;
    }

    public void Dispose()
    {
        try { _bkf?.Dispose(); } catch { }
        _bkf = null;
        try { _crypto.Dispose(); } catch { }
    }
}
