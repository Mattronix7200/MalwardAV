using System.Diagnostics;
using System.Text.Json;

namespace Malward.ResidentShield;

public sealed class RemovableScanWatcher : IDisposable
{
    private readonly string _malscanPath;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(4);

    public RemovableScanWatcher(string malscanPath) => _malscanPath = malscanPath;

    public void Start()
    {
        foreach (var d in EnumerateRemovableReady()) _seen.Add(d);
        _timer = new Timer(_ => Tick(), null, PollInterval, PollInterval);
        Log.Info("Removable", $"Watcher starting (baseline: {_seen.Count} volumes).");
    }

    public void Stop()
    {
        try { _timer?.Dispose(); } catch { }
        _timer = null;
    }

    private void Tick()
    {
        try
        {
            var current = EnumerateRemovableReady();
            foreach (var root in current)
            {
                if (_seen.Add(root))
                {
                    _ = Task.Run(() => RunMalscan(root));
                }
            }

            _seen.RemoveWhere(x => !current.Contains(x));
        }
        catch (Exception ex) { Log.Warn("Removable", $"tick error: {ex.Message}"); }
    }

    private static HashSet<string> EnumerateRemovableReady()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Removable) continue;
                    if (!d.IsReady) continue;
                    set.Add(d.RootDirectory.FullName);
                }
                catch { }
            }
        }
        catch { }
        return set;
    }

    private static readonly string EventsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-events.jsonl");

    private void RunMalscan(string root)
    {
        try
        {
            Log.Info("Removable", $"Scanning newly attached medium: {root}");
            EmitEvent("removable.started", root, detection: null, threats: 0);

            int threats = 0;
            string? firstDetection = null;
            DateTime lastProgressEmit = DateTime.MinValue;

            var files = SafeEnumerate(root);
            int total = files.Count, done = 0;

            foreach (var file in files)
            {
                var detection = Malward.NetworkScanner.SharedScanPipeline.ScanFile(file);
                done++;

                if (!string.IsNullOrEmpty(detection))
                {
                    threats++;
                    firstDetection ??= detection;
                    Log.Alert("Removable", $"DETECTION {detection}: {file}");
                }

                if ((DateTime.UtcNow - lastProgressEmit).TotalMilliseconds >= 250)
                {
                    lastProgressEmit = DateTime.UtcNow;
                    int pct = total > 0 ? (int)(100L * done / total) : 0;
                    EmitProgress(root, pct.ToString(), done.ToString(), total.ToString(), file);
                }
            }

            Log.Info("Removable", $"Scan of {root} finished (files: {done}, threats: {threats}).");
            EmitEvent("removable.finished", root, firstDetection, threats);
        }
        catch (Exception ex)
        {
            Log.Warn("Removable", $"malscan {root} failed: {ex.Message}");
            EmitEvent("removable.finished", root, null, 0);
        }
    }

    private static List<string> SafeEnumerate(string root)
    {
        try
        {
            return new List<string>(Directory.EnumerateFiles(root, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            }));
        }
        catch (Exception ex)
        {
            Log.Warn("Removable", $"Failed to enumerate {root}: {ex.Message}");
            return new List<string>();
        }
    }

    private static string? ExtractField(string line, string key)
    {
        int idx = line.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0) return null;
        int start = idx + key.Length;
        int end = line.IndexOf('\t', start);
        return end < 0 ? line[start..] : line[start..end];
    }

    private static void EmitEvent(string type, string root, string? detection, int threats)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(EventsFile)!);
            var json = JsonSerializer.Serialize(new
            {
                ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                type, root, detection, threats,
            });
            File.AppendAllText(EventsFile, json + Environment.NewLine);
        }
        catch { }
    }

    private static void EmitProgress(string root, string? pct, string? done, string? total, string? file)
    {
        try
        {
            int.TryParse(pct?.Replace(',', '.').Split('.')[0], out int pctI);
            int.TryParse(done, out int doneI);
            int.TryParse(total, out int totalI);
            Directory.CreateDirectory(Path.GetDirectoryName(EventsFile)!);
            var json = JsonSerializer.Serialize(new
            {
                ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                type = "removable.progress",
                root, pct = pctI, done = doneI, total = totalI, file = file ?? "",
            });
            File.AppendAllText(EventsFile, json + Environment.NewLine);
        }
        catch { }
    }

    public void Dispose() => Stop();
}
