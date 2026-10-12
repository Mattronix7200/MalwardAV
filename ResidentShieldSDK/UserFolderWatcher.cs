using System.Collections.Concurrent;

namespace Malward.ResidentShield;

/// <summary>Watches the folders a user actually downloads and saves into, and feeds the resident pipeline.</summary>
/// <remarks>
/// The USN journal is the shield's main source of file events, and where it works the per-drive
/// FileSystemWatcher is switched off for that volume. When the journal delivers nothing - no
/// rights to the volume handle, a reader that stalls, a volume that is not NTFS - nothing else
/// notices a file appearing on the disk. This watcher is the belt to that pair of braces: it is
/// always on, it costs four handles, and it covers exactly the places malware lands first.
/// It only reports; every verdict, action and notification stays in the one resident pipeline.
/// </remarks>
public sealed class UserFolderWatcher : IDisposable
{
    private readonly Action<ScanEvent> _callback;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);
    private Thread? _debouncer;
    private volatile bool _running;

    private static readonly TimeSpan Debounce = TimeSpan.FromMilliseconds(1500);

    private static readonly string[] HalfWrittenExts =
    {
        ".crdownload", ".partial", ".part", ".tmp", ".download", ".opdownload",
    };

    private static readonly string[] DefaultFolders =
    {
        "Downloads", "Desktop", "Documents", "Pictures",
    };

    private readonly IReadOnlyList<string>? _explicitFolders;

    public UserFolderWatcher(Action<ScanEvent> callback,
                             IReadOnlyList<string>? folders = null)
    {
        _callback = callback;
        _explicitFolders = folders;
    }

    public int WatchedCount => _watchers.Count;

    public void Start()
    {
        var folders = _explicitFolders is { Count: > 0 }
            ? _explicitFolders.ToList()
            : ResolveFolders();
        if (folders.Count == 0)
        {
            Log.Info("FSW-User", "No user folders to watch");
            return;
        }

        _running = true;
        foreach (var f in folders)
        {
            try
            {
                var w = new FileSystemWatcher(f)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    EnableRaisingEvents = true,
                };
                w.Created += OnFsEvent;
                w.Renamed += OnFsEvent;
                w.Changed += OnFsEvent;
                w.Error += (_, e) => Log.Warn("FSW-User", $"{f}: {e.GetException().Message}");
                _watchers.Add(w);
                Log.Info("FSW-User", $"Watching: {f}");
            }
            catch (Exception ex)
            {
                Log.Warn("FSW-User", $"watcher {f} failed: {ex.Message}");
            }
        }

        if (_watchers.Count == 0) { _running = false; return; }

        _debouncer = new Thread(DebouncerLoop) { IsBackground = true, Name = "FSW-User-Debounce" };
        _debouncer.Start();
    }

    public void Stop()
    {
        _running = false;
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
        try { _debouncer?.Join(2000); } catch { }
    }

    private void OnFsEvent(object sender, FileSystemEventArgs e)
    {
        try
        {
            var name = Path.GetFileName(e.FullPath);
            foreach (var ext in HalfWrittenExts)
                if (name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) return;

            _pending[e.FullPath] = DateTime.UtcNow;
        }
        catch { }
    }

    private void DebouncerLoop()
    {
        while (_running)
        {
            try
            {
                var now = DateTime.UtcNow;
                foreach (var kv in _pending)
                {
                    if (now - kv.Value < Debounce) continue;
                    if (!_pending.TryRemove(kv.Key, out _)) continue;

                    try
                    {
                        if (!File.Exists(kv.Key)) continue;
                        if (SystemGuard.IsOwnComponent(kv.Key)) continue;
                        if (SystemGuard.IsInQuarantine(kv.Key)) continue;
                        _callback(new ScanEvent(ScanEventKind.FileCreated, kv.Key,
                                                null, null, DateTimeOffset.UtcNow));
                    }
                    catch { }
                }
                Thread.Sleep(500);
            }
            catch { }
        }
    }

    private static List<string> ResolveFolders()
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string usersRoot = Path.Combine(
            Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)) ?? @"C:\", "Users");

        try
        {
            if (!Directory.Exists(usersRoot)) return result;

            foreach (var profile in Directory.GetDirectories(usersRoot))
            {
                var name = Path.GetFileName(profile);
                if (name.Equals("Public", StringComparison.OrdinalIgnoreCase)
                 || name.Equals("Default", StringComparison.OrdinalIgnoreCase)
                 || name.Equals("Default User", StringComparison.OrdinalIgnoreCase)
                 || name.Equals("All Users", StringComparison.OrdinalIgnoreCase)) continue;

                foreach (var sub in DefaultFolders)
                {
                    var p = Path.Combine(profile, sub);
                    if (Directory.Exists(p) && seen.Add(p)) result.Add(p);
                }
            }
        }
        catch { }

        return result;
    }

    public void Dispose() => Stop();
}
