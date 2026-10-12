using System.IO;

namespace Malward.ResidentShield;

public sealed class FileWatcher : IDisposable
{
    private readonly ShieldConfig            _config;
    private readonly Action<ScanEvent>       _callback;
    private readonly List<FileSystemWatcher> _watchers = new();

    private readonly HashSet<string> _skipVolumes;

    private HashSet<string> _watchedSet = new(StringComparer.OrdinalIgnoreCase);
    private volatile bool _disposed = false;

    public FileWatcher(ShieldConfig config, Action<ScanEvent> callback,
        HashSet<string>? skipVolumes = null)
    {
        _config      = config;
        _callback    = callback;
        _skipVolumes = skipVolumes ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    public void ApplySettings()
    {
        _watchedSet = new HashSet<string>(_config.WatchedExtensions, StringComparer.OrdinalIgnoreCase);
    }

    public void Start()
    {
        _watchedSet = new HashSet<string>(_config.WatchedExtensions, StringComparer.OrdinalIgnoreCase);

        Log.Info("FSW", _config.ScanAllExtensions
            ? "Mode: ALL extensions are scanned"
            : $"Monitored extensions: {_watchedSet.Count}");

        var drives = DriveInfo.GetDrives()
            .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable);

        int watched = 0;
        foreach (var drive in drives)
        {
            try
            {
                if (!drive.IsReady) continue;
                string letter = drive.Name.TrimEnd('\\');
                if (_skipVolumes.Contains(letter)) continue;

                var w = CreateWatcher(drive.RootDirectory.FullName);
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
                watched++;
                Log.Info("FSW", $"Watching (fallback): {drive.RootDirectory.FullName} [{drive.DriveFormat}]");
            }
            catch (Exception ex)
            {
                Log.Error("FSW", $"Initialization error for {drive.Name}: {ex.Message}");
            }
        }

        if (watched == 0)
            Log.Info("FSW", "No volumes for FSW (all are handled by USN).");
    }

    private FileSystemWatcher CreateWatcher(string path)
    {
        var w = new FileSystemWatcher(path)
        {
            IncludeSubdirectories = true,
            EnableRaisingEvents   = false,

            NotifyFilter          = NotifyFilters.FileName,
            InternalBufferSize    = 64 * 1024,
        };

        w.Created += OnFile;
        w.Renamed += OnRenamed;
        w.Error   += OnError;

        return w;
    }

    public void Stop()
    {
        foreach (var w in _watchers) w.EnableRaisingEvents = false;
    }

    private void OnFile(object _, FileSystemEventArgs e)
    {
        if (!_config.FileMonitorEnabled) return;
        if (!PassesFilter(e.FullPath)) return;

        var kind = e.ChangeType == WatcherChangeTypes.Created
            ? ScanEventKind.FileCreated
            : ScanEventKind.FileModified;

        Dispatch(kind, e.FullPath);
    }

    private void OnRenamed(object _, RenamedEventArgs e)
    {
        if (!_config.FileMonitorEnabled) return;
        if (!PassesFilter(e.FullPath)) return;
        Dispatch(ScanEventKind.FileCreated, e.FullPath);
    }

    private bool PassesFilter(string fullPath)
    {
        if (!_config.ScanAllExtensions)
        {
            var ext = Path.GetExtension(fullPath);
            if (string.IsNullOrEmpty(ext) || !_watchedSet.Contains(ext))
                return false;
        }

        var excl = _config.ExcludedPaths;
        for (int i = 0; i < excl.Count; i++)
            if (fullPath.StartsWith(excl[i], StringComparison.OrdinalIgnoreCase))
                return false;

        return true;
    }

    private void Dispatch(ScanEventKind kind, string path)
    {
        try
        {
            _callback(new ScanEvent(kind, path, null, null, DateTimeOffset.UtcNow));
        }
        catch (Exception ex)
        {
            Log.Error("FSW", $"Callback error: {ex.Message}");
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        Log.Warn("FSW", $"Buffer overflow — restarting watcher: {e.GetException().Message}");

        if (sender is not FileSystemWatcher w) return;

        Task.Run(async () =>
        {
            try
            {
                w.EnableRaisingEvents = false;
                await Task.Delay(1_000);
                if (_disposed) return;
                w.EnableRaisingEvents = true;
                Log.Info("FSW", $"Watcher restarted: {w.Path}");
            }
            catch (Exception ex)
            {
                Log.Error("FSW", $"Watcher restart error ({w.Path}): {ex.Message}");
            }
        });
    }

    public void Dispose()
    {
        _disposed = true;
        Stop();
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
    }
}
