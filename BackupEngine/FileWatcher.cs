using System.Collections.Concurrent;

namespace Malward.BackupEngine;

internal sealed class FileWatcher : IDisposable
{
    private readonly BackupConfig _config;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _lastBackup = new(StringComparer.OrdinalIgnoreCase);

    public FileWatcher(BackupConfig config) { _config = config; }

    public static List<string> ExpandWatchFolders(IEnumerable<string> raw)
    {
        var result = new List<string>();
        bool runningAsSystem = IsRunningAsLocalSystem();
        foreach (var rawFolder in raw)
        {
            if (string.IsNullOrEmpty(rawFolder)) continue;

            if (runningAsSystem && rawFolder.Contains("%USERPROFILE%", StringComparison.OrdinalIgnoreCase))
            {
                string suffix = rawFolder.Replace("%USERPROFILE%", "", StringComparison.OrdinalIgnoreCase);
                var users = GetUserProfiles();
                foreach (var userHome in users)
                {
                    var full = Path.Combine(userHome, suffix.TrimStart('\\', '/'));
                    result.Add(full);
                }
            }
            else
            {
                result.Add(Environment.ExpandEnvironmentVariables(rawFolder));
            }
        }
        return result;
    }

    private static bool IsRunningAsLocalSystem()
    {
        try
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            return sid != null && sid.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid);
        }
        catch { return false; }
    }

    private static List<string> GetUserProfiles()
    {
        var profiles = new List<string>();
        try
        {
            var usersDir = @"C:\Users";
            if (!Directory.Exists(usersDir)) return profiles;

            var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Default", "Default User", "Public", "All Users",
                "DefaultAppPool", "WDAGUtilityAccount",
            };
            foreach (var dir in Directory.EnumerateDirectories(usersDir))
            {
                var name = Path.GetFileName(dir);
                if (skip.Contains(name)) continue;
                if (name.StartsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                profiles.Add(dir);
            }
        }
        catch { }
        return profiles;
    }

    public void Start()
    {
        foreach (var folder in ExpandWatchFolders(_config.WatchFolders))
        {
            if (!Directory.Exists(folder))
            {
                Log.Warn("FsWatch", $"Folder missing, skip: {folder}");
                continue;
            }
            try
            {
                var fsw = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,

                    InternalBufferSize = 64 * 1024,
                };
                var thisFolder = folder;
                fsw.Created  += (_, e) => OnEvent(e.FullPath);
                fsw.Changed  += (_, e) => OnEvent(e.FullPath);
                fsw.Renamed  += (_, e) => OnEvent(e.FullPath);

                fsw.Error    += (s, e) =>
                {
                    Log.Warn("FsWatch", $"FSW error {thisFolder}: {e.GetException().Message}");
                    try { if (s is FileSystemWatcher w) w.EnableRaisingEvents = true; } catch { }
                };
                fsw.EnableRaisingEvents = true;
                _watchers.Add(fsw);
                Log.Info("FsWatch", $"Watching {folder}");
            }
            catch (Exception ex)
            {
                Log.Warn("FsWatch", $"Failed to create FSW for {folder}: {ex.Message}");
            }
        }
    }

    private void OnEvent(string fullPath)
    {
        try { if (Directory.Exists(fullPath)) return; } catch { }
        if (IsExcluded(fullPath)) return;

        if (_lastBackup.TryGetValue(fullPath, out var when) &&
            (DateTime.UtcNow - when).TotalMinutes < _config.PerFileRateMin)
            return;

        _pending[fullPath] = DateTime.UtcNow.AddSeconds(_config.DebounceSeconds);
    }

    public List<string> DrainReady()
    {
        var now = DateTime.UtcNow;
        var ready = new List<string>();
        foreach (var kv in _pending)
        {
            if (kv.Value <= now) ready.Add(kv.Key);
        }
        foreach (var p in ready) _pending.TryRemove(p, out _);
        return ready;
    }

    public void MarkBackupDone(string path)
    {
        _lastBackup[path] = DateTime.UtcNow;

        if (_lastBackup.Count > 10_000)
        {
            var cutoff = DateTime.UtcNow.AddDays(-1);
            foreach (var kv in _lastBackup)
                if (kv.Value < cutoff) _lastBackup.TryRemove(kv.Key, out _);
        }
    }

    private bool IsExcluded(string fullPath)
    {
        var p = fullPath.Replace('\\', '/');
        foreach (var raw in _config.ExcludeGlobs)
        {
            if (GlobMatch(raw, p)) return true;
        }
        try
        {
            var size = new FileInfo(fullPath).Length;
            if (size > (long)_config.MaxFileSizeMb * 1024 * 1024) return true;
        }
        catch { }
        return false;
    }

    private static bool GlobMatch(string pattern, string path)
    {
        pattern = pattern.Replace('\\', '/');

        if (pattern.Contains("**"))
        {
            var prefix = pattern.Substring(0, pattern.IndexOf("**"));
            return path.IndexOf(prefix, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        var rx = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
                              .Replace("\\*", "[^/]*")
                              .Replace("\\?", "[^/]") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(path,
            rx, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
    }
}
