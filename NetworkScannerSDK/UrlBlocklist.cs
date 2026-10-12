using System.IO.Compression;
using System.Text;
using System.Threading;

namespace Malward.NetworkScanner;

public sealed class UrlBlocklist : IDisposable
{
    private readonly string[] _candidates;

    private readonly string _watchPattern = "urls*.vdeb";
    private readonly bool _lowMemory;

    private readonly bool _deferred;

    private volatile bool _stale;

    private int _loading;

    private long _nextLoadAttemptTicks;

    private readonly string _datPath;

    private byte[] _blob = Array.Empty<byte>();

    private FileStream? _datFs;

    private int[] _offsets = Array.Empty<int>();
    private long _bodyLength;

    private DateTime _loadedMtime;
    private string?  _loadedPath;
    private readonly object _lock = new();

    private FileSystemWatcher? _watcher;
    private System.Threading.Timer? _debounceReload;
    private DateTime _lastReloadAttempt = DateTime.MinValue;

    public UrlBlocklist(string? explicitPath = null, bool lowMemory = false, bool deferred = false,
                        bool exclusivePath = false)
    {
        _lowMemory = lowMemory;
        _deferred  = deferred;
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "";
        var data = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "urls.vdeb");

        var list = new List<string>();
        if (!string.IsNullOrEmpty(explicitPath)) list.Add(explicitPath);
        if (!exclusivePath || string.IsNullOrEmpty(explicitPath))
        {
            list.Add(data);
            list.Add(Path.Combine(exeDir, "data", "urls.vdeb"));
            list.Add(Path.Combine(exeDir, "_bases", "engine", "urls.vdeb"));
        }
        _candidates = list.ToArray();
        _datPath = _candidates[0] + ".dat";

        _watchPattern = Path.GetFileName(_candidates[0]) is { Length: > 0 } own && exclusivePath
            ? own
            : "urls*.vdeb";

        TryStartWatcher(Path.GetDirectoryName(_candidates[0]) ?? Path.GetDirectoryName(data) ?? "");
    }

    private void TryStartWatcher(string dir)
    {
        try
        {
            if (string.IsNullOrEmpty(dir)) return;
            Directory.CreateDirectory(dir);

            try
            {
                foreach (var f in Directory.EnumerateFiles(dir, _watchPattern + ".tmp"))
                {
                    try { File.Delete(f); Log.Info("UrlDb", $"Cleanup of stale file: {Path.GetFileName(f)}"); }
                    catch { }
                }
            }
            catch { }

            if (!_lowMemory) DeleteSidecar("not needed outside low-memory mode");

            _watcher = new FileSystemWatcher(dir, _watchPattern)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                IncludeSubdirectories = false,
            };
            _watcher.Renamed += (_, e) => DebounceReload($"Renamed {e.Name}");
            _watcher.Changed += (_, e) => DebounceReload($"Changed {e.Name}");
            _watcher.Created += (_, e) => DebounceReload($"Created {e.Name}");
            _watcher.EnableRaisingEvents = true;
            Log.Info("UrlDb", $"Hot-reload watcher active on {dir}\\{_watchPattern}");
        }
        catch (Exception ex)
        {
            Log.Warn("UrlDb", $"FileSystemWatcher init failed: {ex.Message} — reload only via the hourly timer.");
        }
    }

    private void DebounceReload(string reason)
    {
        try
        {
            _debounceReload?.Dispose();
            _debounceReload = new System.Threading.Timer(_ =>
            {
                try
                {
                    if ((DateTime.UtcNow - _lastReloadAttempt).TotalSeconds < 2) return;
                    _lastReloadAttempt = DateTime.UtcNow;
                    if (_deferred)
                    {
                        if (IsLoaded)
                        {
                            _stale = true;
                            Log.Info("UrlDb", $"Deferred mode: database file changed ({reason}) — in-RAM copy marked stale.");
                        }
                        else
                        {
                            Log.Debug("UrlDb", $"Deferred mode: database file changed ({reason}) — not loading, cloud lookups are in charge.");
                        }
                        return;
                    }
                    if (MaybeReload())
                        Log.Info("UrlDb", $"Hot-reload OK ({reason}). Active domains: {DomainCount:N0}.");
                }
                catch (Exception ex) { Log.Warn("UrlDb", $"Hot-reload failed: {ex.Message}"); }
            }, null, 800, System.Threading.Timeout.Infinite);
        }
        catch { }
    }

    public string? ActivePath => Array.Find(_candidates, File.Exists);

    public bool IsLoaded => _offsets.Length > 0;

    public bool HasDatabaseFile => ActivePath != null;

    public int DomainCount => _offsets.Length;
    public string? LoadedPath { get { lock (_lock) return _loadedPath; } }
    public bool LowMemoryMode => _lowMemory;

    public bool DeferredMode => _deferred;

    public bool EnsureLoadedInBackground()
    {
        bool loaded = IsLoaded;
        if (loaded && !_stale) return true;
        if (ActivePath == null) return loaded;
        if (DateTime.UtcNow.Ticks < Interlocked.Read(ref _nextLoadAttemptTicks)) return loaded;

        if (Interlocked.CompareExchange(ref _loading, 1, 0) == 0)
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _stale = false;

                    if (ReloadCore(background: true))
                        Log.Info("UrlDb", $"Deferred database load finished — {DomainCount:N0} domains available for local fallback.");
                }
                catch (Exception ex) { Log.Warn("UrlDb", $"Deferred database load failed: {ex.Message}"); }
                finally
                {
                    Interlocked.Exchange(ref _nextLoadAttemptTicks, DateTime.UtcNow.AddMinutes(1).Ticks);
                    Interlocked.Exchange(ref _loading, 0);
                }
            });
        }
        return loaded;
    }

    public bool MaybeReload()
    {
        if (_deferred)
        {
            if (IsLoaded) _stale = true;
            return false;
        }
        return ReloadCore(background: false);
    }

    private bool ReloadCore(bool background)
    {
        var path = ActivePath;
        if (path == null) return false;
        try
        {
            var mt = File.GetLastWriteTimeUtc(path);
            lock (_lock)
            {
                if (string.Equals(path, _loadedPath, StringComparison.OrdinalIgnoreCase) && mt == _loadedMtime)
                    return false;
            }

            const int prob = 5;
            for (int i = 1; i <= prob; i++)
            {
                try { Load(path, background); return true; }
                catch (IOException) when (i < prob) { Thread.Sleep(400 * i); }
                catch (UnauthorizedAccessException) when (i < prob) { Thread.Sleep(400 * i); }
            }
            return false;
        }
        catch (Exception ex)
        {
            Log.Error("UrlDb", $"Reload {path} failed: {ex.Message}");
            return false;
        }
    }

    private void Load(string path, bool background)
    {
        const int START = 8;
        var mtime = File.GetLastWriteTimeUtc(path);

        if (_lowMemory)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_datPath)!);

            lock (_lock)
            {
                try { _datFs?.Dispose(); } catch { }
                _datFs   = null;
                _offsets = Array.Empty<int>();
            }
            byte[] magic = new byte[4];
            long fileSize;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                                           bufferSize: 64 * 1024, FileOptions.SequentialScan))
            using (var gz = new GZipStream(fs, CompressionMode.Decompress))
            using (var dst = new FileStream(_datPath, FileMode.Create, FileAccess.Write, FileShare.None,
                                            bufferSize: 64 * 1024, FileOptions.WriteThrough))
            {
                int magicLen = ReadFully(gz, magic, 0, 4);
                if (magicLen < 4
                 || magic[0] != (byte)'V' || magic[1] != (byte)'D'
                 || magic[2] != (byte)'E' || magic[3] != (byte)'B')
                    throw new InvalidDataException("Bad magic in urls.vdeb");
                dst.Write(magic, 0, magicLen);

                var buf = new byte[64 * 1024];
                int n;
                while ((n = gz.Read(buf, 0, buf.Length)) > 0) dst.Write(buf, 0, n);
                fileSize = dst.Length;
            }

            var offs = new List<int>(capacity: 1 << 17);
            using (var fs = new FileStream(_datPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                                           bufferSize: 256 * 1024, FileOptions.SequentialScan))
            {
                fs.Position = START;
                int pos = START;
                bool needOffset = true;
                var buf = new byte[256 * 1024];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    for (int i = 0; i < n; i++, pos++)
                    {
                        if (needOffset)
                        {
                            offs.Add(pos);
                            needOffset = false;
                        }
                        if (buf[i] == 0)
                        {
                            needOffset = true;

                            if (i + 1 < n && buf[i + 1] == 0) { i++; pos++; }
                        }
                    }
                }

                if (offs.Count > 0 && offs[^1] >= fileSize) offs.RemoveAt(offs.Count - 1);
            }

            lock (_lock)
            {
                try { _datFs?.Dispose(); } catch { }
                _datFs = new FileStream(_datPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                                       bufferSize: 4096, FileOptions.RandomAccess);
                _blob = Array.Empty<byte>();
                _offsets = offs.ToArray();
                _bodyLength = fileSize - START;
                _loadedMtime = mtime;
                _loadedPath = path;
            }

            if (background)
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Optimized, blocking: false);
            else
            {
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                GC.WaitForPendingFinalizers();
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            }

            Log.Info("UrlDb",
                $"Loaded {offs.Count:N0} domains from {path} " +
                $"(low-memory: blob ON DISK {fileSize / 1024} KB, RAM offsets ≈ {_offsets.Length * 4 / 1024} KB)");
            return;
        }

        byte[] data;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var gz = new GZipStream(fs, CompressionMode.Decompress))
        using (var ms = new MemoryStream())
        {
            gz.CopyTo(ms);
            data = ms.ToArray();
        }
        if (data.Length < 8 || data[0] != (byte)'V' || data[1] != (byte)'D'
                            || data[2] != (byte)'E' || data[3] != (byte)'B')
            throw new InvalidDataException("Bad magic in urls.vdeb");

        var offsFull = new List<int>(capacity: 1 << 16);
        int p = START;
        while (p < data.Length)
        {
            offsFull.Add(p);
            while (p < data.Length && data[p] != 0) p++;
            if (p >= data.Length) break;
            p++;
            if (p < data.Length && data[p] == 0) { p++; continue; }
        }

        lock (_lock)
        {
            try { _datFs?.Dispose(); } catch { }
            _datFs = null;
            _blob = data;
            _offsets = offsFull.ToArray();
            _bodyLength = data.Length - START;
            _loadedMtime = mtime;
            _loadedPath = path;
        }
        Log.Info("UrlDb",
            $"Loaded {offsFull.Count:N0} domains from {path} (full: blob IN RAM ≈ {data.Length / 1024} KB)");
    }

    private static int ReadFully(Stream s, byte[] buf, int off, int len)
    {
        int total = 0;
        while (total < len)
        {
            int n = s.Read(buf, off + total, len - total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    public bool IsBlocked(string domain) => IsBlocked(domain, out _);

    public bool IsBlocked(string domain, out string? matchedEntry)
    {
        matchedEntry = null;
        if (string.IsNullOrEmpty(domain)) return false;
        if (_offsets.Length == 0) return false;
        var d = domain.ToLowerInvariant().TrimStart('.').TrimEnd('.');

        var labels = d.Split('.');

        for (int i = 0; i < labels.Length - 1; i++)
        {
            var cand = string.Join('.', labels, i, labels.Length - i);
            if (BinarySearch(cand)) { matchedEntry = cand; return true; }
        }
        return false;
    }

    private bool BinarySearch(string needle)
    {
        byte[] blob; int[] offs; FileStream? fs;
        lock (_lock) { blob = _blob; offs = _offsets; fs = _datFs; }
        if (offs.Length == 0) return false;

        var needleBytes = Encoding.UTF8.GetBytes(needle);
        int lo = 0, hi = offs.Length - 1;

        Span<byte> scratch = stackalloc byte[260];

        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            int cmp;
            if (fs != null)
            {
                int read = ReadAtOffset(fs, offs[mid], scratch);
                cmp = CompareNullTerm(scratch[..read], needleBytes);
            }
            else
            {
                cmp = CompareAtOffset(blob, offs[mid], needleBytes);
            }
            if (cmp == 0) return true;
            if (cmp < 0) lo = mid + 1; else hi = mid - 1;
        }
        return false;
    }

    private static int ReadAtOffset(FileStream fs, long offset, Span<byte> scratch)
    {
        int n;
        lock (fs)
        {
            fs.Position = offset;
            n = fs.Read(scratch);
        }
        for (int i = 0; i < n; i++)
            if (scratch[i] == 0) return i;
        return n;
    }

    private static int CompareNullTerm(ReadOnlySpan<byte> current, ReadOnlySpan<byte> needle)
    {
        int min = Math.Min(current.Length, needle.Length);
        for (int i = 0; i < min; i++)
        {
            int c = current[i] - needle[i];
            if (c != 0) return c;
        }
        return current.Length - needle.Length;
    }

    private static int CompareAtOffset(byte[] blob, int off, ReadOnlySpan<byte> needle)
    {
        int i = 0;
        while (off + i < blob.Length)
        {
            byte b = blob[off + i];
            if (b == 0) return i < needle.Length ? -1 : 0;
            if (i >= needle.Length) return 1;
            int c = b - needle[i];
            if (c != 0) return c;
            i++;
        }
        return i < needle.Length ? -1 : 0;
    }

    private void DeleteSidecar(string why)
    {
        try
        {
            if (!File.Exists(_datPath)) return;
            File.Delete(_datPath);
            Log.Info("UrlDb", $"Removed working copy {Path.GetFileName(_datPath)} ({why}).");
        }
        catch { }
    }

    public void Dispose()
    {
        try { _watcher?.Dispose(); } catch { }
        _watcher = null;
        try { _debounceReload?.Dispose(); } catch { }
        _debounceReload = null;
        try { _datFs?.Dispose(); } catch { }
        _datFs = null;

        DeleteSidecar("shutdown");

        lock (_lock)
        {
            _blob = Array.Empty<byte>();
            _offsets = Array.Empty<int>();
            _bodyLength = 0;
            _loadedPath = null;
            _loadedMtime = default;
        }
    }
}
