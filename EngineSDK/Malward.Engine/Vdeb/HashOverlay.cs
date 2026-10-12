namespace Malward.Engine.Vdeb;

public sealed class HashOverlay
{
    private readonly string _path;
    private readonly object _lock = new();

    private HashSet<string> _added   = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _removed = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _loadedMod = DateTime.MinValue;
    private long     _loadedLen = -1;

    public HashOverlay(string overlayPath) => _path = overlayPath;

    private void EnsureLoaded()
    {
        try
        {
            if (!File.Exists(_path))
            {
                if (_loadedLen != 0)
                    lock (_lock)
                    {
                        _added = new(StringComparer.OrdinalIgnoreCase);
                        _removed = new(StringComparer.OrdinalIgnoreCase);
                        _loadedLen = 0; _loadedMod = DateTime.MinValue;
                    }
                return;
            }

            var fi  = new FileInfo(_path);
            var mod = fi.LastWriteTimeUtc;
            var len = fi.Length;

            lock (_lock)
            {
                if (mod == _loadedMod && len == _loadedLen) return;

                var added   = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var removed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var raw in File.ReadLines(_path))
                {
                    var line = raw.Trim();
                    if (line.Length < 2) continue;
                    char op = line[0];
                    if (op != '+' && op != '-') continue;
                    string h = line.Substring(1).Trim();
                    if (h.Length is not (32 or 64)) continue;
                    if (op == '+') { removed.Remove(h); added.Add(h); }
                    else           { added.Remove(h);  removed.Add(h); }
                }

                _added = added; _removed = removed;
                _loadedMod = mod; _loadedLen = len;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] overlay load failed ({Path.GetFileName(_path)}): {ex.Message}");
        }
    }

    public bool IsRemoved(string? md5Hex, string? sha256Hex)
    {
        EnsureLoaded();
        lock (_lock)
        {
            if (_removed.Count == 0) return false;
            if (!string.IsNullOrEmpty(sha256Hex) && _removed.Contains(sha256Hex)) return true;
            if (!string.IsNullOrEmpty(md5Hex)    && _removed.Contains(md5Hex))    return true;
            return false;
        }
    }

    public bool IsAdded(string? md5Hex, string? sha256Hex)
    {
        EnsureLoaded();
        lock (_lock)
        {
            if (_added.Count == 0) return false;
            if (!string.IsNullOrEmpty(sha256Hex) && _added.Contains(sha256Hex)) return true;
            if (!string.IsNullOrEmpty(md5Hex)    && _added.Contains(md5Hex))    return true;
            return false;
        }
    }
}
