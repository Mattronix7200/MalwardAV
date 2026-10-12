namespace Malward.Engine.Util;

public sealed class VulnerableDriverList
{
    private readonly string _path;
    private readonly object _lock = new();
    private HashSet<string> _sha = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _md5 = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _mtimeUtc = DateTime.MinValue;

    public VulnerableDriverList(string path)
    {
        _path = path;
        Reload();
    }

    public bool IsEmpty { get { lock (_lock) return _sha.Count == 0 && _md5.Count == 0; } }

    public int Count { get { lock (_lock) return _sha.Count + _md5.Count; } }

    private DateTime _lastProbeUtc = DateTime.MinValue;
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(2);

    private void Reload()
    {
        try
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                if (now - _lastProbeUtc < ProbeInterval) return;
                _lastProbeUtc = now;
            }

            if (!File.Exists(_path))
            {
                lock (_lock)
                {
                    _sha = new(StringComparer.OrdinalIgnoreCase);
                    _md5 = new(StringComparer.OrdinalIgnoreCase);
                    _mtimeUtc = DateTime.MinValue;
                }
                return;
            }

            var mt = File.GetLastWriteTimeUtc(_path);
            lock (_lock) { if (mt == _mtimeUtc && (_sha.Count > 0 || _md5.Count > 0)) return; }

            var sha = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var md5 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadLines(_path))
            {
                var t = line.Trim();
                if (t.Length == 0 || t[0] == '#') continue;
                if (t.Length == 64) sha.Add(t);
                else if (t.Length == 32) md5.Add(t);
            }

            lock (_lock) { _sha = sha; _md5 = md5; _mtimeUtc = mt; }
        }
        catch { }
    }

    public string? Match(string? sha256, string? md5)
    {
        Reload();

        lock (_lock)
        {
            if (!string.IsNullOrEmpty(sha256) && _sha.Contains(sha256!)) return sha256;
            if (!string.IsNullOrEmpty(md5) && _md5.Contains(md5!)) return md5;
        }
        return null;
    }
}
