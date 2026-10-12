using System.Security.Cryptography.X509Certificates;

namespace Malward.Engine.Util;

public sealed class CertBlocklist
{
    private readonly string _path;
    private readonly object _lock = new();
    private HashSet<string> _fps = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _mtimeUtc = DateTime.MinValue;

    public CertBlocklist(string path)
    {
        _path = path;
        Reload();
    }

    public bool IsEmpty { get { lock (_lock) return _fps.Count == 0; } }

    private void Reload()
    {
        try
        {
            if (!File.Exists(_path))
            {
                lock (_lock) { _fps = new(StringComparer.OrdinalIgnoreCase); _mtimeUtc = DateTime.MinValue; }
                return;
            }
            var mt = File.GetLastWriteTimeUtc(_path);
            lock (_lock) { if (mt == _mtimeUtc && _fps.Count > 0) return; }

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadLines(_path))
            {
                var t = line.Trim();
                if (t.Length == 64) set.Add(t);
            }
            lock (_lock) { _fps = set; _mtimeUtc = mt; }
        }
        catch {  }
    }

    public string? MatchSigner(string filePath)
    {
        lock (_lock) { if (_fps.Count == 0) return null; }
        Reload();
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));

            var tp = cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
            if (string.IsNullOrEmpty(tp)) return null;
            lock (_lock) return _fps.Contains(tp) ? tp : null;
        }
        catch { return null; }
    }
}
