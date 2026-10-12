using Malward.ResidentShield.Vdeb;

namespace Malward.ResidentShield;

public sealed class VpsLookup : IDisposable
{
    public static readonly string DefaultVpsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "vps.vdeb");

    private readonly string[] _candidates;
    private VdebReader? _reader;
    private string?     _activePath;
    private DateTime    _readerModTime;
    private readonly object _lock = new();

    private readonly HashOverlay _overlay = new(HashOverlay.DataDirPath("vps-overlay.txt"));

    public VpsLookup(string? explicitPath = null)
    {
        var exeDir = Path.GetDirectoryName(
            Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "";

        var list = new List<string>();
        if (!string.IsNullOrEmpty(explicitPath)) list.Add(explicitPath);
        list.Add(DefaultVpsPath);
        list.Add(Path.Combine(exeDir, "data", "vps.vdeb"));
        list.Add(Path.Combine(exeDir, "_bases", "engine", "vps.vdeb"));
        _candidates = list.ToArray();
    }

    private string? ResolvePath() => Array.Find(_candidates, File.Exists);

    public bool IsAvailable => ResolvePath() != null;

    public string? ActivePath => ResolvePath();

    public string? Lookup(string sha256Hex) => Lookup(null, sha256Hex);

    public string? Lookup(string? md5Hex, string? sha256Hex)
    {
        try
        {
            if (_overlay.IsRemoved(md5Hex, sha256Hex)) return null;

            var hit = GetReader()?.TryFind(md5Hex, sha256Hex);
            if (hit != null) return hit;

            if (_overlay.IsAdded(md5Hex, sha256Hex))
            {
                var h = (sha256Hex ?? md5Hex ?? "").ToLowerInvariant();
                return Malward.Engine.Core.DetectionNames.Prefix + (h.Length >= 12 ? h.Substring(0, 12) : h);
            }
            return null;
        }
        catch (Exception ex)
        {
            Log.Error("VPS", $"Local lookup error: {ex.Message}");
            return null;
        }
    }

    private VdebReader? GetReader()
    {
        string? path = ResolvePath();
        if (path == null)
        {
            lock (_lock) { _reader?.Dispose(); _reader = null; _activePath = null; }
            return null;
        }

        DateTime modTime = File.GetLastWriteTimeUtc(path);

        lock (_lock)
        {
            bool samePath = string.Equals(_activePath, path, StringComparison.OrdinalIgnoreCase);
            if (_reader != null && samePath && modTime == _readerModTime)
                return _reader;

            _reader?.Dispose();
            _reader = null;

            try
            {
                _reader        = new VdebReader(path);
                _activePath    = path;
                _readerModTime = modTime;
                Log.Info("VPS", $"Local database loaded: {path}");
            }
            catch (Exception ex)
            {
                Log.Error("VPS", $"Cannot load database ({path}): {ex.Message}");
            }

            return _reader;
        }
    }

    public void Dispose()
    {
        lock (_lock) { _reader?.Dispose(); _reader = null; }
    }
}
