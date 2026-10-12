using Malward.ResidentShield.Vdeb;

namespace Malward.ResidentShield;

public sealed class WhitelistLookup : IDisposable
{
    private readonly string[] _candidates;
    private VdebReader? _reader;
    private string?     _activePath;
    private DateTime    _readerModTime;
    private readonly object _lock = new();

    private readonly HashOverlay _overlay = new(HashOverlay.DataDirPath("rf-whitelist-overlay.txt"));

    public WhitelistLookup(string? explicitPath = null)
    {
        var exeDir = Path.GetDirectoryName(
            Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "";

        var data = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "rf-whitelist.vdeb");

        var list = new List<string>();
        if (!string.IsNullOrEmpty(explicitPath)) list.Add(explicitPath);
        list.Add(data);
        list.Add(Path.Combine(exeDir, "data", "rf-whitelist.vdeb"));
        list.Add(Path.Combine(exeDir, "_bases", "engine", "rf-whitelist.vdeb"));
        _candidates = list.ToArray();
    }

    private string? ResolvePath() => Array.Find(_candidates, File.Exists);
    public bool IsAvailable => ResolvePath() != null;
    public string? ActivePath => ResolvePath();

    public bool IsWhitelisted(string sha256Hex) => IsWhitelisted(null, sha256Hex);

    public bool IsWhitelisted(string? md5Hex, string? sha256Hex)
    {
        try
        {
            if (_overlay.IsRemoved(md5Hex, sha256Hex)) return false;

            if (GetReader()?.TryFind(md5Hex, sha256Hex) != null) return true;

            return _overlay.IsAdded(md5Hex, sha256Hex);
        }
        catch (Exception ex)
        {
            Log.Error("Whitelist", $"Lookup error: {ex.Message}");
            return false;
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
                Log.Info("Whitelist", $"Whitelist database loaded: {path}");
            }
            catch (Exception ex)
            {
                Log.Error("Whitelist", $"Cannot load ({path}): {ex.Message}");
            }
            return _reader;
        }
    }

    public void Dispose()
    {
        lock (_lock) { _reader?.Dispose(); _reader = null; }
    }
}
