using System.Diagnostics;
using System.Security.Cryptography;

namespace Malward.ResidentShield;

public enum ScanVerdict { Clean, Threat, Suspicious, Unknown, Error }

public sealed record ScanResult(
    string      FilePath,
    ScanVerdict Verdict,
    string?     ThreatName,
    string?     Detail,
    string?     Sha256 = null,
    string?     Md5    = null,
    bool        CloudChecked = false);

internal readonly record struct FileHashes(string Md5, string Sha256);

public sealed class ScanEngine : IDisposable
{
    private readonly ShieldConfig    _config;
    private readonly string          _malscanPath;
    private readonly VpsLookup       _vps;
    private readonly WhitelistLookup _whitelist;
    private readonly Malward.Engine.Util.VulnerableDriverList _byod =
        new(System.IO.Path.Combine(Malward.Engine.Util.Paths.DataDir, "vps-ex04.vdeb"));
    private readonly long            _maxBytes;

    private readonly ScanVerdictCache _verdictCache = new(TimeSpan.FromMinutes(30));

    private Malward.Engine.Core.ScanPipeline? _pipeline;
    private readonly object _pipelineGate = new();
    private int _pipelineFailures;
    private DateTime _pipelineRetryUtc = DateTime.MinValue;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (long Size, DateTime Mtime, FileHashes H)>
        _hashMemo = new(StringComparer.OrdinalIgnoreCase);
    private const int HashMemoMax = 8192;

    private FileHashes HashesCached(string path)
    {
        long size; DateTime mt;
        try { var fi = new FileInfo(path); size = fi.Length; mt = fi.LastWriteTimeUtc; }
        catch { return ComputeHashes(path); }
        if (_hashMemo.TryGetValue(path, out var e) && e.Size == size && e.Mtime == mt)
            return e.H;

        var h = ComputeHashes(path);
        if (_hashMemo.Count > HashMemoMax) _hashMemo.Clear();
        _hashMemo[path] = (size, mt, h);
        return h;
    }

    public string MalscanPath => _malscanPath;

    public ScanEngine(ShieldConfig config)
    {
        _config      = config;
        _malscanPath = FindMalscan(config.MalscanPath);
        _vps         = new VpsLookup();
        _whitelist   = new WhitelistLookup();
        _maxBytes    = (long)Math.Max(1, config.MaxFileSizeMb) * 1024 * 1024;
        if (_vps.IsAvailable)
            Log.Info("ScanEngine", $"Local VPS database: {_vps.ActivePath}");
        else
            Log.Warn("ScanEngine", "No local VPS database (vps.vdeb) — fast offline " +
                "detection disabled. Run `malscan update` to download it. " +
                "Until then detection depends on the cloud (malscan).");

        if (_config.TrustWhitelist && _whitelist.IsAvailable)
            Log.Info("ScanEngine", $"Whitelist: {_whitelist.ActivePath}");
    }

    private string? ByodHit(string md5, string sha256) => _byod.Match(sha256, md5);

    private static string ByodDetection(string byodHash) =>
        Malward.Engine.Core.DetectionNames.Prefix
        + (byodHash.Length >= 8 ? byodHash.Substring(0, 8) : byodHash).ToLowerInvariant();

    private bool IsTrusted(string filePath, string md5, string sha256)
    {
        if (ByodHit(md5, sha256) != null) return false;

        if (Malward.Engine.Util.SystemFileCheck.IsGenuineSystemFile(filePath)) return true;

        if (SystemGuard.IsOwnComponent(filePath)) return true;
        if (_config.TrustWhitelist && _whitelist.IsWhitelisted(md5, sha256)) return true;
        return false;
    }

    public bool IsBehaviorTrusted(string filePath)
    {
        try
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;
            if (SystemGuard.IsOwnComponent(filePath)) return true;
            var h = HashesCached(filePath);
            if (ByodHit(h.Md5, h.Sha256) != null) return false;
            if (SystemGuard.IsProtectedPath(filePath)) return true;
            if (_vps.Lookup(h.Md5, h.Sha256) != null) return false;
            if (_config.TrustWhitelist && _whitelist.IsWhitelisted(h.Md5, h.Sha256)) return true;
            return false;
        }
        catch { return false; }
    }

    public async Task<ScanResult> ScanAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
            return new ScanResult(filePath, ScanVerdict.Unknown, null, "plik nie istnieje");

        try
        {
            long size = new FileInfo(filePath).Length;
            if (size > _maxBytes)
                return new ScanResult(filePath, ScanVerdict.Unknown, null,
                    $"plik > {_config.MaxFileSizeMb} MB — pominięto");
        }
        catch {  }

        if (!await WaitFileReadyAsync(filePath, ct))
            return new ScanResult(filePath, ScanVerdict.Error, null, "plik zablokowany");

        FileHashes hashes;
        try { hashes = HashesCached(filePath); }
        catch { return new ScanResult(filePath, ScanVerdict.Error, null, "błąd odczytu pliku"); }
        string sha256 = hashes.Sha256;
        string md5    = hashes.Md5;

        if (ByodHit(md5, sha256) is { } byodHash)
        {
            var byodName = ByodDetection(byodHash);
            Log.Alert("BYOD", $"Vulnerable driver {Path.GetFileName(filePath)} -> {byodName}");
            return new ScanResult(filePath, ScanVerdict.Threat, byodName,
                "VulnerableDriver", sha256, md5);
        }

        var detection = _vps.Lookup(md5, sha256);
        if (detection != null)
        {
            if (IsTrusted(filePath, md5, sha256))
            {
                Log.Info("VPS", "VPS hit ignored (whitelist or genuine Microsoft system file): "
                                + Path.GetFileName(filePath));
                return new ScanResult(filePath, ScanVerdict.Clean, null, "whitelisted", sha256, md5);
            }
            Log.Alert("VPS", $"HIT {Path.GetFileName(filePath)} → {detection}");
            return new ScanResult(filePath, ScanVerdict.Threat, detection, "VPS local", sha256, md5);
        }

        if (string.IsNullOrEmpty(_malscanPath) && Pipeline() == null)
            return new ScanResult(filePath, ScanVerdict.Unknown, null, "silnik skanowania niedostępny", sha256, md5);

        if (_verdictCache.TryGet(sha256, out var hit, filePath, md5))
        {
            Log.Debug("Cache", $"Verdict from cache ({hit.Verdict}): {Path.GetFileName(filePath)}");
            return hit;
        }

        if (HasMarkOfTheWeb(filePath))
            Log.Debug("Reputation", $"File downloaded from the internet (MOTW): {Path.GetFileName(filePath)}");

        var result = await ScanInProcessAsync(filePath, sha256, ct);
        _verdictCache.Set(sha256, result);

        return result with { Md5 = md5 };
    }

    public ScanResult QuickVerdict(string filePath) => QuickVerdict(filePath, out _);

    public ScanResult QuickVerdict(string filePath, out ProcRep rep)
    {
        rep = ProcRep.Unknown;
        try
        {
            if (!File.Exists(filePath))
                return new ScanResult(filePath, ScanVerdict.Unknown, null, "brak pliku");

            if (SystemGuard.IsProtectedPath(filePath) || SystemGuard.IsOwnComponent(filePath))
                rep = ProcRep.SystemTrusted;

            long size = new FileInfo(filePath).Length;
            if (size <= 0 || size > _maxBytes)
                return new ScanResult(filePath, ScanVerdict.Unknown, null, "rozmiar");

            var hashes = HashesCached(filePath);
            var det = _vps.Lookup(hashes.Md5, hashes.Sha256);
            if (det != null)
            {
                rep = ProcRep.VpsBad;
                if (!IsTrusted(filePath, hashes.Md5, hashes.Sha256))
                    return new ScanResult(filePath, ScanVerdict.Threat, det, "VPS local (gate)", hashes.Sha256, hashes.Md5);

                rep = ProcRep.Whitelisted;
            }
            else if (rep != ProcRep.SystemTrusted)
            {
                if (_config.TrustWhitelist && _whitelist.IsWhitelisted(hashes.Md5, hashes.Sha256))
                    rep = ProcRep.Whitelisted;
                else if (SystemGuard.HasValidSignature(filePath))
                    rep = ProcRep.Whitelisted;
            }
            return new ScanResult(filePath, ScanVerdict.Unknown, null, "vps miss", hashes.Sha256, hashes.Md5);
        }
        catch
        {
            rep = ProcRep.Unknown;
            return new ScanResult(filePath, ScanVerdict.Unknown, null, "quick error");
        }
    }

    private Malward.Engine.Core.ScanPipeline? Pipeline()
    {
        if (_pipeline != null) return _pipeline;
        lock (_pipelineGate)
        {
            if (_pipeline != null) return _pipeline;
            if (DateTime.UtcNow < _pipelineRetryUtc) return null;
            try
            {
                var settings = Malward.Engine.Config.Settings.Load();

                if (!_config.CloudEnabled) settings.CloudScanEnabled = false;
                _pipeline = new Malward.Engine.Core.ScanPipeline(settings);
                if (_pipelineFailures > 0)
                    Log.Info("ScanEngine", $"In-process engine rebuilt after {_pipelineFailures} failed attempts.");
                else
                    Log.Info("ScanEngine", "Scan engine is running inside the resident process (no separate malscan.exe processes).");
                _pipelineFailures = 0;
                return _pipeline;
            }
            catch (Exception ex)
            {
                _pipelineFailures++;
                var wait = TimeSpan.FromSeconds(Math.Min(60, 5 * _pipelineFailures));
                _pipelineRetryUtc = DateTime.UtcNow + wait;
                Log.Alert("ScanEngine", $"In-process engine is NOT working (attempt {_pipelineFailures}): {ex.Message}. " +
                                        $"Temporarily falling back to malscan.exe, retrying in {wait.TotalSeconds:F0} s.");
                return null;
            }
        }
    }

    public int PipelineFailureCount { get { lock (_pipelineGate) return _pipelineFailures; } }

    private async Task<ScanResult> ScanInProcessAsync(string filePath, string sha256, CancellationToken ct)
    {
        var pipe = Pipeline();
        if (pipe == null) return await ScanViaMalscanAsync(filePath, sha256, ct);

        try
        {
            var r = await Task.Run(() => pipe.ScanRealtime(filePath), ct).WaitAsync(TimeSpan.FromSeconds(60), ct);
            bool cloudChecked = _config.CloudEnabled;

            switch (r.Verdict)
            {
                case Malward.Engine.Core.Verdict.Malware:
                    return new ScanResult(filePath, ScanVerdict.Threat, r.Detection ?? "Unknown",
                                          r.Source, sha256, CloudChecked: cloudChecked);
                case Malward.Engine.Core.Verdict.Clean:
                    return new ScanResult(filePath, ScanVerdict.Clean, null, null, sha256, CloudChecked: cloudChecked);
                case Malward.Engine.Core.Verdict.Skipped:
                {
                    bool encrypted = (r.Source ?? "").Contains("encrypted", StringComparison.OrdinalIgnoreCase);

                    return new ScanResult(filePath,
                        encrypted ? ScanVerdict.Error : ScanVerdict.Unknown, null,
                        encrypted ? "archiwum chronione hasłem — przeskanuj ręcznie w Malward aby podać hasło"
                                  : "pominięty plik",
                        sha256, CloudChecked: cloudChecked);
                }
                default:
                    return new ScanResult(filePath, ScanVerdict.Unknown, null, r.Error ?? "brak werdyktu",
                                          sha256, CloudChecked: cloudChecked);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (TimeoutException)
        {
            return new ScanResult(filePath, ScanVerdict.Error, null, "timeout", sha256);
        }
        catch (Exception ex)
        {
            Log.Warn("ScanEngine", $"In-process scan failed ({ex.Message}) — retrying via malscan.exe.");
            return await ScanViaMalscanAsync(filePath, sha256, ct);
        }
    }

    private async Task<ScanResult> ScanViaMalscanAsync(string filePath, string sha256, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo(_malscanPath, $"scan \"{filePath}\" -silent --realtime")
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding  = System.Text.Encoding.UTF8,
            };
            psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";

            if (!_config.CloudEnabled)
                psi.Environment["MALWARD_NO_CLOUD"] = "1";

            using var proc = new Process { StartInfo = psi, EnableRaisingEvents = false };
            proc.Start();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            timeoutCts.CancelAfter(TimeSpan.FromSeconds(25));

            string? detectionName = null;
            string? detectionStage = null;
            bool    hasSkip       = false;
            string? skipCategory  = null;

            while (true)
            {
                string? line;
                try { line = await proc.StandardOutput.ReadLineAsync(timeoutCts.Token); }
                catch (OperationCanceledException) { break; }
                if (line == null) break;

                if (line.StartsWith("DETECTION\t", StringComparison.Ordinal))
                {
                    detectionName = ExtractField(line, "det=");
                    if (string.IsNullOrEmpty(detectionName)) detectionName = "Unknown";
                    detectionStage = ExtractField(line, "source=");
                }
                else if (line.StartsWith("SKIP\t", StringComparison.Ordinal))
                {
                    hasSkip = true;

                    var cat = ExtractField(line, "category=");
                    if (!string.IsNullOrEmpty(cat)) skipCategory = cat;
                }
            }

            try { await proc.WaitForExitAsync(timeoutCts.Token); }
            catch (OperationCanceledException)
            {
                try { proc.Kill(); } catch { }
                return new ScanResult(filePath, ScanVerdict.Error, null, "timeout", sha256);
            }

            bool cloudChecked = _config.CloudEnabled;

            if (detectionName != null)
                return new ScanResult(filePath, ScanVerdict.Threat, detectionName, detectionStage,
                                      sha256, CloudChecked: cloudChecked);
            if (proc.ExitCode == 0)
                return new ScanResult(filePath, ScanVerdict.Clean, null, null, sha256, CloudChecked: cloudChecked);
            if (hasSkip)
            {
                bool encrypted = string.Equals(skipCategory, "encrypted", StringComparison.OrdinalIgnoreCase);

                return new ScanResult(filePath,
                    encrypted ? ScanVerdict.Error : ScanVerdict.Unknown, null,
                    encrypted ? "archiwum chronione hasłem — przeskanuj ręcznie w Malward aby podać hasło"
                              : "pominięty plik",
                    sha256, CloudChecked: cloudChecked);
            }

            return new ScanResult(filePath, ScanVerdict.Unknown, null,
                $"malscan exit {proc.ExitCode}", sha256, CloudChecked: cloudChecked);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new ScanResult(filePath, ScanVerdict.Error, null, ex.Message, sha256);
        }
    }

    private static async Task<bool> WaitFileReadyAsync(string path, CancellationToken ct)
    {
        for (int i = 0; i < 12; i++)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (fs.Length > 0 || i >= 2) return true;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { return true; }
            try { await Task.Delay(100, ct); } catch { return false; }
        }
        return true;
    }

    private static bool HasMarkOfTheWeb(string path)
    {
        try { return File.Exists(path + ":Zone.Identifier:$DATA"); }
        catch { return false; }
    }

    private static string? ExtractField(string line, string key)
    {
        int idx = line.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0) return null;
        int start = idx + key.Length;
        int end   = line.IndexOf('\t', start);
        return end < 0 ? line[start..] : line[start..end];
    }

    internal static string LocateMalscan(string hint)
    {
        if (!string.IsNullOrEmpty(hint) && File.Exists(hint)) return hint;

        var appDir = Path.GetDirectoryName(
            Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "";

        string[] candidates =
        [
            Path.Combine(appDir, "malscan.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Malward", "malscan.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Malward", "malscan.exe"),
        ];

        return Array.Find(candidates, File.Exists) ?? "";
    }

    private static string FindMalscan(string hint)
    {
        if (!string.IsNullOrEmpty(hint) && File.Exists(hint)) return hint;

        var appDir = Path.GetDirectoryName(
            Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "";

        string[] candidates =
        [
            Path.Combine(appDir, "malscan.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Malward", "malscan.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Malward", "malscan.exe"),
        ];

        var found = Array.Find(candidates, File.Exists) ?? "";
        Log.Info("ScanEngine", string.IsNullOrEmpty(found)
            ? "WARNING: malscan.exe not found — cloud/heuristics disabled"
            : $"malscan.exe: {found}");
        return found;
    }

    private static FileHashes ComputeHashes(string path)
    {
        const int CHUNK = 1 << 20;
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, CHUNK, FileOptions.SequentialScan);
        using var md5 = MD5.Create();
        using var sha = SHA256.Create();
        var buf = new byte[CHUNK];
        int n;
        while ((n = fs.Read(buf, 0, CHUNK)) > 0)
        {
            md5.TransformBlock(buf, 0, n, null, 0);
            sha.TransformBlock(buf, 0, n, null, 0);
        }
        md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return new FileHashes(
            Convert.ToHexString(md5.Hash!).ToLowerInvariant(),
            Convert.ToHexString(sha.Hash!).ToLowerInvariant());
    }

    public void Dispose()
    {
        try { _pipeline?.Dispose(); } catch { }
        _pipeline = null;
        _vps.Dispose();
        _whitelist.Dispose();
    }
}
