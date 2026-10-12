using System.Diagnostics;
using Malward.Engine.Archive;
using Malward.Engine.Cloud;
using Malward.Engine.Config;
using Malward.Engine.Heuristic;
using Malward.Engine.Util;
using Malward.Engine.Vdeb;

namespace Malward.Engine.Core;

public sealed class ScanPipeline : IDisposable
{
    private readonly Settings _settings;
    private readonly VdebReader? _vps;
    private readonly VdebReader? _whitelist;
    private readonly ServerClient? _cloud;
    private readonly long _maxFileBytes;

    private readonly HashOverlay _vpsOverlay =
        new(Path.Combine(Paths.DataDir, "vps-overlay.txt"));
    private readonly HashOverlay _wlOverlay =
        new(Path.Combine(Paths.DataDir, "rf-whitelist-overlay.txt"));

    private readonly CertBlocklist _certBlock =
        new(Path.Combine(Paths.DataDir, "vps-ex02.vdeb"));

    private readonly VulnerableDriverList _byod =
        new(Path.Combine(Paths.DataDir, "vps-ex04.vdeb"));

    private readonly ArchiveScanner _archive = new();

    private int MaxNestedArchiveLevels => Math.Clamp(_settings.ArchiveMaxDepth, 0, 12);

    private string? _heurYacPath;
    private HeurReader? _heurReader;
    private readonly HeurScannerRunner _heurRunner;
    private readonly object _heurInitLock = new();

    private static readonly HashSet<string> HeuristicSkipExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".lnk", ".url", ".log", ".ini", ".md", ".csv",
    };

    private static readonly HashSet<string> CloudOffSkipExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".url",
    };

    private static readonly HashSet<string> PureTextSkipExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".md", ".csv", ".ini",

        ".log2", ".log1", ".json", ".dat", ".lock", ".typed", ".empty", ".bak", ".tmp",
        ".etl", ".evtx", ".pid", ".cache",
    };
    private static bool HasExt(string path, HashSet<string> set)
    {
        var e = Path.GetExtension(path);
        return !string.IsNullOrEmpty(e) && set.Contains(e);
    }

    private static bool LooksLikePe(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return fs.ReadByte() == 0x4D && fs.ReadByte() == 0x5A;
        }
        catch { return false; }
    }

    public StatusBar? Status { get; set; }

    public VdebReader? VpsReader => _vps;
    public HeurReader? HeurReader { get { _ = EnsureHeurYacExtracted(); return _heurReader; } }

    public ScanPipeline(Settings settings)
    {
        _settings = settings;
        _maxFileBytes = (long)settings.MaxFileSizeMb * 1024 * 1024;

        _archive.ConfigureExtensions(settings.ArchiveExtensions);
        _heurRunner = new HeurScannerRunner(settings.MaxScanTimePerFileSec);

        if (settings.CloudScanEnabled)
        {
            try { _cloud = new ServerClient(settings); }
            catch (Exception ex) { Console.Error.WriteLine($"[!] Cloud client init failed: {ex.Message}"); }
        }

        var vpsPath = Paths.VpsVdebReadable;
        if (File.Exists(vpsPath))
        {
            try
            {
                _vps = new VdebReader(vpsPath);
                Console.WriteLine($"[+] VPS database loaded: {vpsPath} " +
                                  $"({_vps.TotalEntries:N0} entries, " +
                                  $"compact={_vps.IsCompact} prefix={_vps.CompactPrefix}B)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] VPS load failed: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine("[!] vps.vdeb not found — local lookup disabled. Run `malscan.exe update`.");
        }

        var wlPath = Paths.WhitelistVdebReadable;
        if (File.Exists(wlPath))
        {
            try
            {
                _whitelist = new VdebReader(wlPath);
                Console.WriteLine($"[+] Whitelist loaded: {_whitelist.TotalEntries:N0} entries");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Whitelist load failed: {ex.Message}");
            }
        }
    }

    public DetectionResult Scan(string filePath) =>
        ScanCore(filePath, recurseArchives: true);

    public const string UnverifiedSource = "VPS-unverified";

    public const string ByodSource = "VulnerableDriver";

    public const string OversizedSource = "Oversized-container";

    private static bool LooksLikeContainer(string path)
    {
        try
        {
            if (LooksLikePe(path)) return true;
            var ext = Path.GetExtension(path);
            return ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".dat", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".img", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".iso", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static readonly int[] VerifyBackoffMs = { 400, 1200, 3000 };

    private ServerClient.HashResponse VerifyWithRetry(string sha)
    {
        Exception? last = null;
        for (int attempt = 0; attempt < VerifyBackoffMs.Length; attempt++)
        {
            try { return _cloud!.HashLookupAsync(sha).GetAwaiter().GetResult(); }
            catch (ServerClient.CloudThrottledException ex)
            {
                last = ex;
                var wait = ex.RetryAfter is { } ra && ra > TimeSpan.Zero
                    ? (int)Math.Min(ra.TotalMilliseconds, 15000)
                    : VerifyBackoffMs[attempt];
                Thread.Sleep(wait);
            }
        }
        throw last ?? new System.Net.Http.HttpRequestException("cloud verification unavailable");
    }

    public DetectionResult ScanRealtime(string filePath) =>
        ScanCore(filePath, recurseArchives: true,

                 realtimeHeurAllowed: _settings.HeuristicRealtimeEnabled,

                 realtime: true);

    public DetectionResult ScanProcessImage(string filePath, bool ignoreWhitelist)
        => ScanCore(filePath, recurseArchives: true, ignoreWhitelist: ignoreWhitelist);

    internal DetectionResult ScanArchiveEntry(string tempPath, string displayPath, int depth)
        => ScanCore(tempPath, recurseArchives: true,
                    archiveEntryMode: true, displayOverride: displayPath,
                    archiveDepth: depth);

    private static readonly string OwnAppDir =
        AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static bool IsOwnTempFile(string filePath)
    {
        var name = Path.GetFileName(filePath);
        return name.StartsWith("malward-", StringComparison.OrdinalIgnoreCase)
            && name.EndsWith(".yac", StringComparison.OrdinalIgnoreCase)
            && filePath.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase);
    }

    private static readonly HashSet<string> OwnComponentFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "malscan.exe", "malscan.dll", "malward.exe", "malward.fwmanager.dll", "malwardctx.exe",
        "mwshield.exe", "netmonitor.exe", "bkmonitor.exe", "heurscanner.exe", "sbhelper.exe",
        "dllhost.exe", "7z.dll", "7z.exe", "qemu-system-x86_64.exe",
    };

    private static readonly HashSet<string> OwnDataExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vdeb", ".yac", ".yar", ".yara", ".bloom", ".db", ".dat", ".idx", ".bin",
        ".json", ".txt", ".log", ".ini", ".cfg", ".config", ".pdb", ".xml",
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".css", ".js", ".html", ".woff", ".woff2",
    };

    private static bool IsOwnAppPath(string filePath)
    {
        if (string.IsNullOrEmpty(OwnAppDir)) return false;
        bool insideOwnDir =
            filePath.StartsWith(OwnAppDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || string.Equals(filePath, OwnAppDir, StringComparison.OrdinalIgnoreCase);
        if (!insideOwnDir) return false;

        var name = Path.GetFileName(filePath);
        if (OwnComponentFiles.Contains(name)) return true;
        var ext = Path.GetExtension(filePath);
        if (OwnDataExts.Contains(ext)) return true;

        return false;
    }

    private static bool IsNonScannableSystemArtifact(string filePath)
    {
        try
        {
            var name = Path.GetFileName(filePath);
            var dir = (Path.GetDirectoryName(filePath) ?? "").TrimEnd(Path.DirectorySeparatorChar);
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd(Path.DirectorySeparatorChar);

            if (name.Equals("pagefile.sys", StringComparison.OrdinalIgnoreCase)
             || name.Equals("swapfile.sys", StringComparison.OrdinalIgnoreCase)
             || name.Equals("hiberfil.sys", StringComparison.OrdinalIgnoreCase)
             || name.StartsWith("DumpStack.log", StringComparison.OrdinalIgnoreCase))
                return true;

            if (string.IsNullOrEmpty(win)) return false;

            if (name.Equals("Memory.DMP", StringComparison.OrdinalIgnoreCase)
                && dir.Equals(win, StringComparison.OrdinalIgnoreCase))
                return true;

            foreach (var sub in new[] { "Minidump", "LiveKernelReports" })
            {
                var p = Path.Combine(win, sub);
                if (dir.Equals(p, StringComparison.OrdinalIgnoreCase)
                 || dir.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch { }
        return false;
    }

    private static bool IsOsManagedUserPath(string filePath)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(local))
        {
            var winShell = Path.Combine(local, "Microsoft", "Windows") + Path.DirectorySeparatorChar;
            if (filePath.StartsWith(winShell, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private DetectionResult ScanCore(string filePath, bool recurseArchives,
                                      bool archiveEntryMode = false,
                                      string? displayOverride = null,
                                      bool ignoreWhitelist = false,
                                      bool realtimeHeurAllowed = true,
                                      bool realtime = false,
                                      int archiveDepth = 0)
    {
        bool heurYaraEnabled = _settings.HeuristicEnabled && realtimeHeurAllowed;
        var sw = Stopwatch.StartNew();
        long size = 0;

        string displayPath = displayOverride ?? filePath;
        try
        {
            foreach (var ex in _settings.Exceptions)
            {
                if (string.IsNullOrEmpty(ex)) continue;
                if (filePath.StartsWith(ex, StringComparison.OrdinalIgnoreCase))
                    return new DetectionResult(filePath, "", Verdict.Skipped, null, "Skipped:exception", 0, sw.ElapsedMilliseconds);
            }

            if (IsOwnTempFile(filePath) || IsOwnAppPath(filePath))
                return new DetectionResult(filePath, "", Verdict.Skipped, null,
                    "Skipped:own-app", 0, sw.ElapsedMilliseconds);

            if (IsNonScannableSystemArtifact(filePath))
                return new DetectionResult(filePath, "", Verdict.Skipped, null,
                    "Skipped:system-artifact", 0, sw.ElapsedMilliseconds);

            if (!File.Exists(filePath))
                return new DetectionResult(filePath, "", Verdict.Error, null, "Skipped:not_found", 0, sw.ElapsedMilliseconds, "File not found");

            size = new FileInfo(filePath).Length;

            if (size == 0)
                return new DetectionResult(filePath, "", Verdict.Skipped, null, "Skipped:empty", 0, sw.ElapsedMilliseconds);

            bool looksPe = LooksLikePe(filePath);

            if (!looksPe && HasExt(filePath, PureTextSkipExts))
                return new DetectionResult(filePath, "", Verdict.Skipped, null, "Skipped:pure-text", size, sw.ElapsedMilliseconds);

            if (!ExtensionPasses(filePath) && !looksPe)
                return new DetectionResult(filePath, "", Verdict.Skipped, null, "Skipped:ext_filter", size, sw.ElapsedMilliseconds);

            if (!_settings.CloudScanEnabled && HasExt(filePath, CloudOffSkipExts))
                return new DetectionResult(filePath, "", Verdict.Skipped, null, "Skipped:cloud-off-text", size, sw.ElapsedMilliseconds);

            string sha; string md5;
            try
            {
                var hashes = HashService.HashBoth(filePath);
                md5 = hashes.Md5Hex;
                sha = hashes.Sha256Hex;
            }
            catch (UnauthorizedAccessException)
            {
                return new DetectionResult(filePath, "", Verdict.Skipped, null,
                    "Skipped:blocked", 0, sw.ElapsedMilliseconds, "Access denied (blocked by system)");
            }
            catch (IOException ioex) when (ioex.HResult == unchecked((int)0x80070020)
                                        || ioex.HResult == unchecked((int)0x80070021) )
            {
                return new DetectionResult(filePath, "", Verdict.Skipped, null,
                    "Skipped:locked", 0, sw.ElapsedMilliseconds, "File is locked / blocked (in use)");
            }

            bool isSystem = SystemFileCheck.IsSystemFile(filePath);

            if (!isSystem) isSystem = IsOsManagedUserPath(filePath);

            bool willRunHeur = heurYaraEnabled;
            bool isTrustedSigned = willRunHeur && !isSystem && !ignoreWhitelist
                                   && SystemFileCheck.HasValidTrustedSignature(filePath);

            bool isGenuineSystem = !ignoreWhitelist && isSystem
                                   && SystemFileCheck.IsGenuineSystemFile(filePath);

            if (!_certBlock.IsEmpty)
            {
                var pe = Path.GetExtension(filePath).TrimStart('.').ToUpperInvariant();
                if (pe is "EXE" or "DLL" or "SYS" or "OCX" or "SCR" or "CPL" or "DRV" || looksPe)
                {
                    var badTp = _certBlock.MatchSigner(filePath);
                    if (badTp != null)
                    {
                        var certDet = "Malware.KnownBASF@" + (sha.Length >= 8 ? sha[..8] : sha);
                        if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, "CertBlocklist", certDet, "CertBlocklist");
                        return new DetectionResult(filePath, sha, Verdict.Malware, certDet, "CertBlocklist", size, sw.ElapsedMilliseconds);
                    }
                }
            }

            long archiveLimit = (long)Math.Max(1, _settings.ArchiveMaxSizeMb) * 1024 * 1024;
            bool willExpandArchive = recurseArchives && _settings.ScanArchives
                                     && archiveDepth <= MaxNestedArchiveLevels
                                     && size <= archiveLimit
                                     && _archive.IsArchivePath(filePath);

            bool oversizedContainer = !willExpandArchive
                                      && _settings.InspectOversizedContainers
                                      && recurseArchives
                                      && archiveDepth <= MaxNestedArchiveLevels
                                      && size > _maxFileBytes
                                      && LooksLikeContainer(filePath);

            if (_byod.Match(sha, md5) is { } byodHash)
            {
                var byodDet = DetectionNames.Prefix
                              + (byodHash.Length >= 8 ? byodHash[..8] : byodHash).ToLowerInvariant();
                return new DetectionResult(filePath, sha, Verdict.Malware, byodDet,
                    ByodSource, size, sw.ElapsedMilliseconds);
            }

            if (!willExpandArchive && !ignoreWhitelist && _settings.TrustWhitelist && WhitelistHit(md5, sha))
                return new DetectionResult(filePath, sha, Verdict.Clean, null,
                    "Whitelist", size, sw.ElapsedMilliseconds);

            if (!willExpandArchive && !ignoreWhitelist && _settings.SkipMsSigned && SystemFileCheck.IsGenuineSystemFile(filePath))
                return new DetectionResult(filePath, sha, Verdict.Clean, null,
                    "Microsoft/System", size, sw.ElapsedMilliseconds);

            if (oversizedContainer)
            {
                willExpandArchive = true;
                Console.Error.WriteLine(
                    $"[i] {displayPath}: {size / (1024 * 1024)} MB exceeds the limit "
                    + "— inspecting the contents instead of skipping the file");
            }

            Status?.State("VPS lookup", displayPath);

            if (VpsLookup(md5, sha) is { } det)
            {
                if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, "VPS", det, "VPS");

                if (_settings.CloudVerifyDetections && _cloud != null)
                {
                    bool verified = false;
                    try
                    {
                        Status?.State("VPS verify (cloud /hash)", displayPath);
                        var vpsHash = VerifyWithRetry(sha);
                        verified = true;
                        if (vpsHash.Verdict == "clean")
                        {
                            const int CLIENT_AUTO_TTL_DAYS = 30;
                            bool staleAuto = vpsHash.Source == "auto"
                                             && vpsHash.AgeDays.HasValue
                                             && vpsHash.AgeDays.Value > CLIENT_AUTO_TTL_DAYS;
                            if (!staleAuto)
                            {
                                return new DetectionResult(filePath, sha, Verdict.Clean, null,
                                    "VPS→Cloud-hash-clean", size, sw.ElapsedMilliseconds);
                            }
                        }
                        else if (vpsHash.Verdict == "malware")
                        {
                            return new DetectionResult(filePath, sha, Verdict.Malware, det,
                                "VPS+Cloud", size, sw.ElapsedMilliseconds);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[!] VPS verify via cloud failed for {filePath}: {ex.Message}");
                    }

                    if (!verified)
                        return new DetectionResult(filePath, sha, Verdict.Malware, det,
                            UnverifiedSource, size, sw.ElapsedMilliseconds);
                }

                return new DetectionResult(filePath, sha, Verdict.Malware, det, "VPS", size, sw.ElapsedMilliseconds);
            }

            bool archiveExpanded = false;
            if (willExpandArchive)
            {
                Status?.State("archive scan", displayPath);

                ArchiveScanner.ArchiveScanFn archiveFn =
                    (tmp, disp) => ScanArchiveEntry(tmp, disp, archiveDepth + 1);

                var ar = _archive.ScanArchive(filePath, archiveFn, _settings.MaxScanTimePerFileSec * 4,
                                              onEntry: disp => Status?.State("archive scan", disp),

                                              displayName: displayOverride ?? Path.GetFileName(filePath));

                archiveExpanded = ar.Expanded;
                if (ar.Error != null)
                    Console.Error.WriteLine($"[!] archive {filePath}: {ar.Error}");
                if (ar.PasswordProtected)
                {
                    return new DetectionResult(filePath, sha, Verdict.Skipped, null,
                        "Skipped:encrypted-archive", size, sw.ElapsedMilliseconds,
                        "Archive is encrypted");
                }
                if (ar.AnyDetected)
                {
                    var findings = ar.Findings.Select(f => new ArchiveFinding(
                        f.EntryName,
                        string.IsNullOrEmpty(f.Display) ? $"{Path.GetFileName(filePath)} >> /{f.EntryName}" : f.Display,
                        f.Detection, f.Source, f.Direct)).ToList();

                    var first = ar.Findings[0];
                    string innerDet = first.Detection.EndsWith("!archive", StringComparison.Ordinal)
                        ? first.Detection
                        : first.Detection + "!archive";

                    string allEntries = string.Join("|", findings.Select(f => f.Entry));
                    return new DetectionResult(filePath, sha, Verdict.Malware, innerDet,
                        $"Archive:{first.Source}", size, sw.ElapsedMilliseconds,
                        ArchiveEntry: allEntries,
                        ArchiveFindings: findings);
                }
            }

            ServerClient.HashResponse? hr = null;
            if (_cloud != null && _settings.ScanOptimization)
            {
                Status?.State("cloud /hash", displayPath);
                try
                {
                    hr = _cloud.HashLookupAsync(sha).GetAwaiter().GetResult();
                    if (hr.Verdict == "malware")
                    {
                        var cloudName = DetectionNames.Normalize(hr.Name);
                        if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, "Cloud:hash", cloudName, "Cloud:hash");
                        return new DetectionResult(filePath, sha, Verdict.Malware, cloudName, "Cloud:hash", size, sw.ElapsedMilliseconds);
                    }
                    if (hr.Verdict == "clean")
                    {
                        const int CLIENT_AUTO_TTL_DAYS = 30;
                        bool isStaleAuto = hr.Source == "auto"
                                           && hr.AgeDays.HasValue
                                           && hr.AgeDays.Value > CLIENT_AUTO_TTL_DAYS;
                        if (isStaleAuto)
                        {
                            hr = hr with { Verdict = "unknown", Action = "upload" };
                        }
                        else
                        {
                            string srcTag = hr.Source switch
                            {
                                "curated" => "Cloud:whitelist-curated",
                                "auto"    => "Cloud:whitelist-auto",
                                _         => "Cloud:whitelist"
                            };
                            return new DetectionResult(filePath, sha, Verdict.Clean, null, srcTag, size, sw.ElapsedMilliseconds);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[!] Cloud /hash failed for {filePath}: {ex.Message}");
                }
            }
            else if (_cloud != null)
            {
                hr = new ServerClient.HashResponse("unknown", null, "upload");
            }

            if (size > _maxFileBytes && _cloud != null && hr?.Verdict == "unknown" && !archiveExpanded)
            {
                Console.Error.WriteLine(
                    $"[i] {displayPath}: {size / (1024 * 1024)} MB exceeds the upload limit " +
                    $"({_settings.MaxFileSizeMb} MB) — checked locally, not uploaded to the cloud");
            }
            else if (_cloud != null && hr?.Verdict == "unknown" && !archiveExpanded)
            {
                Status?.State("cloud /scan (upload+silniki)", displayPath);
                try
                {
                    var sr = _cloud.ScanFileAsync(filePath, _settings.ScanLevel).GetAwaiter().GetResult();

                    if (sr.Verdict == "malware" && !string.IsNullOrWhiteSpace(sr.Label))
                        CloudLabel = sr.Label;
                    if (sr.Verdict == "malware")
                    {
                        if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, "Cloud:scan", sr.Name, "Cloud:scan");
                        return new DetectionResult(filePath, sha, Verdict.Malware, sr.Name, "Cloud:scan", size, sw.ElapsedMilliseconds);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[!] Cloud /scan failed for {filePath}: {ex.Message}");
                }
            }

            if (!isTrustedSigned && !isGenuineSystem)
            {
                var mq = Masquerade.CheckFile(filePath, verifySignature: false);
                if (mq != null)
                {
                    if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, "Masquerade", mq.Detection, "Masquerade");
                    return new DetectionResult(filePath, sha, Verdict.Malware, mq.Detection, "Masquerade", size, sw.ElapsedMilliseconds);
                }
            }

            if (heurYaraEnabled && _settings.ScriptAnalysisEnabled && !isTrustedSigned && !isGenuineSystem)
            {
                var sh = Malward.Engine.Heuristic.ScriptHeuristics.Check(filePath);
                if (sh != null)
                {
                    string src = sh.Confidence == Malward.Engine.Heuristic.ScriptHeuristics.ScriptConfidence.High
                        ? "Script" : "Heur:Script";
                    if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, src, sh.Detection, src);
                    Console.Error.WriteLine($"[i] {Path.GetFileName(filePath)}: {sh.Reason}");
                    return new DetectionResult(filePath, sha, Verdict.Malware, sh.Detection, src, size, sw.ElapsedMilliseconds);
                }
            }

            if (heurYaraEnabled && !isTrustedSigned && !isGenuineSystem && !HasExt(filePath, HeuristicSkipExts))
            {
                Status?.State("heur YARA", displayPath);
                var yac = EnsureHeurYacExtracted();
                if (yac != null)
                {
                    var hres = _heurRunner.Scan(yac, filePath);
                    if (hres.Detected && !string.IsNullOrEmpty(hres.RuleName))
                    {
                        if (isSystem) return SystemFalsePositive(filePath, sha, size, sw, "Heur:YARA", HeurMalwareName(sha), "Heur:YARA");
                        var name = HeurMalwareName(sha);
                        return new DetectionResult(filePath, sha, Verdict.Malware, name, "Heur:YARA", size, sw.ElapsedMilliseconds);
                    }
                    if (hres.Error != null)
                        Console.Error.WriteLine($"[!] heur for {filePath}: {hres.Error}");
                }
            }

            return new DetectionResult(filePath, sha, Verdict.Clean, null, "Local", size, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            return new DetectionResult(filePath, "", Verdict.Error, null, "Error", size, sw.ElapsedMilliseconds, ex.Message);
        }
    }

    private string? VpsLookup(string? md5, string? sha)
    {
        if (_vpsOverlay.IsRemoved(md5, sha)) return null;
        var det = _vps?.TryFind(md5, sha);
        if (det != null) return det;
        if (_vpsOverlay.IsAdded(md5, sha))
        {
            var h = (sha ?? md5 ?? "").ToLowerInvariant();
            return DetectionNames.Prefix + (h.Length >= 12 ? h.Substring(0, 12) : h);
        }
        return null;
    }

    private bool WhitelistHit(string? md5, string? sha)
    {
        if (_wlOverlay.IsRemoved(md5, sha)) return false;
        if (_whitelist?.TryFind(md5, sha) != null) return true;
        return _wlOverlay.IsAdded(md5, sha);
    }

    private DetectionResult SystemFalsePositive(string filePath, string sha, long size,
        Stopwatch sw, string srcStage, string? detName = null, string? source = null)
    {
        if (!SystemFileCheck.IsGenuineSystemFile(filePath))
        {
            Console.Error.WriteLine($"[!] {srcStage}: file in a system folder is UNSIGNED/not TrustedInstaller — " +
                                    $"treating as a threat (possible dropper into System32): {filePath}");
            return new DetectionResult(filePath, sha, Verdict.Malware, detName ?? "Malware",
                source ?? srcStage, size, sw.ElapsedMilliseconds);
        }

        Console.Error.WriteLine($"[i] System file false-positive @ {srcStage} — auto-whitelist: {filePath}");
        if (_cloud != null && !string.IsNullOrEmpty(sha))
        {
            _ = Task.Run(() => _cloud.SubmitCleanAsync(sha));
        }
        return new DetectionResult(filePath, sha, Verdict.Clean, null, "System:auto-whitelist", size, sw.ElapsedMilliseconds);
    }

    public string? CloudLabel { get; private set; }

    private static string HeurMalwareName(string sha256Hex)
    {
        var s = sha256Hex.ToLowerInvariant();
        if (s.Length < 4) return $"Heur.Malware@generic!{s}";
        return $"Heur.Malware@generic!{s[..2]}{s[^2..]}";
    }

    private string? EnsureHeurYacExtracted()
    {
        if (_heurYacPath != null) return _heurYacPath;
        lock (_heurInitLock)
        {
            if (_heurYacPath != null) return _heurYacPath;
            var heurPath = Paths.HeurVdebReadable;
            if (!File.Exists(heurPath))
            {
                Console.Error.WriteLine("[!] heur.vdeb missing — heuristic disabled this run");
                return null;
            }
            try
            {
                _heurReader = new HeurReader(heurPath);
                _heurYacPath = _heurReader.ExtractToTempFile("002.yac");
                return _heurYacPath;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] heur init failed: {ex.Message}");
                return null;
            }
        }
    }

    private bool ExtensionPasses(string filePath)
    {
        var ext = Path.GetExtension(filePath).TrimStart('.').ToUpperInvariant();
        return _settings.ExtFilterMode switch
        {
            "all"       => true,
            "blacklist" => !_settings.ExtBlacklist.Any(b => b.Equals(ext, StringComparison.OrdinalIgnoreCase)),
            _           => _settings.ExtListCommon.Any(b => b.Equals(ext, StringComparison.OrdinalIgnoreCase)) || string.IsNullOrEmpty(ext),
        };
    }

    public void Dispose()
    {
        _vps?.Dispose();
        _whitelist?.Dispose();
        _cloud?.Dispose();
        _heurReader?.Dispose();
        if (_heurYacPath != null && File.Exists(_heurYacPath))
        {
            try { File.Delete(_heurYacPath); } catch {  }
        }
    }
}
