using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.ResidentShield;

public enum RepairMode { Ask = 0, Auto = 1, QuarantineOnly = 2, Delete = 3 }

public sealed class RansomwareDetectFlags
{
    [JsonPropertyName("mass_rename")] public bool MassRename { get; set; } = true;

    [JsonPropertyName("entropy_check")] public bool EntropyCheck { get; set; } = true;

    [JsonPropertyName("entropy_threshold")] public double EntropyThreshold { get; set; } = 7.8;

    [JsonPropertyName("entropy_min_files")] public int EntropyMinFiles { get; set; } = 3;

    [JsonPropertyName("ransom_note_signatures")] public bool RansomNoteSignatures { get; set; } = true;

    [JsonPropertyName("vss_delete_hook")] public bool VssDeleteHook { get; set; } = true;

    [JsonPropertyName("defense_tamper")] public bool DefenseTamper { get; set; } = true;

    [JsonPropertyName("raw_disk_guard")] public bool RawDiskGuard { get; set; } = true;

    [JsonPropertyName("io_anomaly")] public bool IoAnomaly { get; set; } = false;

    [JsonPropertyName("io_anomaly_mb_per_min")] public int IoAnomalyMbPerMin { get; set; } = 100;
}

public sealed class BehaviorScoreConfig
{
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;

    [JsonPropertyName("threshold")] public int Threshold { get; set; } = 8;

    [JsonPropertyName("self_copy")] public bool SelfCopy { get; set; } = true;

    [JsonPropertyName("file_infector")] public bool FileInfector { get; set; } = true;

    [JsonPropertyName("mass_pe_creation")] public bool MassPeCreation { get; set; } = true;
}

public sealed class ExclusionEntry
{
    [JsonPropertyName("path")]  public string Path  { get; set; } = "";
    [JsonPropertyName("scope")] public string Scope { get; set; } = "both";
}

public sealed class ShieldConfig
{
    [JsonPropertyName("file_monitor")]
    public bool FileMonitorEnabled    { get; set; } = true;

    [JsonPropertyName("usn_journal")]
    public bool UsnJournalEnabled     { get; set; } = true;

    [JsonPropertyName("active_process_scan")]
    public bool ActiveProcessScan    { get; set; } = true;

    [JsonIgnore] public bool ProcessMonitorEnabled  => ActiveProcessScan;
    [JsonIgnore] public bool RegistryMonitorEnabled => ActiveProcessScan;

    [JsonPropertyName("behavior_monitor")]
    public bool BehaviorMonitorEnabled { get; set; } = true;

    [JsonPropertyName("behavior_file_tracking")]
    public bool BehaviorFileTrackingEnabled { get; set; } = true;

    [JsonPropertyName("behavior_scoring")]
    public BehaviorScoreConfig BehaviorScoring { get; set; } = new();

    [JsonPropertyName("behavior_user_decides")]
    public bool BehaviorUserDecides { get; set; } = false;

    [JsonPropertyName("pre_launch_analysis")]
    public bool PreLaunchAnalysis { get; set; } = true;

    [JsonPropertyName("pre_launch_timeout_sec")]
    public int PreLaunchTimeoutSec { get; set; } = 8;

    [JsonPropertyName("scan_on_startup")]
    public bool AutoScanOnStartup     { get; set; } = false;

    [JsonPropertyName("scan_on_sig_update")]
    public bool AutoScanOnSigUpdate   { get; set; } = false;

    [JsonPropertyName("scan_on_infection")]
    public bool AutoScanOnInfection   { get; set; } = true;

    [JsonPropertyName("repair_mode")]
    public RepairMode RepairMode      { get; set; } = RepairMode.Auto;

    [JsonPropertyName("max_file_size_mb")]
    public int MaxFileSizeMb          { get; set; } = 100;

    [JsonPropertyName("scan_archives")]
    public bool ScanArchives          { get; set; } = false;

    [JsonPropertyName("scan_removable")]
    public bool ScanRemovable         { get; set; } = false;

    [JsonPropertyName("heuristic_enabled")]
    public bool HeuristicEnabled      { get; set; } = false;

    [JsonPropertyName("cloud_enabled")]
    public bool CloudEnabled          { get; set; } = true;

    [JsonPropertyName("network_shield_enabled")]
    public bool NetworkShieldEnabled  { get; set; } = true;

    [JsonPropertyName("resident_shield_enabled")]
    public bool ResidentShieldEnabled { get; set; } = true;

    [JsonPropertyName("cloud_for_unknown_only")]
    public bool CloudForUnknownOnly   { get; set; } = true;

    [JsonPropertyName("trust_whitelist")]
    public bool TrustWhitelist        { get; set; } = true;

    [JsonPropertyName("log_level")]
    public string LogLevel            { get; set; } = "Info";

    [JsonPropertyName("notifications")]
    public bool Notifications         { get; set; } = true;

    [JsonPropertyName("notification_sound")]
    public bool NotificationSound     { get; set; } = true;

    [JsonPropertyName("malscan_path")]
    public string MalscanPath         { get; set; } = "";

    [JsonPropertyName("queue_capacity")]
    public int QueueCapacity          { get; set; } = 4000;

    [JsonPropertyName("scan_workers")]
    public int ScanWorkers            { get; set; } = 4;

    [JsonPropertyName("dedup_window_ms")]
    public int DedupWindowMs          { get; set; } = 10_000;

    [JsonPropertyName("change_debounce_ms")]
    public int ChangeDebounceMs       { get; set; } = 300;

    [JsonPropertyName("watched_extensions")]
    public List<string> WatchedExtensions { get; set; } = DefaultWatchedExtensions();

    public static List<string> DefaultWatchedExtensions() => new()
    {
        ".exe", ".dll", ".sys", ".drv", ".cpl", ".ocx", ".ax", ".com", ".scr", ".pif",
        ".elf", ".so", ".bin", ".out", ".apk", ".apx", ".appx", ".msix",

        ".msi", ".msp", ".msc", ".cab",

        ".bat", ".cmd", ".ps1", ".ps2", ".psm1", ".vbs", ".vbe", ".js", ".jse",
        ".hta", ".wsf", ".wsh", ".sh", ".py", ".pyc", ".pyw", ".rb", ".pl", ".php",

        ".lnk", ".url", ".reg", ".inf",

        ".doc", ".docx", ".docm", ".rtf", ".xls", ".xlsx", ".xlsm", ".csv",
        ".ppt", ".pptx", ".pptm", ".pdf", ".one", ".pub",

        ".html", ".htm", ".svg", ".xml", ".chm",

        ".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".gz", ".tar",

        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".ico", ".webp",

        ".mp3", ".wav", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".m4a", ".mpg", ".mpeg",

        ".jar",
    };

    [JsonPropertyName("scan_all_extensions")]
    public bool ScanAllExtensions     { get; set; } = false;

    [JsonPropertyName("exclusions")]
    public List<ExclusionEntry> Exclusions { get; set; } = DefaultExclusions();

    [JsonIgnore]
    public List<string> ExcludedPaths =>
        Exclusions.Where(e => e.Scope is "shield" or "both")
                  .Select(e => e.Path).Where(p => !string.IsNullOrWhiteSpace(p)).ToList();

    public static List<ExclusionEntry> DefaultExclusions()
    {
        var list = new List<ExclusionEntry>();

        foreach (var p in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows Defender"),
        })
        {
            if (Directory.Exists(p)) list.Add(new() { Path = p.TrimEnd('\\') + "\\", Scope = "both" });
        }

        foreach (var cache in FindEdgeCacheDirs())
            list.Add(new() { Path = cache.TrimEnd('\\') + "\\", Scope = "both" });

        return list;
    }

    private static IEnumerable<string> FindEdgeCacheDirs()
    {
        var roots = new List<string>();
        try
        {
            var usersDir = Path.GetDirectoryName(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            if (usersDir != null && Directory.Exists(usersDir))
            {
                foreach (var user in Directory.EnumerateDirectories(usersDir))
                {
                    var edge = Path.Combine(user, "AppData", "Local",
                        "Microsoft", "Edge", "User Data");
                    if (Directory.Exists(edge)) roots.Add(edge);
                }
            }
        }
        catch { }

        foreach (var root in roots)
        {
            string[] sub = { "Cache", "Code Cache", "GPUCache", "Service Worker" };
            IEnumerable<string> profiles;
            try { profiles = Directory.EnumerateDirectories(root)
                .Where(d => Path.GetFileName(d).StartsWith("Default")
                         || Path.GetFileName(d).StartsWith("Profile")); }
            catch { continue; }

            foreach (var prof in profiles)
                foreach (var s in sub)
                {
                    var c = Path.Combine(prof, s);
                    if (Directory.Exists(c)) yield return c;
                }
        }
    }

    [JsonPropertyName("ransomware_file_threshold")]
    public int RansomwareFileThreshold { get; set; } = 25;

    [JsonPropertyName("ransomware_window_ms")]
    public int RansomwareWindowMs      { get; set; } = 5000;

    [JsonPropertyName("ransomware_detect")]
    public RansomwareDetectFlags RansomwareDetect { get; set; } = new();

    [JsonPropertyName("backup_engine_pipe")]
    public string BackupEnginePipe { get; set; } = "malward-backup";

    [JsonPropertyName("boot_backup")]
    public bool BootBackup { get; set; } = true;

    [JsonPropertyName("auto_restore_ransomware")]
    public bool AutoRestoreRansomware { get; set; } = true;

    public static string ConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-settings.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented        = true,
        PropertyNamingPolicy = null,
    };

    public void CopyFrom(ShieldConfig other)
    {
        if (other == null || ReferenceEquals(other, this)) return;
        foreach (var p in typeof(ShieldConfig).GetProperties(
                     System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
        {
            if (!p.CanRead || !p.CanWrite || p.GetIndexParameters().Length > 0) continue;
            try { p.SetValue(this, p.GetValue(other)); } catch { }
        }
    }

    public static ShieldConfig Load(string? path = null)
    {
        string target = path ?? ConfigPath;
        try
        {
            if (File.Exists(target))
            {
                var raw = File.ReadAllText(target);
                var cfg = JsonSerializer.Deserialize<ShieldConfig>(raw, JsonOpts) ?? new();
                cfg.StripLegacySystemExclusions();

                try { cfg.Save(target); }
                catch (Exception ex)
                {
                    try { Log.Warn("Config", $"Could not backfill {target}: {ex.Message} — continuing with the parsed settings."); }
                    catch { }
                    Console.Error.WriteLine($"[Config] Could not backfill {target}: {ex.Message} — continuing with the parsed settings.");
                }
                Console.WriteLine($"[Config] Loaded: {target}");
                return cfg;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[Config] Failed to read {target}: {ex.Message} — using defaults in memory only; the file is left untouched.");
            try { Log.Error("Config", $"Failed to read {target}: {ex.Message} — using defaults in memory only; the file is left untouched."); }
            catch { }
            return new ShieldConfig();
        }

        var defaults = new ShieldConfig();
        defaults.Save(target);
        Console.WriteLine($"[Config] Created default file: {target}");
        return defaults;
    }

    private static readonly object FlagPeekLock = new();
    private static bool _netFlagCached = true;
    private static long _netFlagReadAt = long.MinValue;
    private static readonly TimeSpan FlagPeekTtl = TimeSpan.FromSeconds(2);

    public static bool PeekNetworkShieldEnabled()
    {
        lock (FlagPeekLock)
        {
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            if (_netFlagReadAt != long.MinValue
                && System.Diagnostics.Stopwatch.GetElapsedTime(_netFlagReadAt, now) < FlagPeekTtl)
                return _netFlagCached;

            bool value = true;
            try
            {
                if (File.Exists(ConfigPath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(ConfigPath));
                    if (doc.RootElement.ValueKind == JsonValueKind.Object
                        && doc.RootElement.TryGetProperty("network_shield_enabled", out var el)
                        && el.ValueKind == JsonValueKind.False)
                        value = false;
                }
            }
            catch { value = true; }

            _netFlagCached = value;
            _netFlagReadAt = now;
            return value;
        }
    }

    public readonly record struct ModuleFlags(bool Resident, bool Network, bool Backup);

    private static ModuleFlags _moduleFlagsCached = new(true, true, true);
    private static long _moduleFlagsReadAt = long.MinValue;

    public static ModuleFlags ModuleFlagsNow()
    {
        lock (FlagPeekLock)
        {
            long now = System.Diagnostics.Stopwatch.GetTimestamp();
            if (_moduleFlagsReadAt != long.MinValue
                && System.Diagnostics.Stopwatch.GetElapsedTime(_moduleFlagsReadAt, now) < FlagPeekTtl)
                return _moduleFlagsCached;

            bool resident = true, network = true;
            try
            {
                if (File.Exists(ConfigPath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(ConfigPath));
                    if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        if (doc.RootElement.TryGetProperty("resident_shield_enabled", out var r)
                            && r.ValueKind == JsonValueKind.False)
                            resident = false;
                        if (doc.RootElement.TryGetProperty("network_shield_enabled", out var n)
                            && n.ValueKind == JsonValueKind.False)
                            network = false;
                    }
                }
            }
            catch { resident = true; network = true; }

            bool backup = true;
            try
            {
                var bkPath = Malward.BackupEngine.BackupConfig.DefaultConfigPath;
                if (File.Exists(bkPath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(bkPath));
                    if (doc.RootElement.ValueKind == JsonValueKind.Object
                        && doc.RootElement.TryGetProperty("enabled", out var b)
                        && b.ValueKind == JsonValueKind.False)
                        backup = false;
                }
            }
            catch { backup = true; }

            _moduleFlagsCached = new ModuleFlags(resident, network, backup);
            _moduleFlagsReadAt = now;
            return _moduleFlagsCached;
        }
    }

    public void StripLegacySystemExclusions()
    {
        var legacy = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)",
        };
        Exclusions.RemoveAll(e =>
            e?.Path != null && legacy.Contains(e.Path.TrimEnd('\\', '/')));
    }

    public void Save(string? path = null)
    {
        string target = path ?? ConfigPath;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(target, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Config] Błąd zapisu ({target}): {ex.Message}");
        }
    }

    public LogLevel ResolveLogLevel() => LogLevel.Trim().ToLowerInvariant() switch
    {
        "debug" => Malward.ResidentShield.LogLevel.Debug,
        "warn" or "warning" => Malward.ResidentShield.LogLevel.Warn,
        "error" => Malward.ResidentShield.LogLevel.Error,
        _       => Malward.ResidentShield.LogLevel.Info,
    };
}
