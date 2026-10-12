using System.Text.Json;
using System.Text.Json.Serialization;
using Malward.Engine.Util;

namespace Malward.Engine.Config;

public sealed class Settings
{
    [JsonPropertyName("max_file_size_mb")]
    public int MaxFileSizeMb { get; set; } = 100;

    [JsonPropertyName("inspect_oversized_containers")]
    public bool InspectOversizedContainers { get; set; } = true;

    [JsonPropertyName("max_scan_time_per_file_sec")]
    public int MaxScanTimePerFileSec { get; set; } = 30;

    [JsonPropertyName("max_upload_to_cloud_sec")]
    public int MaxUploadToCloudSec { get; set; } = 60;

    [JsonPropertyName("ext_filter_mode")]
    public string ExtFilterMode { get; set; } = "all";

    [JsonPropertyName("ext_list_common")]
    public List<string> ExtListCommon { get; set; } = new()
    {
        "EXE","DLL","DRV","SYS","VBS","VBE","JS","JSE","BAT","CMD","PS1","PSM1","SH","COM",
        "SCR","HTA","MSI","JAR","WSF","WSH","DOC","DOCM","XLS","XLSM","PPT",
        "PPTM","PDF","ZIP","RAR","7Z","CAB","ISO","LNK","CHM","HTML","HTM",

        "ELF","SO","OUT","PY","PYW","PYC","RB","PL","PHP"
    };

    [JsonPropertyName("ext_blacklist")]
    public List<string> ExtBlacklist { get; set; } = new();

    [JsonPropertyName("scan_archives")]
    public bool ScanArchives { get; set; } = true;

    [JsonPropertyName("background_scan_enabled")]
    public bool BackgroundScanEnabled { get; set; } = true;

    [JsonPropertyName("heuristic_enabled")]
    public bool HeuristicEnabled { get; set; } = false;

    [JsonPropertyName("script_analysis_enabled")]
    public bool ScriptAnalysisEnabled { get; set; } = true;

    [JsonPropertyName("heuristic_realtime_enabled")]
    public bool HeuristicRealtimeEnabled { get; set; } = true;

    [JsonPropertyName("cloud_scan_enabled")]
    public bool CloudScanEnabled { get; set; } = true;

    [JsonPropertyName("cloud_verify_detections")]
    public bool CloudVerifyDetections { get; set; } = true;

    [JsonPropertyName("scan_optimization")]
    public bool ScanOptimization { get; set; } = true;

    [JsonPropertyName("scan_max_parallelism")]
    public int ScanMaxParallelism { get; set; } = 0;

    [JsonPropertyName("scan_cpu_limit_percent")]
    public int ScanCpuLimitPercent { get; set; } = 50;

    [JsonPropertyName("trust_whitelist")]
    public bool TrustWhitelist { get; set; } = true;

    [JsonPropertyName("skip_ms_signed")]
    public bool SkipMsSigned { get; set; } = false;

    [JsonIgnore]
    public int ScanLevel { get; set; } = 4;

    [JsonIgnore]
    public string ServerIp { get; set; } = "83.168.95.69";

    [JsonIgnore]
    public int ServerPort { get; set; } = 5000;

    public const string DefaultServerCertPinSha256 =
        "fd927471fa9e6b05a51459d37989791272860b63e667e34c37e73e321708a0e0";

    [JsonIgnore]
    public string? ServerCertPinSha256 { get; set; } = DefaultServerCertPinSha256;

    [JsonIgnore]
    public string ClientToken { get; set; } = Cloud.ClientSecrets.AuthPsk;

    [JsonPropertyName("quarantine_size_limit_mb")]
    public int QuarantineSizeLimitMb { get; set; } = 5120;

    [JsonPropertyName("repair_mode")]
    public int RepairMode { get; set; } = 1;

    [JsonPropertyName("archive_repair_mode")]
    public int ArchiveRepairMode { get; set; } = 1;

    [JsonPropertyName("archive_max_depth")]
    public int ArchiveMaxDepth { get; set; } = 5;

    [JsonPropertyName("archive_max_size_mb")]
    public int ArchiveMaxSizeMb { get; set; } = 250;

    [JsonPropertyName("archive_extensions")]
    public List<string> ArchiveExtensions { get; set; } = new();

    [JsonPropertyName("memory_scan")]
    public bool MemoryScan { get; set; } = true;

    [JsonPropertyName("sysrepair_disabled")]
    public List<string> SysRepairDisabled { get; set; } = new();

    [JsonPropertyName("memory_scan_check_whitelist")]
    public bool MemoryScanCheckWhitelist { get; set; } = false;

    [JsonPropertyName("exceptions")]
    public List<string> Exceptions { get; set; } = new();

    [JsonPropertyName("gui_theme")]
    public string GuiTheme { get; set; } = "light";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public static Settings Load()
    {
        Paths.EnsureDirs();
        var path = Paths.SettingsFile;
        if (!File.Exists(path))
        {
            var fresh = new Settings();
            fresh.Save();
            return fresh;
        }
        try
        {
            var json = File.ReadAllText(path);
            var s = JsonSerializer.Deserialize<Settings>(json, JsonOpts) ?? new Settings();

            s.Save();
            ApplyEnvOverrides(s);
            return s;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] settings.json corrupted: {ex.Message} — using defaults");
            var fresh = new Settings();
            fresh.Save();
            ApplyEnvOverrides(fresh);
            return fresh;
        }
    }

    private static void ApplyEnvOverrides(Settings s)
    {
        if (Environment.GetEnvironmentVariable("MALWARD_NO_CLOUD") == "1")
            s.CloudScanEnabled = false;

        if (Environment.GetEnvironmentVariable("MALWARD_FORCE_UPLOAD") == "1")
        {
            s.CloudScanEnabled = true;
            s.ScanOptimization = false;
        }
    }

    public void Save()
    {
        Paths.EnsureDirs();
        var json = JsonSerializer.Serialize(this, JsonOpts);
        File.WriteAllText(Paths.SettingsFile, json);
    }
}
