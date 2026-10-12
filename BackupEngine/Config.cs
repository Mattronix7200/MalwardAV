using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.BackupEngine;

public sealed class BackupConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("watch_folders")]
    public List<string> WatchFolders { get; set; } = new()
    {
        @"%USERPROFILE%\Documents",
        @"%USERPROFILE%\Desktop",
        @"%USERPROFILE%\Pictures",
        @"%USERPROFILE%\Videos",
        @"%USERPROFILE%\Downloads",
        @"%USERPROFILE%\Music",
    };

    [JsonPropertyName("exclude_globs")]
    public List<string> ExcludeGlobs { get; set; } = new()
    {
        "*.tmp", "*.lock", "*~", "*.log", "*.bak",
        ".git/**", "node_modules/**", "__pycache__/**",
        "*.pyc", "AppData/Local/Temp/**", "Temp/**",
        "$RECYCLE.BIN/**", "System Volume Information/**",
    };

    [JsonPropertyName("max_file_size_mb")]
    public int MaxFileSizeMb { get; set; } = 500;

    [JsonPropertyName("schedule")]
    public string Schedule { get; set; } = "dailyAt:02:00";

    [JsonPropertyName("on_file_change")]
    public bool OnFileChange { get; set; } = true;

    [JsonPropertyName("debounce_seconds")]
    public int DebounceSeconds { get; set; } = 5;

    [JsonPropertyName("compression_mode")]
    public int CompressionMode { get; set; } = 0;

    [JsonPropertyName("per_file_rate_min")]
    public int PerFileRateMin { get; set; } = 0;

    [JsonPropertyName("retention_versions")]
    public int RetentionVersions { get; set; } = 0;

    [JsonPropertyName("backup_size_limit_percent")]
    public int BackupSizeLimitPercent { get; set; } = 10;

    [JsonPropertyName("ransomware_detect")]
    public RansomwareDetectConfig RansomwareDetect { get; set; } = new();

    [JsonPropertyName("bkf_path")]
    public string BkfPath { get; set; } = "";

    public static string DefaultBkfPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "backup", "malward.bkf");

    public static string DefaultConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "backup", "settings.json");

    public string ResolvedBkfPath() => string.IsNullOrEmpty(BkfPath) ? DefaultBkfPath : BkfPath;

    public CompressionMode ResolvedCompression()
        => CompressionMode switch
        {
            1 => Malward.BackupEngine.CompressionMode.Deflate,
            2 => Malward.BackupEngine.CompressionMode.Brotli,
            _ => Malward.BackupEngine.CompressionMode.None,
        };

    public string NormalizedSchedule()
    {
        var s = (Schedule ?? "off").Trim();
        return s switch
        {
            "5min"       => "everyN:5",
            "15min"      => "everyN:15",
            "1h"         => "everyN:60",
            "6h"         => "everyN:360",
            "daily-2am"  => "dailyAt:02:00",
            "daily-3am"  => "dailyAt:03:00",
            "weekly-sun" => "weeklyAt:0:03:00",
            _ => s,
        };
    }

    public static BackupConfig Load(string? explicitPath = null)
    {
        var path = explicitPath ?? DefaultConfigPath;
        try
        {
            if (File.Exists(path))
            {
                var raw = File.ReadAllText(path);
                var opts = new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip };
                var cfg = JsonSerializer.Deserialize<BackupConfig>(raw, opts);
                if (cfg != null) return cfg;
            }
        }
        catch { }
        return new BackupConfig();
    }

    public void Save(string? explicitPath = null)
    {
        var path = explicitPath ?? DefaultConfigPath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var opts = new JsonSerializerOptions { WriteIndented = true };
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, opts));
        if (File.Exists(path))
            File.Replace(tmp, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
        else
            File.Move(tmp, path);
    }
}

public sealed class RansomwareDetectConfig
{
    [JsonPropertyName("mass_rename")]
    public bool MassRename { get; set; } = true;

    [JsonPropertyName("mass_rename_threshold")]
    public int MassRenameThreshold { get; set; } = 50;

    [JsonPropertyName("mass_rename_window_s")]
    public int MassRenameWindowS { get; set; } = 30;

    [JsonPropertyName("entropy_check")]
    public bool EntropyCheck { get; set; } = true;

    [JsonPropertyName("entropy_threshold")]
    public double EntropyThreshold { get; set; } = 7.8;

    [JsonPropertyName("ransom_note_signatures")]
    public bool RansomNoteSignatures { get; set; } = true;

    [JsonPropertyName("vss_hook")]
    public bool VssDeleteHook { get; set; } = true;

    [JsonPropertyName("io_anomaly")]
    public bool IoAnomaly { get; set; } = false;

    [JsonPropertyName("io_anomaly_mb_per_min")]
    public int IoAnomalyMbPerMin { get; set; } = 100;
}
