using System.Text.Json;
using System.Text.Json.Serialization;
using Malward.Engine.Config;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public enum FixMode
{
    Report,
    Quarantine,
    Delete,
    Ask,
}

public enum ArchiveFixMode
{
    DropEntry,
    DeleteArchive,
}

public enum ExtensionMode
{
    All,
    Common,
    Only,
    Blacklist,
}

public sealed class ScanOptions
{
    public const int NoLimitMb = 1_000_000;

    [JsonPropertyName("cloud_scan")]           public bool CloudScan { get; set; } = true;
    [JsonPropertyName("cloud_verify")]         public bool CloudVerify { get; set; } = true;
    [JsonPropertyName("cloud_cache")]          public bool CloudCache { get; set; } = true;
    [JsonPropertyName("skip_signed")]          public bool SkipSigned { get; set; } = true;
    [JsonPropertyName("memory_scan")]          public bool MemoryScan { get; set; }
    [JsonPropertyName("archives")]             public bool Archives { get; set; }
    [JsonPropertyName("heuristics")]           public bool Heuristics { get; set; }

    [JsonPropertyName("threads")]              public int Threads { get; set; }
    [JsonPropertyName("cpu_limit")]            public int CpuLimit { get; set; } = 100;
    [JsonPropertyName("max_file_mb")]          public int MaxFileMb { get; set; } = 100;
    [JsonPropertyName("cloud_wait_sec")]       public int CloudWaitSec { get; set; } = 30;
    [JsonPropertyName("file_budget_sec")]      public int FileBudgetSec { get; set; } = 60;
    [JsonPropertyName("archive_max_mb")]       public int ArchiveMaxMb { get; set; } = 250;
    [JsonPropertyName("archive_depth")]        public int ArchiveDepth { get; set; } = 5;

    [JsonPropertyName("fix")]                  public FixMode Fix { get; set; } = FixMode.Report;
    [JsonPropertyName("archive_fix")]          public ArchiveFixMode ArchiveFix { get; set; } = ArchiveFixMode.DropEntry;
    [JsonPropertyName("extensions")]           public ExtensionMode Extensions { get; set; } = ExtensionMode.All;
    [JsonPropertyName("extension_list")]       public List<string> ExtensionList { get; set; } = new();

    [JsonIgnore] public bool AutoReport { get; set; }

    [JsonIgnore] public int EffectiveThreads => Threads > 0 ? Threads : Environment.ProcessorCount;

    [JsonIgnore] public bool CloudWeakened => !CloudScan || !CloudVerify;

    private static string StorePath => Path.Combine(Paths.DataDir, "malcsm-settings.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static ScanOptions Load()
    {
        try
        {
            if (File.Exists(StorePath))
                return JsonSerializer.Deserialize<ScanOptions>(File.ReadAllText(StorePath), JsonOpts)
                       ?? new ScanOptions();
        }
        catch { }
        return new ScanOptions();
    }

    public bool Save()
    {
        try
        {
            Directory.CreateDirectory(Paths.DataDir);
            File.WriteAllText(StorePath, JsonSerializer.Serialize(this, JsonOpts),
                              new System.Text.UTF8Encoding(false));
            return true;
        }
        catch { return false; }
    }

    public void Reset()
    {
        var fresh = new ScanOptions();
        CloudScan = fresh.CloudScan;
        CloudVerify = fresh.CloudVerify;
        CloudCache = fresh.CloudCache;
        SkipSigned = fresh.SkipSigned;
        MemoryScan = fresh.MemoryScan;
        Archives = fresh.Archives;
        Heuristics = fresh.Heuristics;
        Threads = fresh.Threads;
        CpuLimit = fresh.CpuLimit;
        MaxFileMb = fresh.MaxFileMb;
        CloudWaitSec = fresh.CloudWaitSec;
        FileBudgetSec = fresh.FileBudgetSec;
        ArchiveMaxMb = fresh.ArchiveMaxMb;
        ArchiveDepth = fresh.ArchiveDepth;
        Fix = fresh.Fix;
        ArchiveFix = fresh.ArchiveFix;
        Extensions = fresh.Extensions;
        ExtensionList = new List<string>();
    }

    public void ApplyCommandLine(CommandLine cl)
    {
        CloudScan   = cl.Flag(CloudScan,   "cs", "enable-cloud-scan", "cloud");
        CloudVerify = cl.Flag(CloudVerify, "cv", "enable-cloud-verify");
        CloudCache  = cl.Flag(CloudCache,  "cc", "use-cloud-cache");
        SkipSigned  = cl.Flag(SkipSigned,  "ss", "skip-signed");
        MemoryScan  = cl.Flag(MemoryScan,  "m",  "memory");
        Archives    = cl.Flag(Archives,    "a",  "archive");
        Heuristics  = cl.Flag(Heuristics,  "h",  "heur");

        if (cl.Has("nocloud", "offline"))
        {
            CloudScan = false;
            CloudVerify = false;
            CloudCache = false;
        }

        Threads       = cl.Number("t", "threads")                  ?? Threads;
        CpuLimit      = cl.Number("cpu", "cpu-limit")              ?? CpuLimit;
        CloudWaitSec  = cl.Number("mct", "max-cloud-time")         ?? CloudWaitSec;
        FileBudgetSec = cl.Number("mut", "max-upload-time")        ?? FileBudgetSec;
        ArchiveDepth  = cl.Number("amn", "archive-max-nesting")    ?? ArchiveDepth;

        var fileLimit = cl.Number("mfs", "max-file-size");
        if (fileLimit.HasValue) MaxFileMb = fileLimit.Value <= 0 ? NoLimitMb : fileLimit.Value;

        var archiveLimit = cl.Number("amfs", "archive-max-file-size");
        if (archiveLimit.HasValue) ArchiveMaxMb = archiveLimit.Value <= 0 ? NoLimitMb : archiveLimit.Value;

        AutoReport = cl.Has("log", "log-output");

        Clamp();
    }

    public void Clamp()
    {
        Threads = Math.Clamp(Threads, 0, 256);
        CpuLimit = Math.Clamp(CpuLimit, 5, 100);
        MaxFileMb = Math.Clamp(MaxFileMb, 1, NoLimitMb);
        CloudWaitSec = Math.Clamp(CloudWaitSec, 5, 600);
        FileBudgetSec = Math.Clamp(FileBudgetSec, 5, 3600);
        ArchiveMaxMb = Math.Clamp(ArchiveMaxMb, 1, NoLimitMb);
        ArchiveDepth = Math.Clamp(ArchiveDepth, 0, 12);
    }

    public Settings ToSettings()
    {
        var s = new Settings
        {
            CloudScanEnabled = CloudScan,
            CloudVerifyDetections = CloudVerify,
            CloudRescanDetections = CloudVerify,
            ScanOptimization = CloudCache,
            SkipMsSigned = SkipSigned,
            MemoryScan = MemoryScan,
            MemoryScanCheckWhitelist = true,
            ScanArchives = Archives,
            HeuristicEnabled = Heuristics,
            ScriptAnalysisEnabled = true,
            ScanMaxParallelism = EffectiveThreads,
            ScanCpuLimitPercent = CpuLimit,
            MaxFileSizeMb = MaxFileMb,
            MaxUploadToCloudSec = CloudWaitSec,
            MaxScanTimePerFileSec = FileBudgetSec,
            ArchiveMaxSizeMb = ArchiveMaxMb,
            ArchiveMaxDepth = ArchiveDepth,
            ArchiveRepairMode = ArchiveFix == ArchiveFixMode.DeleteArchive ? 2 : 1,
            RepairMode = Fix switch
            {
                FixMode.Quarantine => 2,
                FixMode.Delete     => 3,
                _                  => 1,
            },
        };

        switch (Extensions)
        {
            case ExtensionMode.Common:
                s.ExtFilterMode = "common";
                break;
            case ExtensionMode.Only:
                s.ExtFilterMode = "common";
                s.ExtListCommon = new List<string>(ExtensionList);
                break;
            case ExtensionMode.Blacklist:
                s.ExtFilterMode = "blacklist";
                s.ExtBlacklist = new List<string>(ExtensionList);
                break;
            default:
                s.ExtFilterMode = "all";
                break;
        }

        return s;
    }

    public static string Limit(int mb) => mb >= NoLimitMb ? "unlimited" : mb + " MB";

    [JsonIgnore] public string FixLabel => Fix switch
    {
        FixMode.Quarantine => "QUARANTINE",
        FixMode.Delete     => "DELETE",
        FixMode.Ask        => "ASK AFTER SCAN",
        _                  => "REPORT ONLY",
    };

    [JsonIgnore] public string ArchiveFixLabel =>
        ArchiveFix == ArchiveFixMode.DeleteArchive ? "DELETE ARCHIVE" : "DROP ENTRY";

    [JsonIgnore] public string ExtensionLabel => Extensions switch
    {
        ExtensionMode.Common    => "COMMON",
        ExtensionMode.Only      => "ONLY " + string.Join(",", ExtensionList),
        ExtensionMode.Blacklist => "ALL EXCEPT " + string.Join(",", ExtensionList),
        _                       => "ALL",
    };

    public string LayerSummary() => string.Join("  ", new[]
    {
        "whitelist on",
        "cloud " + OnOff(CloudScan),
        "verify " + OnOff(CloudVerify),
        "cache " + OnOff(CloudCache),
        "signed-skip " + OnOff(SkipSigned),
        "memory " + OnOff(MemoryScan),
        "archives " + OnOff(Archives),
        "heuristics " + OnOff(Heuristics),
    });

    public static string OnOff(bool value) => value ? "on" : "off";
}
