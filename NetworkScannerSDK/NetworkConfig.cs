using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Malward.NetworkScanner;

public sealed class NetworkConfig
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("upstream_dns")]
    public string UpstreamDns { get; set; } = "94.140.14.14";

    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "local+cloud";

    [JsonPropertyName("url_cloud_only")]
    public bool UrlCloudOnly { get; set; } = true;

    [JsonIgnore]
    public bool IsCloudUrlOnly =>
        UrlCloudOnly && string.Equals(Mode, "local+cloud", StringComparison.OrdinalIgnoreCase);

    [JsonPropertyName("sensitivity_profile")]
    public string SensitivityProfile { get; set; } = "medium";

    [JsonPropertyName("ad_blocking")]
    public bool AdBlockingEnabled { get; set; } = false;

    public string GetServerProfileName()
    {
        var lvl = (SensitivityProfile ?? "medium").ToLowerInvariant();
        if (lvl != "low" && lvl != "medium" && lvl != "high") lvl = "medium";
        return AdBlockingEnabled ? lvl + "-ads" : lvl;
    }

    [JsonPropertyName("exclusions")]
    public List<string> Exclusions { get; set; } = new(DefaultSafeDomains);

    public static readonly string[] PackageRegistryDomains =
    {
        "pypi.org", "pythonhosted.org", "python.org",
        "npmjs.org", "npmjs.com", "nodejs.org",
        "nuget.org", "crates.io", "rubygems.org", "packagist.org",
        "maven.org", "gradle.org", "golang.org", "go.dev", "sum.golang.org",
        "debian.org", "ubuntu.com", "archlinux.org", "fedoraproject.org",
        "dotnet.microsoft.com", "visualstudio.com", "nvidia.com",
    };

    public static readonly string[] DefaultSafeDomains =
    {
        "microsoft.com", "windowsupdate.com", "windows.com", "office.com", "live.com",
        "msn.com", "office365.com", "sharepoint.com", "onedrive.com", "skype.com",
        "google.com", "gstatic.com", "googleapis.com", "youtube.com", "bing.com",
        "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "cloudflare.com",

        "facebook.com", "instagram.com", "messenger.com", "whatsapp.com", "twitter.com",
        "x.com", "linkedin.com", "reddit.com", "discord.com", "telegram.org",

        "wikipedia.org", "stackoverflow.com", "github.com", "githubusercontent.com",

        "netflix.com", "spotify.com", "twitch.tv",

        "onet.pl", "wp.pl", "interia.pl", "gazeta.pl", "tvn24.pl", "rmf24.pl",
        "polsatnews.pl", "tvp.pl", "tvp.info", "wyborcza.pl", "fakt.pl", "naszemiasto.pl",
        "money.pl", "bankier.pl", "wprost.pl", "rp.pl", "polskieradio.pl",

        "allegro.pl", "olx.pl", "ceneo.pl", "morele.net", "x-kom.pl", "empik.com",
        "rossmann.pl", "mediaexpert.pl", "euro.com.pl", "neonet.pl", "ikea.com",

        "pkobp.pl", "ipko.pl", "mbank.pl", "ing.pl", "santander.pl", "bankmillennium.pl",
        "aliorbank.pl", "pekao.com.pl", "credit-agricole.pl", "bnpparibas.pl", "citibank.pl",

        "gov.pl", "epuap.gov.pl", "obywatel.gov.pl", "podatki.gov.pl", "zus.pl",

        "icm.edu.pl",
    };

    [JsonPropertyName("auto_set_system_dns")]
    public bool AutoSetSystemDns { get; set; } = true;

    [JsonPropertyName("low_memory")]
    public bool LowMemory { get; set; } = true;

    [JsonPropertyName("log_to_file")]
    public bool LogToFile { get; set; } = false;

    [JsonPropertyName("log_level")]
    public string LogLevel { get; set; } = "Info";

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "network-settings.json");

    public static NetworkConfig Load(string? explicitPath)
    {
        var path = explicitPath ?? DefaultPath;
        try
        {
            if (File.Exists(path))
            {
                var raw = File.ReadAllText(path);
                var opts = new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip };
                var cfg = JsonSerializer.Deserialize<NetworkConfig>(raw, opts);
                if (cfg != null)
                {
                    bool untouched = cfg.Exclusions == null || cfg.Exclusions.Count == 0
                        || (cfg.Exclusions.Count == 1 &&
                            string.Equals(cfg.Exclusions[0]?.Trim(), "microsoft.com", StringComparison.OrdinalIgnoreCase));
                    if (untouched) cfg.Exclusions = new List<string>(DefaultSafeDomains);
                    return cfg;
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn("Config", $"Failed to read {path}: {ex.Message} — using defaults.");
        }
        return new NetworkConfig();
    }

    public LogLevel ResolveLogLevel() => LogLevel switch
    {
        "Debug" => NetworkScanner.LogLevel.Debug,
        "Warn"  => NetworkScanner.LogLevel.Warn,
        "Error" => NetworkScanner.LogLevel.Error,
        _       => NetworkScanner.LogLevel.Info,
    };

    public static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte>
        SessionExclusions = new(StringComparer.OrdinalIgnoreCase);

    public bool IsExcluded(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        var d = domain.ToLowerInvariant().TrimStart('.');

        foreach (var ex in PackageRegistryDomains)
            if (d == ex || d.EndsWith("." + ex, StringComparison.Ordinal)) return true;

        foreach (var raw in Exclusions)
        {
            var ex = raw?.ToLowerInvariant().TrimStart('.');
            if (string.IsNullOrEmpty(ex)) continue;
            if (d == ex || d.EndsWith("." + ex, StringComparison.Ordinal)) return true;
        }

        foreach (var ex in SessionExclusions.Keys)
        {
            if (d == ex || d.EndsWith("." + ex, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}
