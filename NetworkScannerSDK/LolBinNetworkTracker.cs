using System.Collections.Concurrent;

namespace Malward.NetworkScanner;

public sealed class LolBinNetworkTracker
{
    private static readonly HashSet<string> DefaultLolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe",
        "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
        "python.exe", "pythonw.exe",

        "ftp.exe", "tftp.exe",

        "msiexec.exe",
    };

    private static readonly string[] LegitimateLolBinDomains =
    [
        "microsoft.com", "windowsupdate.com", "windows.com", "msftncsi.com",
        "msftconnecttest.com", "azureedge.net", "powershellgallery.com",
        "ps.gallerycdn.net", "nuget.org", "github.com", "githubusercontent.com",
        "githubassets.com", "live.com", "office.com", "visualstudio.com",

        "digicert.com", "verisign.com", "entrust.net", "globalsign.com",
        "comodoca.com", "letsencrypt.org",
    ];

    private readonly ConcurrentDictionary<string, DateTime> _lastAlert = new();
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

    private readonly HashSet<string> _lolBinSet;
    private readonly ActivityReporter _activity;

    public LolBinNetworkTracker(ActivityReporter activity, IEnumerable<string>? customLolBins = null)
    {
        _activity = activity;
        _lolBinSet = customLolBins != null
            ? new HashSet<string>(customLolBins, StringComparer.OrdinalIgnoreCase)
            : DefaultLolBins;
    }

    public bool TryReportLolBinQuery(string? processName, string domain)
    {
        if (string.IsNullOrEmpty(processName) || string.IsNullOrEmpty(domain)) return false;
        if (!_lolBinSet.Contains(processName)) return false;

        if (IsWhitelistedDomain(domain)) return false;

        var key = processName + "|" + domain.ToLowerInvariant();
        var now = DateTime.UtcNow;
        if (_lastAlert.TryGetValue(key, out var last) && (now - last) < AlertCooldown)
            return false;
        _lastAlert[key] = now;

        if (_lastAlert.Count > 5000)
        {
            var cutoff = now - AlertCooldown;
            foreach (var kv in _lastAlert)
                if (kv.Value < cutoff) _lastAlert.TryRemove(kv.Key, out _);
        }

        var det = $"LolBin.Network!{processName}→{domain}";
        _activity.ReportBlock(domain, detection: det, source: "lolbin", process: processName);
        Log.Alert("LolBin",
            $"Process {processName} próbował połączyć się z {domain} (DNS query). " +
            "Klasyczny wektor download/exec malware.");
        return true;
    }

    private static bool IsWhitelistedDomain(string domain)
    {
        var d = domain.ToLowerInvariant().TrimStart('.').TrimEnd('.');
        foreach (var w in LegitimateLolBinDomains)
        {
            if (d == w || d.EndsWith("." + w, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}
