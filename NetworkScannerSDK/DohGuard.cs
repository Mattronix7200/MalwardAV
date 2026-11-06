using Microsoft.Win32;

namespace Malward.NetworkScanner;

public sealed class DohGuard
{
    private static readonly string SnapshotPath = Path.Combine(PolicyGuard.DataDir, "doh-snapshot.json");

    private const string EdgeKey    = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string ChromeKey  = @"SOFTWARE\Policies\Google\Chrome";
    private const string BraveKey   = @"SOFTWARE\Policies\BraveSoftware\Brave";
    private const string VivaldiKey = @"SOFTWARE\Policies\Vivaldi";
    private const string OperaKey   = @"SOFTWARE\Policies\Opera Software\Opera";
    private const string FirefoxKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";
    private const string DnscacheKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";

    private static readonly PolicyGuard.Policy[] Policies =
    {
        new(EdgeKey,    "DnsOverHttpsMode",        RegistryValueKind.String,  "off", "Microsoft Edge"),
        new(EdgeKey,    "BuiltInDnsClientEnabled", RegistryValueKind.DWord,   0,     "Microsoft Edge"),
        new(ChromeKey,  "DnsOverHttpsMode",        RegistryValueKind.String,  "off", "Google Chrome"),
        new(ChromeKey,  "BuiltInDnsClientEnabled", RegistryValueKind.DWord,   0,     "Google Chrome"),
        new(BraveKey,   "DnsOverHttpsMode",        RegistryValueKind.String,  "off", "Brave"),
        new(BraveKey,   "BuiltInDnsClientEnabled", RegistryValueKind.DWord,   0,     "Brave"),
        new(VivaldiKey, "DnsOverHttpsMode",        RegistryValueKind.String,  "off", "Vivaldi"),
        new(OperaKey,   "DnsOverHttpsMode",        RegistryValueKind.String,  "off", "Opera"),
        new(FirefoxKey, "Enabled",                 RegistryValueKind.DWord,   0,     "Mozilla Firefox"),
        new(FirefoxKey, "Locked",                  RegistryValueKind.DWord,   1,     "Mozilla Firefox"),
        new(DnscacheKey, "EnableAutoDoh",          RegistryValueKind.DWord,   0,     "Windows"),
    };

    public static readonly string[] ValueNames =
    {
        "dnsoverhttpsmode", "builtindnsclientenabled", "enableautodoh",
    };

    private static readonly string[] BootstrapHosts =
    {
        "dns.google", "dns64.dns.google", "chrome.cloudflare-dns.com", "mozilla.cloudflare-dns.com",
        "cloudflare-dns.com", "one.one.one.one", "security.cloudflare-dns.com",
        "family.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net",
        "dns11.quad9.net", "dns.nextdns.io", "doh.opendns.com", "doh.familyshield.opendns.com",
        "dns.adguard.com", "dns.adguard-dns.com", "unfiltered.adguard-dns.com",
        "family.adguard-dns.com", "doh.cleanbrowsing.org", "doh.dns.sb", "dns.alidns.com",
        "doh.pub", "dns.twnic.tw", "doh.libredns.gr", "odvr.nic.cz", "dns.digitale-gesellschaft.ch",
        "doh.mullvad.net", "adblock.doh.mullvad.net", "dns.controld.com", "freedns.controld.com",
    };

    public static bool IsDohEndpoint(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        var d = domain.TrimEnd('.').ToLowerInvariant();
        foreach (var host in BootstrapHosts)
            if (d == host || d.EndsWith("." + host, StringComparison.Ordinal)) return true;
        return false;
    }

    public static bool HasPendingSnapshot() => File.Exists(SnapshotPath);

    public void Apply()
    {
        var touched = PolicyGuard.Apply(Policies, SnapshotPath, "DoH");
        if (touched.Count > 0)
            Log.Info("DoH", "Encrypted DNS turned off by policy for: " + string.Join(", ", touched)
                            + " — a running browser keeps its old setting until it restarts.");
        else
            Log.Debug("DoH", "Encrypted DNS was already disabled by policy.");
    }

    public void Restore()
    {
        int count = PolicyGuard.Restore(SnapshotPath, "DoH");
        if (count > 0) Log.Info("DoH", $"Browser DNS policy restored ({count} value(s)).");
    }
}
