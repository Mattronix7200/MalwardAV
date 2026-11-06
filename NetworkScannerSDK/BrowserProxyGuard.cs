using System.Text;
using Microsoft.Win32;

namespace Malward.NetworkScanner;

public sealed class BrowserProxyGuard
{
    private static readonly string SnapshotPath = Path.Combine(PolicyGuard.DataDir, "proxy-snapshot.json");

    private const string EdgeKey    = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string ChromeKey  = @"SOFTWARE\Policies\Google\Chrome";
    private const string BraveKey   = @"SOFTWARE\Policies\BraveSoftware\Brave";
    private const string VivaldiKey = @"SOFTWARE\Policies\Vivaldi";
    private const string OperaKey   = @"SOFTWARE\Policies\Opera Software\Opera";
    private const string FirefoxKey = @"SOFTWARE\Policies\Mozilla\Firefox\Proxy";
    private const string FirefoxCertKey = @"SOFTWARE\Policies\Mozilla\Firefox\Certificates";

    public static string Pac(int port) =>
        "function FindProxyForURL(url, host) {"
        + " if (isPlainHostName(host) || host == '127.0.0.1' || host == 'localhost'"
        + " || shExpMatch(host, '*.local') || shExpMatch(host, '*.lan')) return 'DIRECT';"
        + " return 'PROXY 127.0.0.1:" + port + "; DIRECT';"
        + " }";

    public static string PacUrl(int port) =>
        "data:application/x-ns-proxy-autoconfig;base64,"
        + Convert.ToBase64String(Encoding.UTF8.GetBytes(Pac(port)));

    public static string ChromiumSettings(int port) =>
        "{\"ProxyMode\":\"pac_script\",\"ProxyPacUrl\":\"" + PacUrl(port) + "\"}";

    public static PolicyGuard.Policy[] PoliciesFor(int port)
    {
        string chromium = ChromiumSettings(port);
        string pac = PacUrl(port);
        return new PolicyGuard.Policy[]
        {
            new(EdgeKey,    "ProxySettings", RegistryValueKind.String, chromium, "Microsoft Edge"),
            new(ChromeKey,  "ProxySettings", RegistryValueKind.String, chromium, "Google Chrome"),
            new(BraveKey,   "ProxySettings", RegistryValueKind.String, chromium, "Brave"),
            new(VivaldiKey, "ProxySettings", RegistryValueKind.String, chromium, "Vivaldi"),
            new(OperaKey,   "ProxySettings", RegistryValueKind.String, chromium, "Opera"),
            new(FirefoxKey, "Mode",          RegistryValueKind.String, "autoConfig", "Mozilla Firefox"),
            new(FirefoxKey, "AutoConfigURL", RegistryValueKind.String, pac,          "Mozilla Firefox"),
            new(FirefoxKey, "Locked",        RegistryValueKind.DWord,  1,            "Mozilla Firefox"),

            new(FirefoxCertKey, "ImportEnterpriseRoots", RegistryValueKind.DWord, 1, "Mozilla Firefox"),
        };
    }

    public static bool HasPendingSnapshot() => File.Exists(SnapshotPath);

    public void Apply(int port)
    {
        var touched = PolicyGuard.Apply(PoliciesFor(port), SnapshotPath, "HttpFilter");
        if (touched.Count > 0)
            Log.Info("HttpFilter", $"Browsers routed through the address filter on 127.0.0.1:{port}: "
                                   + string.Join(", ", touched)
                                   + " — a running browser picks this up after it restarts. Firefox was "
                                   + "also told to read the Windows certificate store, without which it "
                                   + "rejects our certificate and nothing inside HTTPS can be filtered.");
        else
            Log.Debug("HttpFilter", "Browser proxy policy was already in place.");
    }

    public void Restore()
    {
        int count = PolicyGuard.Restore(SnapshotPath, "HttpFilter");
        if (count > 0) Log.Info("HttpFilter", $"Browser proxy policy restored ({count} value(s)).");
    }
}
