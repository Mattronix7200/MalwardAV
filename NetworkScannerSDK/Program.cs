using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Malward.NetworkScanner;

internal static class Program
{
    public const string ServiceName = "MalwardNetworkScanner";

    private static async Task<int> Main(string[] args)
    {
        if (Environment.UserInteractive)
        {
            ShowInteractiveRefusal();
            return 3;
        }

        if (!IsElevated()) return 2;

        NetworkConfig config;
        try { config = NetworkConfig.Load(null); }
        catch { return 2; }

        Log.MinLevel = config.ResolveLogLevel();
        Log.FileLoggingEnabled = config.LogToFile;

        var standDown = StandaloneStandDownReason();
        if (standDown != null)
        {
            Log.Info("Service", $"netmonitor.exe is standing down: {standDown}. Not starting the network shield.");

            if (standDown == StandDownShieldDisabled)
            {
                try { await new SystemDnsManager().RecoverStaleAsync(); }
                catch (Exception ex) { Log.Warn("Service", $"DNS self-repair on stand-down failed: {ex.Message}"); }
            }
            Log.Shutdown();
            return 0;
        }

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(o => o.ServiceName = ServiceName);
        builder.Services.AddSingleton(config);
        builder.Services.AddHostedService<NetworkWorker>();

        var host = builder.Build();
        await host.RunAsync();
        Log.Shutdown();
        return 0;
    }

    private const string ShieldHostServiceName = "MalwardResidentShield";

    private static readonly string ShieldSettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-settings.json");

    private const string StandDownShieldDisabled = "the network shield is disabled in shield-settings.json";

    private static string? StandaloneStandDownReason()
    {
        try
        {
            if (File.Exists(ShieldSettingsPath))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(ShieldSettingsPath));
                if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
                    && doc.RootElement.TryGetProperty("network_shield_enabled", out var el)
                    && el.ValueKind == System.Text.Json.JsonValueKind.False)
                    return StandDownShieldDisabled;
            }
        }
        catch (Exception ex)
        {
            Log.Warn("Service", $"Could not read {ShieldSettingsPath}: {ex.Message} — assuming enabled.");
        }

        try
        {
            foreach (var sc in System.ServiceProcess.ServiceController.GetServices())
            {
                using (sc)
                {
                    if (string.Equals(sc.ServiceName, ShieldHostServiceName, StringComparison.OrdinalIgnoreCase))
                        return $"the {ShieldHostServiceName} service is installed and hosts the network shield itself";
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn("Service", $"Could not enumerate services: {ex.Message} — assuming no shield host.");
        }
        return null;
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void ShowInteractiveRefusal()
    {
        const string msg =
            "Malward Network Scanner to usługa systemowa.\n\n" +
            "Nie można jej uruchomić bezpośrednio. Włącz osłonę sieciową " +
            "w aplikacji Malward (zakładka „Ochrona”).";
        try { MessageBoxW(IntPtr.Zero, msg, "Malward(R) Network Scanner", 0x40 ); }
        catch { try { Console.Error.WriteLine(msg); } catch { } }
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
