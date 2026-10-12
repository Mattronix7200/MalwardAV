using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Malward.ResidentShield;

internal static class Program
{
    public const string ServiceName = "MalwardResidentShield";

    private static async Task<int> Main(string[] args)
    {
        if (Environment.UserInteractive)
        {
            ShowInteractiveRefusal();
            return 3;
        }

        if (!IsElevated()) return 2;

        ShieldConfig config;
        try { config = ShieldConfig.Load(null); }
        catch { return 2; }

        Log.MinLevel = config.ResolveLogLevel();
        NativeProcess.EnableDebugPrivilege();

        try { if (SelfDefense.HardenCurrentProcess()) Log.Info("Shield", "Process self-defense active (deny-terminate)."); } catch { }

        InstallFolderGuard.EnsureApplied();
        InstallFolderGuard.EnsureProgramDataApplied();

        Hips.HipsRules.MarkWired(Hips.HipsFileWatcher.Detectors);
        Hips.HipsRules.MarkWired(Hips.HipsRegistryWatcher.Detectors);
        Hips.HipsRules.MarkWired(Hips.HipsWmiWatcher.Detectors);
        Hips.HipsRules.MarkWired(Hips.HipsInjectionWatcher.Detectors);
        Hips.HipsRules.ExportCatalog();

        var missingSigs = BehaviorAnalyzer.MissingSignatureKeys();
        if (missingSigs.Count > 0)
            Log.Error("Shield", $"Behavior signature database is OUT OF DATE — {missingSigs.Count} " +
                $"lists missing: {string.Join(", ", missingSigs)}. The corresponding detectors are NOT WORKING. " +
                "Regenerate sigdata.vdeb (malscan make-sigdata) and publish again.");

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(o => o.ServiceName = ServiceName);
        builder.Services.AddSingleton(config);

        builder.Services.AddHostedService<ScanTaskWorker>();

        builder.Services.AddHostedService<ModuleSupervisor>();

        RetireLegacyNetworkService();
        if (!config.NetworkShieldEnabled)
        {
            Log.Info("Shield", "Network shield: disabled by the user — not hosted in this process.");

            _ = Task.Run(RepairStaleDnsWithShieldOffAsync);
        }

        var host = builder.Build();
        await host.RunAsync();
        Log.Shutdown();
        return 0;
    }

    private static async Task RepairStaleDnsWithShieldOffAsync()
    {
        try
        {
            Malward.NetworkScanner.Log.FileLoggingEnabled = true;
            var mgr = new Malward.NetworkScanner.SystemDnsManager();
            if (Malward.NetworkScanner.SystemDnsManager.HasPendingSnapshot())
            {
                Log.Warn("Shield", "Network shield is off but a DNS snapshot is pending — restoring system DNS.");
                await mgr.RecoverStaleAsync();
            }
            int reset = await mgr.RepairOrphanedLoopbackAsync();
            if (reset > 0)
                Log.Warn("Shield", $"Network shield is off: reset {reset} interface(s) that still pointed at 127.0.0.1 with no resolver listening.");
            else
                Log.Info("Shield", "Network shield is off: no interface left on 127.0.0.1.");
        }
        catch (Exception ex)
        {
            Log.Warn("Shield", $"Stale DNS repair (shield off) failed: {ex.Message}");
        }
    }

    private static void RetireLegacyNetworkService()
    {
        const string legacy = "MalwardNetworkScanner";
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(legacy);
            _ = sc.Status;
            try
            {
                if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped && sc.CanStop)
                {
                    sc.Stop();
                    sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                }
            }
            catch { }

            RunSc($"config {legacy} start= disabled");
            Log.Info("Shield", $"Disabled the standalone service {legacy} — the network shield runs in this process.");
        }
        catch {  }
    }

    internal static void RetireLegacyBackupService()
    {
        const string legacy = "MalwardBackupEngine";
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(legacy);
            _ = sc.Status;
            try
            {
                if (sc.Status != System.ServiceProcess.ServiceControllerStatus.Stopped && sc.CanStop)
                {
                    sc.Stop();
                    sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                }
            }
            catch { }
            RunSc($"delete {legacy}");
            Log.Info("Shield", $"Removed the standalone service {legacy} — backup runs in this process.");
        }
        catch {  }

        try
        {
            foreach (var p in System.Diagnostics.Process.GetProcessesByName("bkmonitor"))
            {
                using (p)
                {
                    try { p.Kill(); p.WaitForExit(5000); Log.Info("Shield", $"Stopped the old bkmonitor process (PID {p.Id})."); }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void RunSc(string args)
    {
        try
        {
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sc.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            p?.WaitForExit(10000);
        }
        catch { }
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void ShowInteractiveRefusal()
    {
        const string msg =
            "Malward Resident Shield to usługa systemowa.\n\n" +
            "Nie można jej uruchomić bezpośrednio. Włącz ochronę rezydentną " +
            "w aplikacji Malward (zakładka „Ochrona”).";
        try { MessageBoxW(IntPtr.Zero, msg, "Malward(R) Resident Shield", 0x40 ); }
        catch { try { Console.Error.WriteLine(msg); } catch { } }
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
