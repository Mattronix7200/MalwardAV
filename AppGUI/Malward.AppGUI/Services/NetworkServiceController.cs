using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class NetworkServiceController
{
    public const string ServiceName = "MalwardNetworkScanner";
    public const string DisplayName = "Malward Network Scanner";
    private const string Description =
        "Ochrona sieciowa (Malward): lokalny proxy DNS + filtr URL na bazie urls.vdeb.";

    private readonly string _exePath;

    public NetworkServiceController(string netmonitorExePath) => _exePath = netmonitorExePath;

    public static string? FindNetmonitor()
    {
        var dirs = new[]
        {
            EngineLocator.GuiExeDir,
            EngineLocator.EngineDir(),
        };
        foreach (var d in dirs)
        {
            if (string.IsNullOrEmpty(d)) continue;
            try
            {
                var p = Path.Combine(d, "netmonitor.exe");
                if (File.Exists(p)) return Path.GetFullPath(p);
            }
            catch { }
        }
        return null;
    }

    public bool IsInstalled()
    {
        try
        {
            foreach (var sc in ServiceController.GetServices())
                if (string.Equals(sc.ServiceName, ServiceName, StringComparison.OrdinalIgnoreCase))
                    return true;
        }
        catch { }
        return false;
    }

    public bool IsRunning()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            return sc.Status == ServiceControllerStatus.Running
                || sc.Status == ServiceControllerStatus.StartPending;
        }
        catch { return false; }
    }

    public string State()
    {
        var host = new ResidentServiceController(ResidentServiceController.FindShieldHost() ?? "");
        if (!host.IsInstalled()) return "not-installed";
        if (!ReadEnabledFlag()) return "stopped";
        if (!host.IsRunning()) return "stopped";

        return ResidentServiceController.ModuleRunning("network") ? "running" : "stopped";
    }

    private static string ConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-settings.json");

    private static bool ReadEnabledFlag()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return true;
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ConfigPath));
            return node?["network_shield_enabled"]?.GetValue<bool>() ?? true;
        }
        catch { return true; }
    }

    public bool IsModuleEnabled() => ReadEnabledFlag();

    private static void WriteEnabledFlag(bool on)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
            var obj = File.Exists(ConfigPath)
                ? System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ConfigPath)) as System.Text.Json.Nodes.JsonObject
                : null;
            obj ??= new System.Text.Json.Nodes.JsonObject();
            obj["network_shield_enabled"] = on;
            File.WriteAllText(ConfigPath, IndentedJson(obj));
        }
        catch { }
    }

    public async Task<(bool ok, string? error)> EnableAsync()
    {
        try
        {
            await RetireLegacyServiceAsync();

            WriteEnabledFlag(true);
            var host = new ResidentServiceController(ResidentServiceController.FindShieldHost() ?? "");
            if (!host.IsInstalled())
                return (false, "Usługa ochrony nie jest zainstalowana — zainstaluj ją, aby korzystać z osłony sieciowej.");

            return await host.EnsureHostRunningAsync();
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<(bool ok, string? error)> DisableAsync()
    {
        try
        {
            WriteEnabledFlag(false);
            await RetireLegacyServiceAsync();
            var host = new ResidentServiceController(ResidentServiceController.FindShieldHost() ?? "");
            if (!host.IsInstalled() || !host.IsRunning()) return (true, null);

            if (!ResidentServiceController.ModuleEnabled()) return await host.DisableAsync();

            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private async Task RetireLegacyServiceAsync()
    {
        try
        {
            if (!IsInstalled()) return;
            await StopAsync();
            await ScAsync($"config {ServiceName} start= disabled");
        }
        catch { }
    }

    public async Task<(bool ok, string? error)> UninstallAsync()
    {
        try
        {
            await StopAsync();
            var (rc, outp) = await ScAsync($"delete {ServiceName}");
            return rc == 0 ? (true, null) : (false, outp);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<(bool ok, string? error)> StartAsync()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status == ServiceControllerStatus.Running) return (true, null);
            if (sc.Status != ServiceControllerStatus.StartPending) sc.Start();
            await Task.Run(() => sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20)));
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<(bool ok, string? error)> StopAsync()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status == ServiceControllerStatus.Stopped) return (true, null);
            if (sc.CanStop) sc.Stop();
            await Task.Run(() => sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)));
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<(bool ok, string? error)> RestartAsync()
    {
        if (!IsInstalled()) return (false, "Usługa nie jest zainstalowana.");
        var (sok, serr) = await StopAsync();
        if (!sok) return (false, serr);
        return await StartAsync();
    }

    private static string QuotedBinPath(string exePath) => $"\"\\\"{exePath}\\\"\"";

    private static string? ReadRegistryImagePath(string serviceName)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key?.GetValue("ImagePath") as string;
        }
        catch { return null; }
    }

    private async Task ReconcileBinPathAsync()
    {
        if (string.IsNullOrEmpty(_exePath) || !File.Exists(_exePath)) return;
        try
        {
            var current = ReadRegistryImagePath(ServiceName);
            var want = Path.GetFullPath(_exePath);
            var curUnquoted = (current ?? "").Trim().Trim('"');
            bool pathChanged = !string.Equals(curUnquoted, want, StringComparison.OrdinalIgnoreCase);
            bool notQuoted   = current != null && want.Contains(' ') && !current.TrimStart().StartsWith("\"");
            if (pathChanged || notQuoted)
                await ScAsync($"config {ServiceName} binPath= {QuotedBinPath(want)}");
        }
        catch { }
    }

    private static async Task<(int rc, string output)> ScAsync(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return (-1, "nie uruchomiono sc.exe");
            string o = await p.StandardOutput.ReadToEndAsync();
            string e = await p.StandardError.ReadToEndAsync();
            await p.WaitForExitAsync();
            return (p.ExitCode, string.IsNullOrWhiteSpace(e) ? o : e);
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }

    private static string IndentedJson(System.Text.Json.Nodes.JsonNode node)
    {
        using var buffer = new MemoryStream();
        using (var writer = new System.Text.Json.Utf8JsonWriter(
                   buffer, new System.Text.Json.JsonWriterOptions { Indented = true }))
            node.WriteTo(writer);
        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }
}
