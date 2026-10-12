using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class ResidentServiceController
{
    public const string ServiceName = "MalwardResidentShield";
    public const string DisplayName = "Malward Resident Shield";
    private const string Description =
        "Usługa monitora rezydentnego programu Malward(R). Zarządza stanem działania programu " +
        "oraz uruchamia zadania skanowania plików, w poszukiwaniu złośliwego oprogramowania.";

    private readonly string _exePath;

    public ResidentServiceController(string shieldHostExePath) => _exePath = shieldHostExePath;

    public static string? FindShieldHost()
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
                foreach (var nazwa in new[] { "mwshield.exe", "rsmonitor.exe" })
                {
                    var p = Path.Combine(d, nazwa);
                    if (File.Exists(p)) return Path.GetFullPath(p);
                }
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
        if (!IsInstalled()) return "not-installed";
        if (!IsRunning()) return "stopped";

        return ModuleRunning("resident") ? "running" : "stopped";
    }

    private static string ModuleStatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "module-state.json");

    public static bool ModuleRunning(string key)
    {
        try
        {
            var fi = new FileInfo(ModuleStatePath);
            if (!fi.Exists) return true;
            if (DateTime.UtcNow - fi.LastWriteTimeUtc > TimeSpan.FromSeconds(30)) return true;

            if (fi.LastWriteTimeUtc < LastDecisionUtc()) return true;
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ModuleStatePath));
            return node?[key]?.GetValue<bool>() ?? true;
        }
        catch { return true; }
    }

    private static DateTime LastDecisionUtc()
    {
        var newest = DateTime.MinValue;
        foreach (var p in new[] { ShieldConfigPath, BackupConfigPath })
        {
            try
            {
                var fi = new FileInfo(p);
                if (fi.Exists && fi.LastWriteTimeUtc > newest) newest = fi.LastWriteTimeUtc;
            }
            catch { }
        }
        return newest;
    }

    public async Task<(bool ok, string? error)> EnableAsync()
    {
        try
        {
            if (!IsInstalled())
            {
                var (ok, err) = await InstallAsync();
                if (!ok) return (false, err);
            }
            else
            {
                await ReconcileBinPathAsync();
            }

            await ScAsync($"config {ServiceName} start= auto");
            WriteModuleEnabled(true);

            await ScAsync($"description {ServiceName} \"{Description}\"");
            return await StartAsync();
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<(bool ok, string? error)> DisableAsync()
    {
        try
        {
            if (!IsInstalled()) { WriteModuleEnabled(false); return (true, null); }
            WriteModuleEnabled(false);

            if (OtherModulesWanted()) return (true, null);

            if (ScanInProgress())
            {
                LogService("Resident module disabled by flag; container left running because a scan is in progress.");
                await ScAsync($"config {ServiceName} start= demand");
                return (true, null);
            }

            var (ok, err) = await StopAsync();

            await ScAsync($"config {ServiceName} start= demand");
            return (ok, err);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static string ShieldConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-settings.json");

    private static bool ReadFlag(string key, bool fallback)
    {
        try
        {
            if (!File.Exists(ShieldConfigPath)) return fallback;
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ShieldConfigPath));
            return node?[key]?.GetValue<bool>() ?? fallback;
        }
        catch { return fallback; }
    }

    public static bool ModuleEnabled() => ReadFlag("resident_shield_enabled", true);

    public static bool OtherModulesWanted() => ReadFlag("network_shield_enabled", true) || BackupEnabled();

    private static string BackupConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "backup", "settings.json");

    public static bool BackupEnabled()
    {
        try
        {
            if (!File.Exists(BackupConfigPath)) return true;
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(BackupConfigPath));
            return node?["enabled"]?.GetValue<bool>() ?? true;
        }
        catch { return true; }
    }

    public static bool ModuleFlagPresent()
    {
        try
        {
            if (!File.Exists(ShieldConfigPath)) return false;
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ShieldConfigPath));
            return node?["resident_shield_enabled"] != null;
        }
        catch { return false; }
    }

    public static void SetModuleEnabled(bool on) => WriteModuleEnabled(on);

    private static void WriteModuleEnabled(bool on)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ShieldConfigPath)!);
            var obj = File.Exists(ShieldConfigPath)
                ? System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(ShieldConfigPath)) as System.Text.Json.Nodes.JsonObject
                : null;
            obj ??= new System.Text.Json.Nodes.JsonObject();
            obj["resident_shield_enabled"] = on;

            using var buffer = new MemoryStream();
            using (var writer = new System.Text.Json.Utf8JsonWriter(
                       buffer, new System.Text.Json.JsonWriterOptions { Indented = true }))
                obj.WriteTo(writer);
            File.WriteAllText(ShieldConfigPath, System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
        }
        catch { }
    }

    public async Task<(bool ok, string? error)> EnsureHostRunningAsync()
    {
        try
        {
            if (!IsInstalled()) return (false, "Usługa ochrony nie jest zainstalowana.");
            await ReconcileBinPathAsync();

            await ScAsync($"config {ServiceName} start= auto");

            if (IsRunning()) return (true, null);
            return await StartAsync();
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private async Task<(bool ok, string? error)> InstallAsync()
    {
        if (string.IsNullOrEmpty(_exePath) || !File.Exists(_exePath))
            return (false, "Nie znaleziono mwshield.exe.");

        var (rc, outp) = await ScAsync($"create {ServiceName} binPath= {QuotedBinPath(_exePath)} start= auto obj= LocalSystem DisplayName= \"{DisplayName}\"");
        if (rc != 0) return (false, $"sc create: {outp}");

        await ScAsync($"description {ServiceName} \"{Description}\"");

        await ScAsync($"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000");

        await ScAsync($"failureflag {ServiceName} 1");

        const string sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
        await ScAsync($"sdset {ServiceName} {sddl}");

        return (true, null);
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
        if (RebootRequired)
            return (false, "Ochrona wymaga ponownego uruchomienia komputera, żeby dokończyć naprawę.");

        var (ok, err) = await TryStartOnceAsync();
        if (ok) return (true, null);

        var naprawy = new List<string>();
        try
        {
            var wskazywany = ReadRegistryImagePath(ServiceName)?.Trim().Trim('"');
            if (!string.IsNullOrEmpty(_exePath) && File.Exists(_exePath)
                && (string.IsNullOrEmpty(wskazywany) || !File.Exists(wskazywany)))
            {
                await ReconcileBinPathAsync();
                naprawy.Add("poprawiono ścieżkę do pliku usługi");
            }

            if (StartTypeIsDisabled())
            {
                await ScAsync($"config {ServiceName} start= auto");
                naprawy.Add("przywrócono automatyczne uruchamianie");
            }

            using (var sc = new ServiceController(ServiceName))
            {
                if (sc.Status is ServiceControllerStatus.StopPending or ServiceControllerStatus.PausePending)
                {
                    await Task.Run(() =>
                    {
                        try { sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15)); }
                        catch { }
                    });
                    naprawy.Add("zakończono poprzednie uruchomienie");
                }
            }
        }
        catch {  }

        var (ok2, err2) = await TryStartOnceAsync();
        if (ok2) return (true, null);

        var (ok3, err3) = await ReregisterAsync();
        if (ok3)
        {
            var (ok4, err4) = await TryStartOnceAsync();
            if (ok4) return (true, null);
            return (false, FriendlyStartError(err4, naprawy.Append("wpis usługi założony od nowa").ToList()));
        }

        if (RebootRequired)
            return (false, "Ochrona wymaga ponownego uruchomienia komputera. Poprzedni wpis usługi "
                         + "został usunięty, ale system zwolni jego nazwę dopiero po restarcie.");

        return (false, FriendlyStartError(err3 ?? err2 ?? err, naprawy));
    }

    public static bool RebootRequired { get; private set; }

    public async Task<(bool ok, string? error)> ReregisterAsync()
    {
        if (string.IsNullOrEmpty(_exePath) || !File.Exists(_exePath))
            return (false, "Nie znaleziono pliku ochrony.");

        try
        {
            try { await StopAsync(); } catch { }

            await ScAsync($"delete {ServiceName}");

            for (int i = 0; i < 10 && ServiceEntryExists(); i++)
                await Task.Delay(300);

            var (rc, outp) = await ScAsync(
                $"create {ServiceName} binPath= {QuotedBinPath(_exePath)} start= auto " +
                $"obj= LocalSystem DisplayName= \"{DisplayName}\"");

            if (rc != 0)
            {
                var t = (outp ?? "").ToLowerInvariant();
                if (rc == 1072 || t.Contains("1072") || t.Contains("marked for deletion")
                    || t.Contains("oznaczona do usunięcia"))
                {
                    RebootRequired = true;
                    return (false, "Nazwa usługi jest zajęta do czasu ponownego uruchomienia komputera.");
                }
                return (false, $"sc create: {outp}");
            }

            await ScAsync($"description {ServiceName} \"{Description}\"");
            await ScAsync($"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000");
            await ScAsync($"failureflag {ServiceName} 1");
            const string sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
            await ScAsync($"sdset {ServiceName} {sddl}");

            RebootRequired = false;
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static bool ServiceEntryExists()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\" + ServiceName);
            return k != null;
        }
        catch { return true; }
    }

    private async Task<(bool ok, string? error)> TryStartOnceAsync()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status == ServiceControllerStatus.Running) return (true, null);
            if (sc.Status != ServiceControllerStatus.StartPending)
                sc.Start();
            await Task.Run(() => sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20)));
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static bool StartTypeIsDisabled()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\" + ServiceName);
            return k?.GetValue("Start") is int v && v == 4;
        }
        catch { return false; }
    }

    private static string FriendlyStartError(string? techniczny, List<string> naprawy)
    {
        var t = (techniczny ?? "").ToLowerInvariant();

        string powod =
            t.Contains("access is denied") || t.Contains("odmowa dostępu")
                ? "Windows odmówił uruchomienia ochrony. Uruchom Malwarda jako administrator."
            : t.Contains("does not exist") || t.Contains("nie istnieje")
                ? "Ochrona nie jest zainstalowana jako usługa systemowa. Zainstaluj ją ponownie w ustawieniach."
            : t.Contains("timeout") || t.Contains("did not respond") || t.Contains("przekroczono")
                ? "Ochrona nie zdążyła się uruchomić. Zwykle pomaga ponowne uruchomienie komputera."
            : t.Contains("marked for deletion") || t.Contains("oznaczona do usunięcia")
                ? "Poprzednia wersja ochrony nie została jeszcze usunięta z systemu. "
                  + "Uruchom komputer ponownie i spróbuj jeszcze raz."
                : "Nie udało się uruchomić ochrony w tle.";

        var sb = new System.Text.StringBuilder(powod);
        if (naprawy.Count > 0)
            sb.Append(" Malward spróbował naprawić konfigurację (").Append(string.Join(", ", naprawy))
              .Append("), ale to nie wystarczyło.");
        return sb.ToString();
    }

    private static string ScanLeasePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "scan-active");

    public static bool ScanInProgress()
    {
        try
        {
            var fi = new FileInfo(ScanLeasePath);
            if (!fi.Exists) return false;
            return DateTime.UtcNow - fi.LastWriteTimeUtc < TimeSpan.FromSeconds(15);
        }
        catch { return false; }
    }

    private const string ScanBusyError =
        "Trwa skanowanie w tle — zatrzymanie ochrony przerwałoby je. Poczekaj na koniec skanowania "
        + "albo przerwij je i spróbuj ponownie.";

    private static void LogService(string message)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "gui-service.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
        }
        catch { }
    }

    public async Task<(bool ok, string? error)> StopAsync()
    {
        if (ScanInProgress())
        {
            LogService("Refused to stop the shield service: an on-demand scan is in progress.");
            return (false, ScanBusyError);
        }

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

        if (ScanInProgress())
        {
            LogService("Refused to restart the shield service: an on-demand scan is in progress.");
            return (false, ScanBusyError);
        }
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
}
