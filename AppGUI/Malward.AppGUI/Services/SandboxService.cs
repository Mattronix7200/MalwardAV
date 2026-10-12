using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public static class SandboxService
{
    private static string AppDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward");

    public static string SettingsPath => Path.Combine(AppDir, "data", "sandbox-settings.json");

    public static JsonObject LoadSettings()
    {
        try { if (File.Exists(SettingsPath)) return JsonNode.Parse(File.ReadAllText(SettingsPath))?.AsObject() ?? new(); }
        catch { }
        return new JsonObject();
    }

    public static void SaveSettings(JsonObject o)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, o.ToJsonString());
        }
        catch { }
    }

    public static string? DetectHelper()
    {
        try
        {
            var saved = LoadSettings()["helper"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(saved) && File.Exists(saved)) return saved;
        }
        catch { }

        foreach (var b in new[] { AppContext.BaseDirectory, Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "" })
        {
            if (string.IsNullOrEmpty(b)) continue;
            foreach (var rel in new[]
            {
                Path.Combine("sandbox", "sbhelper", "SBHelper.exe"),
                Path.Combine("sandbox", "SBHelper.exe"),
                Path.Combine("..", "..", "..", "..", "..", "AutoSandoxSDK", "bin", "sbhelper", "SBHelper.exe"),
            })
            {
                try { var full = Path.GetFullPath(Path.Combine(b, rel)); if (File.Exists(full)) return full; }
                catch { }
            }
        }
        return null;
    }

    public static (string? helper, string sandboxDir, bool qemu, bool disk) ModuleState()
    {
        var helper = DetectHelper();
        if (string.IsNullOrWhiteSpace(helper)) return (null, "", false, false);
        string helperDir = Path.GetDirectoryName(helper)!;
        string sandboxDir = Path.GetDirectoryName(helperDir) ?? helperDir;
        bool qemu = File.Exists(Path.Combine(sandboxDir, "qemu", "qemu-system-x86_64.exe"));
        bool disk = File.Exists(Path.Combine(sandboxDir, "shared", "default.7z"));
        return (helper, sandboxDir, qemu, disk);
    }

    public static Task<bool> InstallAsync(Action<double, string> progress)
    {
        return Task.Run(() =>
        {
            var (helper, dir, qemu, _) = ModuleState();
            if (helper == null || !qemu) return false;
            var malscan = EngineLocator.FindMalscan();
            if (malscan == null || !File.Exists(malscan)) return false;
            string seed = Path.Combine(dir, "shared", "default.7z");

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = malscan, UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(malscan) ?? "",
                };
                psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";
                psi.ArgumentList.Add("fetch-sandbox");
                psi.ArgumentList.Add(seed);
                using var p = Process.Start(psi);
                if (p == null) return false;
                string? line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    if (!line.StartsWith("SBDL\t", StringComparison.Ordinal) || line.Contains("\terror=")) continue;
                    double pct = 0; long done = 0, total = 0;
                    foreach (var part in line.Split('\t'))
                    {
                        if (part.StartsWith("pct=")) double.TryParse(part[4..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out pct);
                        else if (part.StartsWith("done=")) long.TryParse(part[5..], out done);
                        else if (part.StartsWith("total=")) long.TryParse(part[6..], out total);
                    }
                    string mb = total > 0 ? $"{done / 1048576} / {total / 1048576} MB" : "";
                    progress(pct, $"Pobieranie modułu piaskownicy… {mb}");
                }
                p.WaitForExit();
                return p.ExitCode == 0 && File.Exists(seed);
            }
            catch { return false; }
        });
    }

    public static async Task<(bool ok, string? error)> LaunchAsync(JsonObject o, Action<string> onStage)
    {
        var (helper, sandboxDir, qemu, disk) = ModuleState();
        if (helper == null) return (false, "Nie znaleziono SBHelper.exe.");
        if (!qemu) return (false, "Brak komponentów QEMU — reinstalacja programu.");
        if (!disk) return (false, "Brak obrazu piaskownicy — zainstaluj moduł.");

        string exe = o["exe"]?.GetValue<string>() ?? "";
        if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe)) return (false, "Plik do uruchomienia nie istnieje.");

        bool B(string k, bool d) => o[k]?.GetValue<bool>() ?? d;
        int I(string k, int d, int lo, int hi) { try { return Math.Clamp(o[k]?.GetValue<int>() ?? d, lo, hi); } catch { return d; } }
        string S(string k, string d) => o[k]?.GetValue<string>() ?? d;

        string statusFile = Path.Combine(Path.GetTempPath(), $"mw-sbox-status-{Guid.NewGuid():N}.json");
        var psi = new ProcessStartInfo
        {
            FileName = helper, UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(helper)!,
        };
        void A(params string[] a) { foreach (var x in a) psi.ArgumentList.Add(x); }
        A("--exe", exe);
        A("--net", B("net", true) ? "on" : "off");
        A("--mem", I("mem", 2, 2, 16).ToString());
        A("--nat", B("nat", true) ? "on" : "off");
        if (B("fullscreen", false)) A("--fullscreen");
        A("--cpu", S("cpu", "qemu64"));
        A("--cores", I("cores", 2, 1, 16).ToString());
        A("--threads", I("threads", 2, 1, 4).ToString());
        A("--ht", B("ht", true) ? "on" : "off");
        A("--accel", S("accel", "auto"));
        A("--bin", sandboxDir);
        A("--status", statusFile);

        onStage("Przygotowywanie maszyny…");
        var proc = Process.Start(psi);

        var sw = Stopwatch.StartNew();
        string last = "";
        while (sw.Elapsed < TimeSpan.FromMinutes(10))
        {
            await Task.Delay(400);
            string stage = "", msg = "";
            try
            {
                if (File.Exists(statusFile))
                {
                    var n = JsonNode.Parse(File.ReadAllText(statusFile));
                    stage = n?["stage"]?.GetValue<string>() ?? "";
                    msg = n?["msg"]?.GetValue<string>() ?? "";
                }
            }
            catch { }
            if (stage.Length > 0 && stage != last) { last = stage; if (msg.Length > 0) onStage(msg); }
            if (stage == "running") { try { File.Delete(statusFile); } catch { } return (true, null); }
            if (stage == "error") { try { File.Delete(statusFile); } catch { } return (false, msg); }
            if (proc != null && proc.HasExited && last != "running")
            {
                try { File.Delete(statusFile); } catch { }
                return (false, string.IsNullOrEmpty(msg) ? "Maszyna nie wystartowała (akceleracja/ustawienia)." : msg);
            }
        }
        return (false, "Przekroczono czas uruchamiania.");
    }
}
