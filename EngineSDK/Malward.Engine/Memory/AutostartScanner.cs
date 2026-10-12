using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Malward.Engine.Config;
using Malward.Engine.Core;
using Microsoft.Win32;

namespace Malward.Engine.Memory;

[SupportedOSPlatform("windows")]
public sealed class AutostartScanner
{
    private readonly Settings _settings;

    public AutostartScanner(Settings settings) { _settings = settings; }

    private sealed record AutostartEntry(string Source, string Path, Action Remove);

    public IEnumerable<DetectionResult> ScanAutostart(ScanPipeline pipeline)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in EnumerateAutostartTargets())
        {
            if (string.IsNullOrWhiteSpace(entry.Path)) continue;
            string? resolved = ResolvePath(entry.Path);
            if (resolved == null) continue;
            if (!File.Exists(resolved)) continue;
            if (!seen.Add(resolved)) continue;

            DetectionResult r;
            try { r = pipeline.Scan(resolved); }
            catch (Exception ex)
            {
                r = new DetectionResult(resolved, "", Verdict.Error, null,
                    "Autostart:error", 0, 0, ex.Message);
            }

            if (r.Verdict == Verdict.Malware && _settings.RepairMode != 0
                && !Repair.Repairer.IsHeuristic(r))
            {
                try { entry.Remove(); Console.Error.WriteLine($"[i] Removed autostart entry: {entry.Source}"); }
                catch (Exception ex) { Console.Error.WriteLine($"[!] Failed to remove autostart entry {entry.Source}: {ex.Message}"); }
            }

            yield return r with { Source = $"Autostart({entry.Source}):{r.Source}" };
        }
    }

    private static IEnumerable<AutostartEntry> EnumerateAutostartTargets()
    {
        var startupUser = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var startupAll  = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        foreach (var (label, dir) in new[] { ("Startup", startupUser), ("Startup-All", startupAll) })
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            foreach (var f in SafeEnumerate(dir))
                yield return new AutostartEntry(label, f, () => { try { File.Delete(f); } catch { } });
        }

        var runKeys = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\RunServices",
            @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",

            @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        };
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            foreach (var sub in runKeys)
            {
                foreach (var (name, val) in SafeReadValues(hive, sub))
                {
                    var p = ExtractExePath(val);
                    if (p != null)
                    {
                        var h = hive; var s = sub; var n = name;
                        yield return new AutostartEntry($"Reg:{hive}\\{sub}\\{name}", p,
                            () => DeleteRegValue(h, s, n));
                    }
                }
            }
        }

        const string winlogon = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        foreach (var name in new[] { "Shell", "Userinit", "Taskman" })
        {
            var val = SafeReadString(RegistryHive.LocalMachine, winlogon, name);
            if (val == null) continue;
            foreach (var part in val.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var p = ExtractExePath(part);
                if (p != null)
                {
                    var nm = name; var mal = p;
                    yield return new AutostartEntry($"Reg:Winlogon\\{name}", p,
                        () => FixWinlogon(nm, mal));
                }
            }
        }

        const string ifeo = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        foreach (var subKeyName in SafeSubKeyNames(RegistryHive.LocalMachine, ifeo))
        {
            var dbg = SafeReadString(RegistryHive.LocalMachine, $@"{ifeo}\{subKeyName}", "Debugger");
            if (string.IsNullOrEmpty(dbg)) continue;
            var p = ExtractExePath(dbg);
            if (p != null)
            {
                var full = $@"{ifeo}\{subKeyName}";
                yield return new AutostartEntry($"Reg:IFEO\\{subKeyName}\\Debugger", p,
                    () => DeleteRegValue(RegistryHive.LocalMachine, full, "Debugger"));
            }
        }
    }

    private static void DeleteRegValue(RegistryHive hive, string sub, string name)
    {
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub, writable: true);
            k?.DeleteValue(name, throwOnMissingValue: false);
        }
        catch { }
    }

    private static void FixWinlogon(string name, string malwarePath)
    {
        const string winlogon = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
        try
        {
            using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default)
                .OpenSubKey(winlogon, writable: true);
            if (k == null) return;
            if (name.Equals("Shell", StringComparison.OrdinalIgnoreCase))
                k.SetValue("Shell", "explorer.exe", RegistryValueKind.String);
            else if (name.Equals("Userinit", StringComparison.OrdinalIgnoreCase))
            {
                var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                k.SetValue("Userinit", Path.Combine(sys, "userinit.exe") + ",", RegistryValueKind.String);
            }
            else if (name.Equals("Taskman", StringComparison.OrdinalIgnoreCase))
                k.DeleteValue("Taskman", throwOnMissingValue: false);
        }
        catch { }
    }

    private static string? ExtractExePath(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        commandLine = commandLine.Trim();

        if (commandLine.StartsWith('"'))
        {
            int end = commandLine.IndexOf('"', 1);
            if (end > 1) return commandLine.Substring(1, end - 1);
            return null;
        }

        int space = commandLine.IndexOf(' ');
        return space > 0 ? commandLine[..space] : commandLine;
    }

    private static string? ResolvePath(string raw)
    {
        try
        {
            var expanded = Environment.ExpandEnvironmentVariables(raw);
            return Path.GetFullPath(expanded);
        }
        catch { return null; }
    }

    private static IEnumerable<string> SafeEnumerate(string dir)
    {
        try { return Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly); }
        catch { return Enumerable.Empty<string>(); }
    }

    private static IEnumerable<(string name, string? val)> SafeReadValues(RegistryHive hive, string sub)
    {
        RegistryKey? k = null;
        try { k = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub); }
        catch { yield break; }
        if (k == null) yield break;
        string[] names;
        try { names = k.GetValueNames(); } catch { k.Dispose(); yield break; }
        foreach (var n in names)
        {
            string? v = null;
            try { v = k.GetValue(n)?.ToString(); } catch { }
            yield return (n, v);
        }
        k.Dispose();
    }

    private static string? SafeReadString(RegistryHive hive, string sub, string name)
    {
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub);
            return k?.GetValue(name)?.ToString();
        }
        catch { return null; }
    }

    private static IEnumerable<string> SafeSubKeyNames(RegistryHive hive, string sub)
    {
        try
        {
            using var k = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(sub);
            return k?.GetSubKeyNames() ?? Array.Empty<string>();
        }
        catch { return Array.Empty<string>(); }
    }
}
