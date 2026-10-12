using System.Diagnostics;
using Microsoft.Win32;

namespace Malward.Engine.Repair;

public static class TaskRepair
{
    public const string ModernPrefix = "Zadanie: ";
    public const string LegacyPrefix = "Zadanie (.job): ";

    public static bool IsTaskLocation(string location)
        => !string.IsNullOrEmpty(location)
           && (location.StartsWith(ModernPrefix, StringComparison.Ordinal)
            || location.StartsWith(LegacyPrefix, StringComparison.Ordinal));

    public static RegistryRepair.Outcome Remove(string location)
    {
        try
        {
            if (location.StartsWith(LegacyPrefix, StringComparison.Ordinal))
                return RemoveLegacyJob(location[LegacyPrefix.Length..].Trim());

            if (location.StartsWith(ModernPrefix, StringComparison.Ordinal))
                return RemoveModernTask(location[ModernPrefix.Length..].Trim());

            return new RegistryRepair.Outcome(false, $"Nie rozpoznano zadania: {location}");
        }
        catch (Exception ex) { return new RegistryRepair.Outcome(false, ex.Message); }
    }

    private static RegistryRepair.Outcome RemoveLegacyJob(string fileName)
    {
        try
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var path = Path.Combine(win, "Tasks", fileName);
            if (!File.Exists(path)) return new RegistryRepair.Outcome(true, null);
            File.Delete(path);
            return new RegistryRepair.Outcome(true, null);
        }
        catch (UnauthorizedAccessException)
        {
            return new RegistryRepair.Outcome(false, "Brak uprawnień do usunięcia zadania (.job) — uruchom jako administrator.");
        }
        catch (Exception ex) { return new RegistryRepair.Outcome(false, ex.Message); }
    }

    private static RegistryRepair.Outcome RemoveModernTask(string name)
    {
        var taskName = "\\" + name.Replace('/', '\\').Trim('\\');

        var (rc, output) = RunSchtasks($"/Delete /TN \"{taskName}\" /F");
        if (rc == 0) return new RegistryRepair.Outcome(true, null);

        if (!TaskExists(taskName)) return new RegistryRepair.Outcome(true, null);

        var manual = RemoveManually(taskName);
        if (manual.Ok) return manual;

        return new RegistryRepair.Outcome(false,
            $"schtasks: {(string.IsNullOrWhiteSpace(output) ? $"kod {rc}" : output.Trim())}" +
            (manual.Error != null ? $"; ręcznie: {manual.Error}" : ""));
    }

    private static bool TaskExists(string taskName)
    {
        var (rc, _) = RunSchtasks($"/Query /TN \"{taskName}\"");
        return rc == 0;
    }

    private static RegistryRepair.Outcome RemoveManually(string taskName)
    {
        const string cache = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
        var rel = taskName.TrimStart('\\');
        string? id = null;
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);

            using (var tree = hklm.OpenSubKey($@"{cache}\Tree\{rel}"))
                id = tree?.GetValue("Id") as string;

            using (var treeParent = hklm.OpenSubKey($@"{cache}\Tree", writable: true))
            {
                try { treeParent?.DeleteSubKeyTree(rel, throwOnMissingSubKey: false); } catch { }
            }

            if (!string.IsNullOrEmpty(id))
            {
                foreach (var branch in new[] { "Tasks", "Plain", "Logon", "Boot", "Maintenance" })
                {
                    using var b = hklm.OpenSubKey($@"{cache}\{branch}", writable: true);
                    try { b?.DeleteSubKeyTree(id!, throwOnMissingSubKey: false); } catch { }
                }
            }

            var xml = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks",
                                   rel.Replace('/', '\\'));
            if (File.Exists(xml)) File.Delete(xml);

            return new RegistryRepair.Outcome(true, null);
        }
        catch (UnauthorizedAccessException)
        {
            return new RegistryRepair.Outcome(false, "brak uprawnień (wymagany administrator)");
        }
        catch (Exception ex) { return new RegistryRepair.Outcome(false, ex.Message); }
    }

    private static (int rc, string output) RunSchtasks(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return (-1, "nie udało się uruchomić schtasks.exe");
            string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(20000)) { try { p.Kill(); } catch { } return (-1, "schtasks: timeout"); }
            return (p.ExitCode, o);
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }
}
