using System.Diagnostics;
using Microsoft.Win32;

namespace Malward.ResidentShield;

public sealed class PersistenceCleaner
{
    private readonly HashSet<string> _malwarePaths;

    public PersistenceCleaner(IEnumerable<string> malwarePaths)
    {
        _malwarePaths = new HashSet<string>(
            malwarePaths.Where(p => !string.IsNullOrWhiteSpace(p)
                                 && p.Contains('\\')
                                 && !SystemGuard.IsUntouchable(p)),
            StringComparer.OrdinalIgnoreCase);
    }

    public int CleanAll(bool deep)
    {
        if (_malwarePaths.Count == 0) return 0;

        int n = 0;
        try { n += CleanRunKeys(); }        catch (Exception ex) { Log.Error("Persist", $"Run: {ex.Message}"); }
        try { n += CleanStartupFolders(); } catch (Exception ex) { Log.Error("Persist", $"Startup: {ex.Message}"); }
        if (deep)
        {
            try { n += CleanServices(); }       catch (Exception ex) { Log.Error("Persist", $"Svc: {ex.Message}"); }
            try { n += CleanScheduledTasks(); } catch (Exception ex) { Log.Error("Persist", $"Task: {ex.Message}"); }
        }
        try { ResetSecurityDefaults(); }    catch (Exception ex) { Log.Error("Persist", $"SecDef: {ex.Message}"); }
        try { n += RestoreWallpaper(); }    catch (Exception ex) { Log.Error("Persist", $"Wallpaper: {ex.Message}"); }
        return n;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, string pvParam, uint fWinIni);
    private const uint SPI_SETDESKWALLPAPER = 0x0014;
    private const uint SPIF_UPDATEINIFILE = 0x01, SPIF_SENDCHANGE = 0x02;

    private static string? HashOf(string path)
    {
        try
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var fs = System.IO.File.OpenRead(path);
            return Convert.ToHexString(sha.ComputeHash(fs));
        }
        catch { return null; }
    }

    private int RestoreWallpaper()
    {
        int fixedCount = 0;
        var malwareDirs = _malwarePaths
            .Select(p => { try { return System.IO.Path.GetDirectoryName(p); } catch { return null; } })
            .Where(d => !string.IsNullOrEmpty(d))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var guardDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "sysrepair");
        string? baseHash = null, bakPath = null;
        try
        {
            var baselineFile = System.IO.Path.Combine(guardDir, "wallpaper.baseline");
            if (System.IO.File.Exists(baselineFile))
            {
                var parts = System.IO.File.ReadAllText(baselineFile).Split('|');
                if (parts.Length > 1) baseHash = parts[1];
                if (parts.Length > 2) bakPath = System.IO.Path.Combine(guardDir, parts[2]);
            }
        }
        catch { }

        string def = @"C:\Windows\Web\Wallpaper\Windows\img0.jpg";
        string resetVal;
        if (bakPath != null && System.IO.File.Exists(bakPath))
        {
            resetVal = System.IO.Path.Combine(guardDir, "wallpaper-restored" + System.IO.Path.GetExtension(bakPath));
            try { System.IO.File.Copy(bakPath, resetVal, overwrite: true); }
            catch { resetVal = System.IO.File.Exists(def) ? def : ""; }
        }
        else resetVal = System.IO.File.Exists(def) ? def : "";

        foreach (var sid in SafeSubKeyNames(Registry.Users))
        {
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                using var desk = Registry.Users.OpenSubKey($@"{sid}\Control Panel\Desktop", writable: true);
                if (desk?.GetValue("Wallpaper") is not string wp || string.IsNullOrEmpty(wp)) continue;
                string? wd = null; try { wd = System.IO.Path.GetDirectoryName(wp); } catch { }

                bool malicious = _malwarePaths.Contains(wp) || (wd != null && malwareDirs.Contains(wd));
                if (!malicious && !System.IO.File.Exists(wp)) malicious = true;
                if (!malicious && baseHash != null)
                {
                    var cur = HashOf(wp);
                    if (cur != null && !string.Equals(cur, baseHash, StringComparison.OrdinalIgnoreCase))
                        malicious = true;
                }
                if (!malicious) continue;

                desk.SetValue("Wallpaper", resetVal);
                fixedCount++;
                Log.Info("Persist", bakPath != null
                    ? $"Restored the user's wallpaper from backup (it had been replaced: {wp})"
                    : $"Restored the default wallpaper (previous one was malicious: {wp})");
            }
            catch (Exception ex) { Log.Debug("Persist", $"Wallpaper {sid}: {ex.Message}"); }
        }

        if (fixedCount > 0)
            try { SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, resetVal, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE); } catch { }
        return fixedCount;
    }

    private static readonly string[] RunSubKeys =
    {
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\RunServices",
        @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    private int CleanRunKeys()
    {
        int removed = 0;

        removed += CleanRunIn(Registry.LocalMachine);
        removed += CleanRunIn(Registry.CurrentUser);

        foreach (var sid in SafeSubKeyNames(Registry.Users))
        {
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                using var userRoot = Registry.Users.OpenSubKey(sid, writable: true);
                if (userRoot != null) removed += CleanRunIn(userRoot, sid);
            }
            catch { }
        }

        return removed;
    }

    private int CleanRunIn(RegistryKey root, string? userPrefix = null)
    {
        int removed = 0;
        foreach (var sub in RunSubKeys)
        {
            try
            {
                using var key = root.OpenSubKey(sub, writable: true);
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    string data = key.GetValue(valName)?.ToString() ?? "";
                    if (!ReferencesMalware(data)) continue;

                    key.DeleteValue(valName, throwOnMissingValue: false);
                    removed++;
                    Log.Info("Persist", $"Removed autostart entry: {(userPrefix != null ? userPrefix + "\\" : "")}{sub}\\{valName}");
                }
            }
            catch { }
        }
        return removed;
    }

    private int CleanServices()
    {
        int removed = 0;
        using var services = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services", writable: false);
        if (services == null) return 0;

        foreach (var svcName in SafeSubKeyNames(services))
        {
            try
            {
                using var svc = services.OpenSubKey(svcName);
                string imagePath = svc?.GetValue("ImagePath")?.ToString() ?? "";

                if (ReferencesProtected(imagePath)) continue;
                if (!ReferencesMalware(imagePath)) continue;

                RunSilent("sc.exe", $"stop \"{svcName}\"");
                RunSilent("sc.exe", $"delete \"{svcName}\"");
                try
                {
                    Registry.LocalMachine.DeleteSubKeyTree(
                        $@"SYSTEM\CurrentControlSet\Services\{svcName}", throwOnMissingSubKey: false);
                }
                catch { }
                removed++;
                Log.Info("Persist", $"Removed service: {svcName} ({imagePath})");
            }
            catch { }
        }
        return removed;
    }

    private int CleanScheduledTasks()
    {
        int removed = 0;
        string tasksRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");
        if (!Directory.Exists(tasksRoot)) return 0;

        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(tasksRoot, "*", SearchOption.AllDirectories); }
        catch { return 0; }

        foreach (var file in files)
        {
            string xml;
            try { xml = File.ReadAllText(file); }
            catch { continue; }

            if (!ReferencesMalware(xml)) continue;

            string taskName = "\\" + Path.GetRelativePath(tasksRoot, file).Replace('/', '\\');
            if (RunSilent("schtasks.exe", $"/delete /tn \"{taskName}\" /f"))
            {
                removed++;
                Log.Info("Persist", $"Removed scheduled task: {taskName}");
            }
        }
        return removed;
    }

    private int CleanStartupFolders()
    {
        int removed = 0;
        var folders = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };

        foreach (var folder in folders.Where(Directory.Exists))
        {
            foreach (var file in SafeFiles(folder))
            {
                bool hit = ReferencesMalware(file);

                if (!hit && file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    hit = ReferencesMalware(ResolveShortcutTarget(file));

                if (!hit) continue;
                if (SystemGuard.IsUntouchable(file)) continue;

                try { File.Delete(file); removed++; Log.Info("Persist", $"Removed from startup folder: {file}"); }
                catch { }
            }
        }
        return removed;
    }

    private void ResetSecurityDefaults()
    {
        foreach (var linia in Malward.Engine.Data.SignatureStore.List("tamper_restore"))
        {
            var p = linia.Split('\u001F');
            if (p.Length != 4 || !int.TryParse(p[3], out int bezpieczna)) continue;
            var root = p[0] == "m" ? Registry.LocalMachine : Registry.CurrentUser;
            FixIfTampered(root, p[1], p[2], safe: bezpieczna);
        }
    }

    private static void FixIfTampered(RegistryKey root, string sub, string name, int safe)
    {
        try
        {
            using var key = root.OpenSubKey(sub, writable: true);
            var cur = key?.GetValue(name);
            if (cur == null) return;
            if (cur is int v && v == safe) return;
            key!.SetValue(name, safe, RegistryValueKind.DWord);
            Log.Alert("Persist", $"Security tampering detected — restored {name}={safe}: {sub}");
        }
        catch { }
    }

    private bool ReferencesMalware(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        foreach (var p in _malwarePaths)
            if (text.Contains(p, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static readonly string[] _dangerAreas = { @"\shell\", @"\shellex\", @"\defaulticon", @"\clsid\", @"\services\" };

    public int CleanAttributedRegistry(IEnumerable<ProcessChange> changes)
    {
        if (_malwarePaths.Count == 0) return 0;
        int reverted = 0;
        foreach (var ch in changes)
        {
            if (ch.Kind is not (ChangeKind.RegSet or ChangeKind.RegCreate or ChangeKind.RegAutostart)) continue;
            var norm = NormalizeRegPath(ch.Location);
            if (norm == null) continue;
            var (root, sub) = norm.Value;
            if (string.IsNullOrEmpty(sub)) continue;
            try
            {
                if (ch.Kind == ChangeKind.RegCreate)
                {
                    string sl = ("\\" + sub + "\\").ToLowerInvariant();
                    if (!_dangerAreas.Any(a => sl.Contains(a, StringComparison.Ordinal))) continue;
                    bool refs;
                    using (var k = root.OpenSubKey(sub, writable: false))
                    { if (k == null) continue; refs = KeyReferencesMalware(k, depth: 0); }
                    if (!refs) continue;
                    root.DeleteSubKeyTree(sub, throwOnMissingSubKey: false);
                    reverted++;
                    Log.Info("Persist", $"Registry rollback: removed key created by malware: {sub}");
                }
                else
                {
                    if (string.IsNullOrEmpty(ch.Extra)) continue;
                    using var key = root.OpenSubKey(sub, writable: true);
                    var data = key?.GetValue(ch.Extra)?.ToString();
                    if (data == null || !ReferencesMalware(data)) continue;
                    key!.DeleteValue(ch.Extra, throwOnMissingValue: false);
                    reverted++;
                    Log.Info("Persist", $"Registry rollback: removed value referencing malware: {sub}\\{ch.Extra}");
                }
            }
            catch (Exception ex) { Log.Debug("Persist", $"RegRollback {sub}: {ex.Message}"); }
        }
        return reverted;
    }

    private bool KeyReferencesMalware(RegistryKey key, int depth)
    {
        if (depth > 4) return false;
        try
        {
            foreach (var vn in key.GetValueNames())
            {
                var v = key.GetValue(vn)?.ToString();
                if (v != null && ReferencesMalware(v)) return true;
            }
            foreach (var sk in key.GetSubKeyNames())
            {
                try { using var child = key.OpenSubKey(sk); if (child != null && KeyReferencesMalware(child, depth + 1)) return true; }
                catch { }
            }
        }
        catch { }
        return false;
    }

    private static (RegistryKey root, string sub)? NormalizeRegPath(string keyName)
    {
        if (string.IsNullOrEmpty(keyName)) return null;
        var k = keyName.Replace('/', '\\').Trim().TrimStart('\\');
        (string prefix, RegistryKey root)[] map =
        {
            (@"REGISTRY\MACHINE\",   Registry.LocalMachine),
            (@"REGISTRY\USER\",      Registry.Users),
            (@"HKEY_LOCAL_MACHINE\", Registry.LocalMachine),
            (@"HKLM\",               Registry.LocalMachine),
            (@"HKEY_CURRENT_USER\",  Registry.CurrentUser),
            (@"HKCU\",               Registry.CurrentUser),
            (@"HKEY_USERS\",         Registry.Users),
            (@"HKU\",                Registry.Users),
            (@"HKEY_CLASSES_ROOT\",  Registry.ClassesRoot),
            (@"HKCR\",               Registry.ClassesRoot),
            (@"MACHINE\",            Registry.LocalMachine),
            (@"USER\",               Registry.Users),
        };
        foreach (var (prefix, root) in map)
            if (k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return (root, k.Substring(prefix.Length));
        return null;
    }

    private static bool ReferencesProtected(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;

        string candidate = text.Trim().Trim('"');
        return SystemGuard.IsProtectedPath(candidate)
            || candidate.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SafeSubKeyNames(RegistryKey key)
    {
        try { return key.GetSubKeyNames(); } catch { return Array.Empty<string>(); }
    }

    private static IEnumerable<string> SafeFiles(string dir)
    {
        try { return Directory.EnumerateFiles(dir); } catch { return Array.Empty<string>(); }
    }

    private static string ResolveShortcutTarget(string lnkPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(lnkPath);
            string raw = System.Text.Encoding.Unicode.GetString(bytes);
            int idx = raw.IndexOf(":\\", StringComparison.Ordinal);
            if (idx > 0)
            {
                int start = idx - 1;
                int end = raw.IndexOf('\0', idx);
                if (end < 0) end = Math.Min(raw.Length, idx + 260);
                return raw[start..end];
            }
        }
        catch { }
        return "";
    }

    private static bool RunSilent(string exe, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            if (p == null) return false;
            p.WaitForExit(8000);
            return p.HasExited && p.ExitCode == 0;
        }
        catch { return false; }
    }
}
