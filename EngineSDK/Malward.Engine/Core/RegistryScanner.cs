using System.Text.RegularExpressions;
using Microsoft.Win32;
using Malward.Engine.Util;

namespace Malward.Engine.Core;

public static class RegistryScanner
{
    public sealed record Item(string Location, string FilePath, string Kind);

    private sealed record Area(RegistryHive Hive, string Path, string Kind, bool ValuesAreCommands);

    private static readonly Area[] Areas =
    {
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run",              "Autostart", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce",          "Autostart", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunServices",      "Autostart", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run",              "Autostart", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce",          "Autostart", true),
        new(RegistryHive.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",  "Autostart", true),

        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows NT\CurrentVersion\Windows",       "Autostart", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",      "Winlogon",  true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "BHO", false),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "ShellFolder", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Autostart", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Autostart", true),

        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Command Processor",                     "CmdAutoRun", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Command Processor",                     "CmdAutoRun", true),

        new(RegistryHive.CurrentUser,  @"Environment",                                              "LogonScript", true),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Session Manager\AppCertDlls", "AppCertDll", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify", "WinlogonNotify", true),

        new(RegistryHive.CurrentUser,  @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "Autostart", true),
        new(RegistryHive.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "Autostart", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "ShellService", true),

        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "ShellFolder", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnceEx", "Autostart", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnceEx", "Autostart", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "Autostart", true),

        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon", true),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "LsaPackage", true),
        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\SecurityProviders", "LsaPackage", true),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Print\Monitors", "PrintMonitor", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers", "CredProvider", false),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Services\WinSock2\Parameters", "Winsock", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Drivers32", "Drivers32", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules", "WerModule", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB", "ShimDb", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup", "GpoScript", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon", "GpoScript", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown", "GpoScript", true),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff", "GpoScript", true),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors", "PrintProcessor", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "GpExtension", false),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Services\W32Time\TimeProviders", "TimeProvider", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Netsh", "NetshHelper", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\CTF\LangBarAddin", "LangBarAddin", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom", "ShimDb", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\Windows Error Reporting\LocalDumps", "WerDump", true),

        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2", "MountPoint", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Wbem\CIMOM", "WbemMof", true),

        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Office test\Special\Perf", "OfficeTest", true),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Office test\Special\Perf", "OfficeTest", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "ShellHook", false),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler", "ShellHook", false),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjects", "ShellHook", false),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers", "ShellHook", false),
    };

    private static readonly Dictionary<string, HashSet<string>> ExtraValueFilter =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["LsaPackage"] = new(StringComparer.OrdinalIgnoreCase)
                { "Authentication Packages", "Notification Packages", "Security Packages", "SecurityProviders" },
            ["Winsock"]    = new(StringComparer.OrdinalIgnoreCase) { "AutodialDLL" },
            ["Drivers32"]  = new(StringComparer.OrdinalIgnoreCase)
                { "midi", "midi1", "midi2", "wave", "wave1", "wave2", "msacm.imaadpcm",
                  "msacm.msadpcm", "msacm.msg711", "msacm.msgsm610", "vidc.cvid", "vidc.iv50" },
        };

    private static readonly (string Path, string Kind)[] PerUserAreas =
        Areas.Where(a => a.Hive == RegistryHive.CurrentUser)
             .Select(a => (a.Path, a.Kind))
             .Distinct()
             .ToArray();

    private static readonly Dictionary<string, HashSet<string>> ValueFilter =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["CmdAutoRun"]  = new(StringComparer.OrdinalIgnoreCase) { "AutoRun" },
            ["LogonScript"] = new(StringComparer.OrdinalIgnoreCase) { "UserInitMprLogonScript" },
        };

    private static readonly HashSet<string> WinlogonValues =
        new(StringComparer.OrdinalIgnoreCase) { "Shell", "Userinit", "Taskman", "AppInit_DLLs" };

    private static readonly HashSet<string> WindowsNtValues =
        new(StringComparer.OrdinalIgnoreCase) { "load", "run" };

    private const string TaskCache = @"Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";

    public static List<Item> Collect()
    {
        var items = new List<Item>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var area in Areas)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(area.Hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(area.Path);
                if (key == null) continue;

                if (area.Kind == "IFEO")
                {
                    CollectIfeoPayloads(items, seen);
                    continue;
                }

                foreach (var name in key.GetValueNames())
                {
                    if (area.Kind == "Winlogon" && !WinlogonValues.Contains(name)) continue;
                    if (area.Path.EndsWith(@"NT\CurrentVersion\Windows", StringComparison.OrdinalIgnoreCase)
                        && !WindowsNtValues.Contains(name)) continue;
                    if (ValueFilter.TryGetValue(area.Kind, out var allowed) && !allowed.Contains(name)) continue;
                    if (ExtraValueFilter.TryGetValue(area.Kind, out var allowed2) && !allowed2.Contains(name)) continue;

                    if (key.GetValue(name) is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                    AddResolved(items, seen, $@"{HiveName(area.Hive)}\{area.Path}|{name}", cmd, area.Kind);
                }
            }
            catch {  }
        }

        void Safe(string what, Action collector)
        {
            try { collector(); }
            catch (Exception ex) { Console.Error.WriteLine($"[!] rejestr/{what}: {ex.Message}"); }
        }

        Safe("zadania", () => CollectScheduledTasks(items, seen));

        Safe("pliki zadan", () => CollectTaskFiles(items, seen));
        Safe("hives uzytkownikow", () => CollectUserHives(items, seen));
        Safe("active setup", () => CollectActiveSetup(items, seen));
        Safe("hives offline", () => CollectOfflineHives(items, seen));
        Safe("podklucze", () => CollectSubkeyPointers(items, seen));
        return items;
    }

    private static void CollectSubkeyPointers(List<Item> items, HashSet<string> seen)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);

        try
        {
            using var klasy = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class");
            foreach (var guid in klasy?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                try
                {
                    using var k = klasy!.OpenSubKey(guid);
                    if (k == null) continue;
                    foreach (var wartosc in new[] { "UpperFilters", "LowerFilters" })
                    {
                        if (k.GetValue(wartosc) is not string[] sterowniki) continue;
                        foreach (var sterownik in sterowniki)
                        {
                            var sys = DriverImagePath(hklm, sterownik);
                            if (!string.IsNullOrEmpty(sys))
                                AddResolved(items, seen,
                                    $@"HKLM\SYSTEM\CurrentControlSet\Control\Class\{guid}|{wartosc}",
                                    sys, "ClassFilter");
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

        try
        {
            using var uslugi = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            foreach (var nazwa in uslugi?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                try
                {
                    using var u = uslugi!.OpenSubKey(nazwa);
                    if (u == null) continue;

                    using (var par = u.OpenSubKey("Parameters"))
                    {
                        if (par?.GetValue("ServiceDll") is string dll && !string.IsNullOrWhiteSpace(dll))
                            AddResolved(items, seen,
                                $@"HKLM\SYSTEM\CurrentControlSet\Services\{nazwa}\Parameters|ServiceDll",
                                dll, "ServiceDll");
                    }

                    if (u.GetValue("Type") is int typ && (typ == 1 || typ == 2)
                        && u.GetValue("ImagePath") is string img && !string.IsNullOrWhiteSpace(img))
                    {
                        AddResolved(items, seen,
                            $@"HKLM\SYSTEM\CurrentControlSet\Services\{nazwa}|ImagePath",
                            NormalizeDriverPath(img), "DriverService");
                    }
                }
                catch { }
            }
        }
        catch { }

        foreach (var baza in new[] { @"SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
                                     @"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
                                     @"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers",
                                     @"SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers" })
        {
            try
            {
                using var k = hklm.OpenSubKey(baza);
                foreach (var h in k?.GetSubKeyNames() ?? Array.Empty<string>())
                {
                    try
                    {
                        using var sub = k!.OpenSubKey(h);
                        if (sub?.GetValue(null) is not string clsid || string.IsNullOrWhiteSpace(clsid)) continue;
                        var dll = MachineComServer(hklm, clsid.Trim());
                        if (!string.IsNullOrEmpty(dll))
                            AddResolved(items, seen, $@"HKLM\{baza}\{h}", dll, "ContextMenuHandler");
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static string MachineComServer(RegistryKey hklm, string clsid)
    {
        try
        {
            using var k = hklm.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32");
            return k?.GetValue(null) as string ?? "";
        }
        catch { return ""; }
    }

    private static string DriverImagePath(RegistryKey hklm, string serviceName)
    {
        try
        {
            using var k = hklm.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            if (k?.GetValue("ImagePath") is string p && !string.IsNullOrWhiteSpace(p))
                return NormalizeDriverPath(p);

            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                "drivers", serviceName + ".sys");
        }
        catch { return ""; }
    }

    private static string NormalizeDriverPath(string raw)
    {
        var p = raw.Trim().Trim('"');
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        else if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p[12..]);
        else if (!Path.IsPathRooted(p))
            p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p);
        return p;
    }

    private static void CollectOfflineHives(List<Item> items, HashSet<string> seen)
    {
        string usersDir;
        try
        {
            var sysDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\";
            usersDir = Path.Combine(sysDrive, "Users");
            if (!Directory.Exists(usersDir)) return;
        }
        catch { return; }

        var zaladowane = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            foreach (var sid in users.GetSubKeyNames())
            {
                using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default)
                    .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
                if (k?.GetValue("ProfileImagePath") is string p && !string.IsNullOrEmpty(p))
                    zaladowane.Add(Environment.ExpandEnvironmentVariables(p).TrimEnd('\\'));
            }
        }
        catch { }

        int licznik = 0;
        foreach (var profil in Directory.GetDirectories(usersDir))
        {
            if (licznik++ > 20) break;
            if (zaladowane.Contains(profil.TrimEnd('\\'))) continue;

            var hive = Path.Combine(profil, "NTUSER.DAT");
            if (!File.Exists(hive)) continue;

            var usrClass = Path.Combine(profil, @"AppData\Local\Microsoft\Windows\UsrClass.dat");
            if (File.Exists(usrClass))
            {
                var mountC = "MW_OFFLINE_C_" + licznik;
                if (OfflineHive.TryLoad(mountC, usrClass))
                {
                    try
                    {
                        using var u = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                        using var clsid = u.OpenSubKey(mountC + @"\CLSID");
                        foreach (var sub in clsid?.GetSubKeyNames() ?? Array.Empty<string>())
                        {
                            try
                            {
                                using var ips = clsid!.OpenSubKey(sub + @"\InprocServer32");
                                if (ips?.GetValue(null) is string dll && !string.IsNullOrWhiteSpace(dll))
                                    AddResolved(items, seen,
                                        $"{Path.GetFileName(profil)} (offline)\\Classes\\CLSID\\{sub}", dll, "ComServer");
                            }
                            catch { }
                        }
                    }
                    catch { }
                    finally { OfflineHive.TryUnload(mountC); }
                }
            }

            var mount = "MW_OFFLINE_" + licznik;
            if (!OfflineHive.TryLoad(mount, hive)) continue;
            try
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                foreach (var (path, kind) in PerUserAreas)
                {
                    try
                    {
                        using var key = users.OpenSubKey(mount + "\\" + path);
                        if (key == null) continue;
                        foreach (var name in key.GetValueNames())
                        {
                            if (key.GetValue(name) is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                            AddResolved(items, seen,
                                $"{Path.GetFileName(profil)} (offline)\\{path}|{name}", cmd, kind);
                        }
                    }
                    catch { }
                }
            }
            finally { OfflineHive.TryUnload(mount); }
        }
    }

    private static void CollectUserHives(List<Item> items, HashSet<string> seen)
    {
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            foreach (var sid in users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;

                foreach (var (path, kind) in PerUserAreas)
                {
                    try
                    {
                        using var key = users.OpenSubKey(sid + "\\" + path);
                        if (key == null) continue;
                        foreach (var name in key.GetValueNames())
                        {
                            if (key.GetValue(name) is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                            AddResolved(items, seen, "HKU\\" + sid + "\\" + path + "|" + name, cmd, kind);
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void CollectActiveSetup(List<Item> items, HashSet<string> seen)
    {
        const string path = @"Software\Microsoft\Active Setup\Installed Components";
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(path);
                if (key == null) continue;
                foreach (var comp in key.GetSubKeyNames())
                {
                    using var s = key.OpenSubKey(comp);
                    if (s?.GetValue("StubPath") is string stub && !string.IsNullOrWhiteSpace(stub))
                        AddResolved(items, seen, HiveName(hive) + "\\" + path + "\\" + comp + "|StubPath", stub, "ActiveSetup");
                }
            }
            catch { }
        }
    }

    public static Indicator? ClassifyPersistence(Item item)
    {
        var path = item.FilePath;
        if (string.IsNullOrEmpty(path)) return null;
        var lower = path.ToLowerInvariant();

        var mq = Masquerade.CheckFile(path, verifySignature: true);
        if (mq != null) return new Indicator(item.Location, mq.Detection, mq.Reason);

        string valueName = item.Location.Contains('|') ? item.Location[(item.Location.LastIndexOf('|') + 1)..] : "";
        if (LooksLikeFakeUpdater(valueName, lower))
            return new Indicator(item.Location, DetectionNames.ForFile(item.FilePath),
                "Wpis autostartu " + valueName + " podszywa sie pod aktualizator, a cel lezy poza jego folderem: " + path);

        if (lower.Contains(@"\$recycle.bin\")
            || lower.Contains(@"\appdata\local\temp\") || lower.Contains(@"\windows\temp\"))
            return new Indicator(item.Location, DetectionNames.ForFile(item.FilePath),
                "Autostart uruchamiany z lokalizacji tymczasowej/kosza: " + path);

        return null;
    }

    private static bool LooksLikeFakeUpdater(string valueName, string lowerPath)
    {
        if (string.IsNullOrEmpty(valueName)) return false;
        var v = valueName.ToLowerInvariant();
        (string needle, string folder)[] updaters =
        {
            ("microsoftedgeupdate", @"\microsoft\edge"), ("googleupdate", @"\google\"),
            ("onedrive", @"\onedrive"), ("adobe", @"\adobe\"), ("dropbox", @"\dropbox"),
            ("java", @"\java"), ("chrome", @"\google\"), ("firefox", @"\mozilla"),
        };
        foreach (var (needle, folder) in updaters)
            if (v.Contains(needle) && !lowerPath.Contains(folder)) return true;
        return false;
    }

    private static void CollectIfeoPayloads(List<Item> items, HashSet<string> seen)
    {
        var views = Environment.Is64BitOperatingSystem
            ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
            : new[] { RegistryView.Default };

        const string ifeoPath = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        const string exitPath = @"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

        foreach (var view in views)
        {
            string tag = view == RegistryView.Registry32 ? "HKLM32" : "HKLM";
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);

                using (var ifeo = baseKey.OpenSubKey(ifeoPath))
                {
                    foreach (var sub in ifeo?.GetSubKeyNames() ?? Array.Empty<string>())
                    {
                        using var s = ifeo!.OpenSubKey(sub);
                        if (s == null) continue;
                        foreach (var valueName in new[] { "Debugger", "VerifierDlls" })
                            if (s.GetValue(valueName) is string v && !string.IsNullOrWhiteSpace(v))
                                AddResolved(items, seen, $@"{tag}\{ifeoPath}\{sub}|{valueName}", v, "IFEO");
                    }
                }

                using var exit = baseKey.OpenSubKey(exitPath);
                foreach (var sub in exit?.GetSubKeyNames() ?? Array.Empty<string>())
                {
                    using var s = exit!.OpenSubKey(sub);
                    if (s?.GetValue("MonitorProcess") is string mp && !string.IsNullOrWhiteSpace(mp))
                        AddResolved(items, seen, $@"{tag}\{exitPath}\{sub}|MonitorProcess", mp, "IFEO");
                }
            }
            catch {  }
        }
    }

    public sealed record Indicator(string Location, string Detection, string Detail,
                                   bool Artifact = false);

    public static List<Indicator> CollectIndicators()
    {
        var found = new List<Indicator>();

        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1,
            "Defender.Disabled", "Ochrona antyspyware wyłączona przez zasady");
        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring", 1,
            "Defender.Disabled", "Ochrona w czasie rzeczywistym wyłączona przez zasady");
        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableBehaviorMonitoring", 1,
            "Defender.Disabled", "Monitorowanie zachowań wyłączone przez zasady");

        CheckExclusions(found);

        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0,
            "UAC.Disabled", "Kontrola konta użytkownika (UAC) wyłączona");

        CheckDword(found, RegistryHive.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", 1,
            "Policy.Lockout", "Menedżer zadań zablokowany przez zasady");
        CheckDword(found, RegistryHive.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", 1,
            "Policy.Lockout", "Edytor rejestru zablokowany przez zasady");

        CheckDword(found, RegistryHive.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 1,
            "", "");

        CheckDword(found, RegistryHive.LocalMachine,
            @"System\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 1,
            "Credential.Exposure", "WDigest wymusza przechowywanie haseł w postaci jawnej w pamięci");

        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Microsoft\Windows Defender\Features", "TamperProtection", 0,
            "Defender.Disabled", "Ochrona przed manipulacją (Tamper Protection) wyłączona");
        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting", 0,
            "Defender.Disabled", "Raportowanie do chmury Defendera wyłączone");
        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent", 2,
            "Defender.Disabled", "Wysyłanie próbek do Defendera wyłączone");

        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging", 0,
            "Audit.Disabled", "Rejestrowanie bloków skryptów PowerShell wyłączone");
        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", 0,
            "Audit.Disabled", "Rejestrowanie modułów PowerShell wyłączone");

        CheckDword(found, RegistryHive.LocalMachine,
            @"System\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 0,
            "RemoteAccess.Enabled", "Pulpit zdalny (RDP) włączony — sprawdź, czy celowo");

        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 0,
            "UAC.Disabled", "UAC podnosi uprawnienia bez pytania");
        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 0,
            "UAC.Disabled", "Monit UAC poza bezpiecznym pulpitem — podatny na podszycie");

        CheckDword(found, RegistryHive.LocalMachine,
            @"Software\Microsoft\Windows NT\CurrentVersion\SystemRestore", "DisableSR", 1,
            "Recovery.Sabotage", "Przywracanie systemu wyłączone");
        CheckSafeBootRemoved(found);

        CheckProxy(found);

        CheckDword(found, RegistryHive.CurrentUser,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowSuperHidden", 0,
            "", "");

        CheckAppInitDlls(found);

        CheckBootExecute(found);

        CheckComHijack(found);

        CheckServiceAnomalies(found);

        CheckHiddenTasks(found);
        CheckMarkerKeys(found);
        CheckRegistryPayloads(found);
        CheckHiddenKeys(found);
        CheckDanglingAndUnreadable(found);

        return found.Where(f => f.Detection.Length > 0)
                    .Select(f => f with { Detail = Loc.T(f.Detail) })
                    .ToList();
    }

    private static void CheckDanglingAndUnreadable(List<Indicator> found)
    {
        foreach (var (tag, hive, path) in AutostartProbes())
        {
            RegistryKey? key = null;
            try { key = hive.OpenSubKey(path); }
            catch (System.Security.SecurityException)
            {
                found.Add(new Indicator($"{tag}\\{path}", "Suspicious.UnreadableKey",
                    "Klucz autostartu zabezpieczony przed odczytem — nie da się sprawdzić jego zawartości"));
                continue;
            }
            catch { continue; }

            using (key)
            {
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    try
                    {
                        if (key.GetValue(name) is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                        var target = DeclaredExecutable(cmd);
                        if (string.IsNullOrEmpty(target) || File.Exists(target)) continue;
                        found.Add(new Indicator($"{tag}\\{path}|{name}", "Suspicious.DanglingAutorun",
                            Loc.F("Wpis autostartu wskazuje na nieistniejący plik: {0}", target)));
                    }
                    catch { }
                }
            }
        }
    }

    private static string DeclaredExecutable(string command)
    {
        try
        {
            var cmd = Environment.ExpandEnvironmentVariables(command.Trim());
            if (cmd.Length == 0) return "";
            if (cmd[0] == '"')
            {
                int end = cmd.IndexOf('"', 1);
                return end > 1 ? cmd[1..end] : "";
            }

            foreach (var ext in new[] { ".exe", ".com", ".bat", ".cmd", ".scr", ".dll" })
            {
                int i = cmd.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
                if (i > 0) return cmd[..(i + ext.Length)];
            }
            return "";
        }
        catch { return ""; }
    }

    private static IEnumerable<(string Tag, RegistryKey Hive, string Path)> AutostartProbes()
    {
        var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
        foreach (var p in new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        })
            yield return ("HKLM", hklm, p);

        RegistryKey users;
        string[] sids;
        try
        {
            users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            sids = users.GetSubKeyNames();
        }
        catch { yield break; }

        foreach (var sid in sids)
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var p in new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            })
                yield return ("HKU\\" + sid, users, sid + "\\" + p);
        }
    }

    private static void CheckHiddenKeys(List<Indicator> found)
    {
        try
        {
            var korzenie = new List<(string, RegistryKey, string)>();
            try
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                foreach (var sid in users.GetSubKeyNames())
                {
                    if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var p in new[]
                    {
                        @"Software\Microsoft\Windows\CurrentVersion\Run",
                        @"Software\Classes\CLSID",
                        @"Software\Microsoft\Windows\CurrentVersion\Explorer",
                    })
                    {
                        var k = users.OpenSubKey(sid + "\\" + p);
                        if (k != null) korzenie.Add(("HKU\\" + sid + "\\" + p, k, ""));
                    }
                }
            }
            catch { }

            try
            {
                var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                foreach (var p in new[]
                {
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\Classes\CLSID",
                })
                {
                    var k = hklm.OpenSubKey(p);
                    if (k != null) korzenie.Add(("HKLM\\" + p, k, ""));
                }
            }
            catch { }

            foreach (var h in HiddenRegistryKeys.Scan(korzenie))
                found.Add(new Indicator($"{h.ParentPath}\\{h.RawName}", "Malware.HiddenRegistryKey",
                    "Klucz ukryty przed systemem znakiem pustym w nazwie — niewidoczny w edytorze rejestru",
                    Artifact: true));

            foreach (var (_, k, _) in korzenie) { try { k.Dispose(); } catch { } }
        }
        catch { }
    }

    private static void CheckRegistryPayloads(List<Indicator> found)
    {
        var miejsca = new List<(string Tag, RegistryKey Root, string Path)>();
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
            foreach (var sid in users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var p in new[]
                {
                    @"Software\Microsoft\Windows\CurrentVersion\Run",
                    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"Software\Classes\CLSID",
                })
                {
                    var k = users.OpenSubKey(sid + "\\" + p);
                    if (k != null) miejsca.Add(("HKU\\" + sid + "\\" + p, k, p));
                }
            }
        }
        catch { }

        foreach (var (tag, root, _) in miejsca)
        {
            try { ScanValuesForPayload(found, tag, root, depth: 0); }
            catch { }
            finally { try { root.Dispose(); } catch { } }
        }
    }

    private const int PayloadSizeThreshold = 24 * 1024;

    private static void ScanValuesForPayload(List<Indicator> found, string tag, RegistryKey key, int depth)
    {
        if (depth > 2) return;
        foreach (var name in key.GetValueNames())
        {
            object? raw;
            try { raw = key.GetValue(name); } catch { continue; }
            if (raw == null) continue;

            int rozmiar = raw switch
            {
                byte[] b => b.Length,
                string t => t.Length,
                string[] m => m.Sum(x => x.Length),
                _ => 0,
            };

            string? powod = null;
            if (raw is byte[] bin && bin.Length >= 2 && bin[0] == 0x4D && bin[1] == 0x5A)
                powod = Loc.T("wartość zawiera program wykonywalny");
            else if (raw is string txt && LooksLikeEncodedPayload(txt))
                powod = Loc.T("wartość zawiera zakodowany program wykonywalny");
            else if (rozmiar >= PayloadSizeThreshold)
                powod = Loc.F("wartość ma nietypowy rozmiar ({0} KB) jak na wpis konfiguracyjny", rozmiar / 1024);

            if (powod != null)
                found.Add(new Indicator($"{tag}|{name}", "Malware.RegistryPayload",
                    Loc.F("Ładunek trzymany w rejestrze: {0}", powod), Artifact: true));
        }

        foreach (var sub in key.GetSubKeyNames())
        {
            try
            {
                using var k = key.OpenSubKey(sub);
                if (k != null) ScanValuesForPayload(found, tag + "\\" + sub, k, depth + 1);
            }
            catch { }
        }
    }

    private static bool LooksLikeEncodedPayload(string t)
    {
        if (t.Length < 512) return false;
        var s = t.TrimStart();
        if (s.StartsWith("TVqQ", StringComparison.Ordinal)) return true;
        if (s.StartsWith("TVpQ", StringComparison.Ordinal)) return true;
        if (s.StartsWith("4d5a", StringComparison.OrdinalIgnoreCase)) return true;   
        return false;
    }

    private static void CheckComHijack(List<Indicator> found)
    {
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
        var galezie = new List<(string Tag, RegistryKey Root)>();
        try
        {
            foreach (var sid in users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                var k = users.OpenSubKey(sid);
                if (k != null) galezie.Add(("HKU\\" + sid, k));
            }
        }
        catch { }
        if (galezie.Count == 0)
        {
            var own = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            galezie.Add(("HKCU", own));
        }

        foreach (var (tag, hive) in galezie)
        {
            try { CheckComHijackIn(found, hive); }
            catch { }
            finally { try { hive.Dispose(); } catch { } }
        }
    }

    private static void CheckComHijackIn(List<Indicator> found, RegistryKey hkcu)
    {
        try
        {
            using var userClsids = hkcu.OpenSubKey(@"Software\Classes\CLSID");
            if (userClsids == null) return;
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);

            foreach (var clsid in userClsids.GetSubKeyNames())
            {
                string? userDll = null, machineDll = null;
                try
                {
                    using var us = userClsids.OpenSubKey($@"{clsid}\InprocServer32");
                    userDll = us?.GetValue(null) as string;
                    if (string.IsNullOrWhiteSpace(userDll)) continue;

                    using var ms = hklm.OpenSubKey($@"Software\Classes\CLSID\{clsid}\InprocServer32");
                    machineDll = ms?.GetValue(null) as string;
                }
                catch { continue; }

                if (string.IsNullOrWhiteSpace(machineDll)) continue;
                var u = Environment.ExpandEnvironmentVariables(userDll!).Trim().Trim('"');
                var m = Environment.ExpandEnvironmentVariables(machineDll!).Trim().Trim('"');
                if (string.Equals(u, m, StringComparison.OrdinalIgnoreCase)) continue;

                bool present = false;
                try { present = File.Exists(u); } catch { }
                bool trusted = present && Util.SystemFileCheck.HasValidTrustedSignature(u);

                found.Add(new Indicator(
                    $@"HKCU\Software\Classes\CLSID\{clsid}\InprocServer32", DetectionNames.ForText(clsid),
                    trusted
                        ? Loc.F("Klucz użytkownika przesłania systemowy dla {0} — ładowana jest podpisana biblioteka {1} zamiast {2}. Zwykle to celowa rejestracja programu zainstalowanego dla użytkownika.", clsid, u, m)
                        : Loc.F("Przejęcie obiektu COM: klucz użytkownika przesłania systemowy dla {0} — ładowana jest biblioteka {1} zamiast {2}", clsid, u, m),
                    Artifact: present && !trusted));
            }
        }
        catch { }
    }

    private static void CheckServiceAnomalies(List<Indicator> found)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var services = hklm.OpenSubKey(@"System\CurrentControlSet\Services");
            if (services == null) return;

            foreach (var name in services.GetSubKeyNames())
            {
                try
                {
                    using var svc = services.OpenSubKey(name);
                    if (svc == null) continue;

                    if (svc.GetValue("Start") is not int start || start > 2) continue;
                    if (svc.GetValue("ImagePath") is not string img || string.IsNullOrWhiteSpace(img)) continue;

                    var exe = ResolveExecutable(img);
                    if (string.IsNullOrEmpty(exe)) continue;
                    var lower = exe.ToLowerInvariant();

                    bool userWritable = lower.Contains(@"\programdata\") || lower.Contains(@"\appdata\")
                                     || lower.Contains(@"\users\") || lower.Contains(@"\temp\")
                                     || lower.Contains(@"\windows\temp\");
                    if (!userWritable) continue;

                    if (Util.SystemFileCheck.HasValidTrustedSignature(exe)) continue;

                    found.Add(new Indicator($@"HKLM\System\CurrentControlSet\Services\{name}|ImagePath",
                        DetectionNames.ForFile(exe),
                        Loc.F("Usługa „{0}” startuje automatycznie z niepodpisanego pliku w lokalizacji zapisywalnej przez użytkownika: {1}", name, exe),
                        Artifact: true));
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckAppInitDlls(List<Indicator> found)
    {
        foreach (var view in Environment.Is64BitOperatingSystem
                     ? new[] { RegistryView.Registry64, RegistryView.Registry32 }
                     : new[] { RegistryView.Default })
        {
            try
            {
                using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var k = b.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Windows");
                if (k?.GetValue("AppInit_DLLs") is string dlls && !string.IsNullOrWhiteSpace(dlls))
                {
            string tag = view == RegistryView.Registry32 ? "HKLM32" : "HKLM";
                    found.Add(new Indicator($@"{tag}\...\Windows|AppInit_DLLs", DetectionNames.ForText(dlls),
                        Loc.F("AppInit_DLLs wstrzykuje bibliotekę do każdego procesu: {0}", dlls),
                        Artifact: true));
                }
            }
            catch { }
        }
    }

    private static void CheckBootExecute(List<Indicator> found)
    {
        try
        {
            using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = b.OpenSubKey(@"System\CurrentControlSet\Control\Session Manager");
            if (k?.GetValue("BootExecute") is string[] be)
            {
                foreach (var cmd in be)
                {
                    var c = cmd.Trim();
                    if (c.Length == 0) continue;

                    if (c.StartsWith("autocheck", StringComparison.OrdinalIgnoreCase)) continue;
                    found.Add(new Indicator(@"HKLM\...\Session Manager|BootExecute", DetectionNames.ForText(c),
                        $"Nieznana komenda w BootExecute (uruchamiana przed startem Windows): {c}",
                        Artifact: true));
                }
            }
        }
        catch { }
    }

    private static void CheckDword(List<Indicator> found, RegistryHive hive, string path,
                                   string value, int badValue, string detection, string detail)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(path);
            if (key?.GetValue(value) is not int v || v != badValue) return;
            found.Add(new Indicator($@"{HiveName(hive)}\{path}|{value}", detection, detail));
        }
        catch { }
    }

    private static void CheckExclusions(List<Indicator> found)
    {
        foreach (var root in new[]
        {
            @"Software\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            @"Software\Microsoft\Windows Defender\Exclusions\Paths",
        })
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = hklm.OpenSubKey(root);
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    var lower = name.ToLowerInvariant();
                    bool risky = lower.Contains(@"\appdata\") || lower.Contains(@"\temp")
                              || lower.Contains(@"\users\public") || lower.Contains(@"\programdata\")
                              || lower is "c:\\" or "c:";
                    if (!risky) continue;
                    found.Add(new Indicator($@"HKLM\{root}|{name}", "Defender.Exclusion",
                        Loc.F("Wykluczenie Defendera dla lokalizacji zapisywalnej przez użytkownika: {0}", name)));
                }
            }
            catch { }
        }
    }

    private static (string Prefix, string Detection, string Family)[]? _markerPrefixes;
    private static (string Name, string Detection, string Family)[]? _markerExact;

    private static (string Prefix, string Detection, string Family)[] MarkerKeys =>
        _markerPrefixes ??= Data.SignatureStore.List("rat_marker_prefixes")
            .Select(e => e.Split('|', 3))
            .Where(p => p.Length == 3)
            .Select(p => (p[0], p[1], p[2]))
            .ToArray();

    private static (string Name, string Detection, string Family)[] MarkerExact =>
        _markerExact ??= Data.SignatureStore.List("rat_marker_names")
            .Select(e => e.Split('|', 3))
            .Where(p => p.Length == 3)
            .Select(p => (p[0], p[1], p[2]))
            .ToArray();

    private static void CheckMarkerKeys(List<Indicator> found)
    {
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var soft = hkcu.OpenSubKey("Software");
            if (soft == null) return;
            foreach (var sub in soft.GetSubKeyNames())
            {
                foreach (var (prefix, det, family) in MarkerKeys)
                    if (sub.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        found.Add(new Indicator($@"HKCU\Software\{sub}", det,
                            $"Klucz konfiguracyjny pozostawiany przez {family}"));
                foreach (var (name, det, family) in MarkerExact)
                    if (sub.Equals(name, StringComparison.OrdinalIgnoreCase))
                        found.Add(new Indicator($@"HKCU\Software\{sub}", det,
                            $"Klucz konfiguracyjny pozostawiany przez {family}"));
            }
        }
        catch { }
    }

    private static void CollectScheduledTasks(List<Item> items, HashSet<string> seen)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var tree = hklm.OpenSubKey(TaskCache + @"\Tree");
            if (tree == null) return;

            var taskRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
            foreach (var name in EnumerateTaskNames(tree, ""))
            {
                var xml = Path.Combine(taskRoot, name.Replace('/', '\\').TrimStart('\\'));
                if (!File.Exists(xml)) continue;
                string text;
                try { text = File.ReadAllText(xml); } catch { continue; }

                foreach (Match m in Regex.Matches(text, @"<Command>\s*([^<]+?)\s*</Command>",
                                                  RegexOptions.IgnoreCase))
                    AddResolved(items, seen, $@"Zadanie: {name}", m.Groups[1].Value, "ScheduledTask");
            }
        }
        catch { }
    }

    public static void CollectTaskFiles(List<Item> items, HashSet<string> seen,
                                        string? windowsDirOverride = null)
    {
        var win = windowsDirOverride ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(win)) return;

        foreach (var sub in new[] { @"System32\Tasks", @"SysWOW64\Tasks" })
        {
            var root = Path.Combine(win, sub);
            if (!Directory.Exists(root)) continue;

            var files = SafeListFiles(root, "*", recurse: true);

            foreach (var f in files)
            {
                string text;
                try
                {
                    if (new FileInfo(f).Length > 512 * 1024) continue;
                    text = File.ReadAllText(f);
                }
                catch { continue; }
                if (text.IndexOf("<Task", StringComparison.OrdinalIgnoreCase) < 0) continue;

                var taskName = f.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar);

                foreach (var tag in new[] { "Command", "Arguments" })
                    foreach (Match m in Regex.Matches(text, $@"<{tag}>\s*([^<]+?)\s*</{tag}>",
                                                      RegexOptions.IgnoreCase))
                        AddResolved(items, seen, $@"Zadanie: {taskName}", m.Groups[1].Value, "ScheduledTask");
            }
        }

        var legacy = Path.Combine(win, "Tasks");
        if (!Directory.Exists(legacy)) return;
        var jobs = SafeListFiles(legacy, "*.job", recurse: false);

        foreach (var job in jobs)
        {
            byte[] raw;
            try
            {
                if (new FileInfo(job).Length > 1024 * 1024) continue;
                raw = File.ReadAllBytes(job);
            }
            catch { continue; }

            foreach (var candidate in WideStrings(raw, minLength: 6))
                AddResolved(items, seen, $@"Zadanie (.job): {Path.GetFileName(job)}", candidate, "ScheduledTask");
        }
    }

    private static List<string> SafeListFiles(string root, string pattern, bool recurse)
    {
        var result = new List<string>();
        try
        {
            var opts = new EnumerationOptions
            {
                RecurseSubdirectories = recurse,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            };

            foreach (var f in Directory.EnumerateFiles(root, pattern, opts)) result.Add(f);
        }
        catch {  }
        return result;
    }

    private static IEnumerable<string> WideStrings(byte[] data, int minLength)
    {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i + 1 < data.Length; i += 2)
        {
            char c = (char)(data[i] | (data[i + 1] << 8));
            if (c >= ' ' && c <= '\uFFFD' && !char.IsControl(c)) sb.Append(c);
            else
            {
                if (sb.Length >= minLength) yield return sb.ToString();
                sb.Clear();
            }
        }
        if (sb.Length >= minLength) yield return sb.ToString();
    }

    private static IEnumerable<string> EnumerateTaskNames(RegistryKey key, string prefix)
    {
        foreach (var sub in key.GetSubKeyNames())
        {
            string full = string.IsNullOrEmpty(prefix) ? sub : prefix + "\\" + sub;
            RegistryKey? child = null;
            try { child = key.OpenSubKey(sub); } catch { }
            if (child == null) { yield return full; continue; }
            using (child)
            {
                bool leaf = child.GetValue("Id") != null;
                if (leaf) yield return full;
                else
                    foreach (var deeper in EnumerateTaskNames(child, full))
                        yield return deeper;
            }
        }
    }

    private static void AddResolved(List<Item> items, HashSet<string> seen,
                                    string location, string command, string kind)
    {
        var path = ResolveExecutable(command);
        if (string.IsNullOrEmpty(path)) return;
        if (!seen.Add(path + "|" + location)) return;
        items.Add(new Item(location, path, kind));
    }

    public static string ResolveExecutable(string command)
    {
        try
        {
            var cmd = Environment.ExpandEnvironmentVariables(command.Trim());
            if (cmd.Length == 0) return "";

            if (cmd[0] == '"')
            {
                int end = cmd.IndexOf('"', 1);
                if (end > 1)
                {
                    var quoted = cmd[1..end];
                    if (Exists(quoted)) return Path.GetFullPath(quoted);
                }
            }

            var parts = cmd.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (int take = parts.Length; take >= 1; take--)
            {
                var candidate = string.Join(' ', parts, 0, take).Trim().Trim('"');
                if (Exists(candidate)) return Path.GetFullPath(candidate);
            }

            foreach (var rawTok in cmd.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var tok = rawTok.Trim().Trim('"');
                if (tok.Length < 4 || tok.StartsWith('-') || tok.StartsWith('/')) continue;
                if (Exists(tok)) return Path.GetFullPath(tok);
            }
            return "";
        }
        catch { return ""; }
    }

    private static bool Exists(string path)
    {
        try { return path.Length > 3 && File.Exists(path); }
        catch { return false; }
    }

    private static void CheckSafeBootRemoved(List<Indicator> found)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var minimal = hklm.OpenSubKey(@"System\CurrentControlSet\Control\SafeBoot\Minimal");
            if (minimal != null && minimal.GetSubKeyNames().Length > 0) return;
            found.Add(new Indicator(@"HKLM\System\CurrentControlSet\Control\SafeBoot\Minimal",
                "Recovery.Sabotage",
                "Konfiguracja trybu awaryjnego usunięta — system może nie dać się uruchomić w trybie awaryjnym"));
        }
        catch { }
    }

    private static void CheckProxy(List<Indicator> found)
    {
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var key = hkcu.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key == null) return;

            if (key.GetValue("AutoConfigURL") is string pac && !string.IsNullOrWhiteSpace(pac))
                found.Add(new Indicator(@"HKCU\...\Internet Settings|AutoConfigURL", "Network.Redirect",
                    Loc.F("Automatyczna konfiguracja serwera proxy: {0} — cały ruch przechodzi przez wskazany adres", pac)));

            if (key.GetValue("ProxyEnable") is int on && on == 1
                && key.GetValue("ProxyServer") is string px && !string.IsNullOrWhiteSpace(px)
                && !px.StartsWith("127.0.0.1", StringComparison.Ordinal)
                && !px.StartsWith("localhost", StringComparison.OrdinalIgnoreCase))
                found.Add(new Indicator(@"HKCU\...\Internet Settings|ProxyServer", "Network.Redirect",
                    Loc.F("Ruch kierowany przez serwer proxy: {0} — sprawdź, czy ustawiony celowo", px)));
        }
        catch { }
    }

    private static void CheckHiddenTasks(List<Indicator> found)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var tree = hklm.OpenSubKey(TaskCache + @"\Tree");
            if (tree == null) return;
            foreach (var name in EnumerateTaskNames(tree, ""))
            {
                using var t = tree.OpenSubKey(name.Replace('/', '\\'));
                if (t == null) continue;
                if (t.GetValue("Id") == null) continue;      
                if (t.GetValue("SD") != null) continue;      
                found.Add(new Indicator($@"HKLM\{TaskCache}\Tree\{name}", "Task.Hidden",
                    $"Zadanie {name} ukryte przed harmonogramem (usunięty deskryptor zabezpieczeń) " +
                    "— technika ukrywania persystencji", Artifact: true));
            }
        }
        catch { }
    }

    private static string HiveName(RegistryHive hive) => hive switch
    {
        RegistryHive.CurrentUser  => "HKCU",
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.Users        => "HKU",
        _                         => hive.ToString(),
    };
}
