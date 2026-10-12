using Microsoft.Win32;

namespace Malward.Engine.Core;

public static class RegistryLoadPoints
{
    public sealed record Item(string Location, string FilePath, string Kind);

    private sealed record DllPoint(RegistryHive Hive, string Path, string ValueName, string Kind, bool PerSubkey);

    private static readonly DllPoint[] DllPoints =
    {
        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Print\Monitors", "Driver", "PrintMonitor", true),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "Security Packages", "LsaPackage", false),
        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "Authentication Packages", "LsaPackage", false),
        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Control\Lsa", "Notification Packages", "LsaPackage", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Netsh", "", "NetshHelper", false),

        new(RegistryHive.LocalMachine, @"System\CurrentControlSet\Services\W32Time\TimeProviders", "DllName", "TimeProvider", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "", "ShellHook", false),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler", "", "ShellHook", false),
        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "", "ShellHook", false),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\AMSI\Providers", "", "AmsiProvider", true),

        new(RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers", "", "CredProvider", true),
    };

    public static List<Item> Collect()
    {
        var items = new List<Item>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pt in DllPoints)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(pt.Hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(pt.Path);
                if (key == null) continue;

                if (pt.PerSubkey)
                {
                    foreach (var sub in key.GetSubKeyNames())
                    {
                        using var s = key.OpenSubKey(sub);
                        if (s == null) continue;
                        var raw = pt.ValueName.Length > 0
                            ? s.GetValue(pt.ValueName) as string
                            : s.GetValue("") as string;
                        Add(items, seen, $@"HKLM\{pt.Path}\{sub}", raw, pt.Kind);
                    }
                }
                else if (pt.ValueName.Length > 0)
                {
                    var v = key.GetValue(pt.ValueName);
                    foreach (var one in AsStrings(v))
                        Add(items, seen, $@"HKLM\{pt.Path}|{pt.ValueName}", one, pt.Kind);
                }
                else
                {
                    foreach (var name in key.GetValueNames())
                        Add(items, seen, $@"HKLM\{pt.Path}|{name}", key.GetValue(name) as string, pt.Kind);
                    foreach (var sub in key.GetSubKeyNames())
                        Add(items, seen, $@"HKLM\{pt.Path}\{sub}", sub, pt.Kind);
                }
            }
            catch { }
        }

        CollectServices(items, seen);
        return items;
    }

    private static void CollectServices(List<Item> items, HashSet<string> seen)
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var services = hklm.OpenSubKey(@"System\CurrentControlSet\Services");
            if (services == null) return;

            foreach (var name in services.GetSubKeyNames())
            {
                using var svc = services.OpenSubKey(name);
                if (svc == null) continue;

                Add(items, seen, $@"Usługa: {name}|ImagePath", svc.GetValue("ImagePath") as string, "Service");

                using var pars = svc.OpenSubKey("Parameters");
                Add(items, seen, $@"Usługa: {name}|ServiceDll", pars?.GetValue("ServiceDll") as string, "ServiceDll");
            }
        }
        catch { }
    }

    private static void Add(List<Item> items, HashSet<string> seen, string location, string? raw, string kind)
    {
        if (string.IsNullOrWhiteSpace(raw)) return;

        var value = raw!.Trim();
        if (value.StartsWith('{') && value.EndsWith('}'))
        {
            value = ResolveClsid(value) ?? "";
            if (value.Length == 0) return;
        }

        value = value.Replace(@"\??\", "").Replace(@"\SystemRoot\",
            Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\");
        if (value.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase))
            value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), value[9..]);

        var file = RegistryScanner.ResolveExecutable(value);
        if (file.Length == 0) return;
        if (!seen.Add(file + "|" + location)) return;
        items.Add(new Item(location, file, kind));
    }

    private static string? ResolveClsid(string clsid)
    {
        foreach (var (hive, path) in new[]
        {
            (RegistryHive.CurrentUser,  $@"Software\Classes\CLSID\{clsid}\InprocServer32"),
            (RegistryHive.LocalMachine, $@"Software\Classes\CLSID\{clsid}\InprocServer32"),
            (RegistryHive.LocalMachine, $@"Software\Classes\Wow6432Node\CLSID\{clsid}\InprocServer32"),
        })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(path);
                if (key?.GetValue("") is string dll && !string.IsNullOrWhiteSpace(dll)) return dll;
            }
            catch { }
        }
        return null;
    }

    private static IEnumerable<string> AsStrings(object? value) => value switch
    {
        string s        => new[] { s },
        string[] multi  => multi,
        _               => Array.Empty<string>(),
    };
}
