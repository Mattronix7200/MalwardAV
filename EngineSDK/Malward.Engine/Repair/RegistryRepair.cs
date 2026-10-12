using System.Security.AccessControl;
using Microsoft.Win32;

namespace Malward.Engine.Repair;

public static class RegistryRepair
{
    public sealed record Outcome(bool Ok, string? Error);

    public static bool IsRegistryLocation(string location)
        => !string.IsNullOrWhiteSpace(location)
           && (location.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
            || location.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)
            || location.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase));

    public static Outcome Remove(string location)
    {
        try
        {
            if (TaskRepair.IsTaskLocation(location)) return TaskRepair.Remove(location);

            if (!TryParse(location, out var hive, out var view, out var subPath, out var valueName))
                return new Outcome(false, $"Nie rozpoznano ścieżki rejestru: {location}");

            using var baseKey = RegistryKey.OpenBaseKey(hive, view);

            if (string.IsNullOrEmpty(valueName))
            {
                using (var probe = baseKey.OpenSubKey(subPath))
                    if (probe == null) return new Outcome(true, null);
                try
                {
                    baseKey.DeleteSubKeyTree(subPath, throwOnMissingSubKey: false);
                    return new Outcome(true, null);
                }
                catch (Exception ex) { return new Outcome(false, Explain(ex)); }
            }

            RegistryKey? key = null;
            string? openError = null;
            foreach (var attempt in new Func<RegistryKey?>[]
            {
                () => baseKey.OpenSubKey(subPath, writable: true),
                () => baseKey.OpenSubKey(subPath, RegistryKeyPermissionCheck.ReadWriteSubTree,
                                         RegistryRights.SetValue | RegistryRights.QueryValues),
            })
            {
                try { key = attempt(); if (key != null) break; }
                catch (Exception ex) { openError ??= Explain(ex); }
            }

            if (key == null)
            {
                using var probe = baseKey.OpenSubKey(subPath);
                if (probe == null) return new Outcome(true, null);
                return new Outcome(false, openError ?? "Brak dostępu do klucza rejestru.");
            }

            using (key)
            {
                try
                {
                    if (key.GetValue(valueName) == null) return new Outcome(true, null);
                    key.DeleteValue(valueName, throwOnMissingValue: false);
                    return new Outcome(true, null);
                }
                catch (Exception ex) { return new Outcome(false, Explain(ex)); }
            }
        }
        catch (Exception ex) { return new Outcome(false, Explain(ex)); }
    }

    private static string Explain(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "Brak uprawnień do zapisu w tym kluczu (uruchom jako administrator; klucz może być chroniony przez system).",
        System.Security.SecurityException => "Klucz chroniony przez system — odmowa dostępu nawet dla administratora.",
        _ => ex.Message,
    };

    public static bool TryParse(string location, out RegistryHive hive, out RegistryView view,
                                out string subPath, out string valueName)
    {
        hive = RegistryHive.LocalMachine;
        view = RegistryView.Default;
        subPath = ""; valueName = "";
        if (string.IsNullOrWhiteSpace(location)) return false;

        var loc = location.Trim();
        int bar = loc.IndexOf('|');
        if (bar >= 0) { valueName = loc[(bar + 1)..].Trim(); loc = loc[..bar]; }

        int slash = loc.IndexOf('\\');
        if (slash <= 0) return false;
        var prefix = loc[..slash].ToUpperInvariant();
        subPath = loc[(slash + 1)..].Trim('\\');
        if (subPath.Length == 0) return false;

        if (prefix.EndsWith("32", StringComparison.Ordinal))
        {
            view = RegistryView.Registry32;
            prefix = prefix[..^2];
        }
        else if (Environment.Is64BitOperatingSystem)
        {
            view = RegistryView.Registry64;
        }

        switch (prefix)
        {
            case "HKLM": hive = RegistryHive.LocalMachine; break;
            case "HKCU": hive = RegistryHive.CurrentUser;  break;
            case "HKU":

                hive = RegistryHive.Users;
                break;
            default: return false;
        }
        return true;
    }
}
