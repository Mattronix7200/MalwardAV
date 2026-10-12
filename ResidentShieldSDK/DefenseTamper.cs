using System.Text.RegularExpressions;

namespace Malward.ResidentShield;

public static class DefenseTamper
{
    public readonly record struct Hit(string Category, string Description);

    private static readonly Dictionary<string, string[]> SigCache = new();
    private static string[] Sig(string key)
    {
        lock (SigCache)
        {
            if (!SigCache.TryGetValue(key, out var v))
            { v = Malward.Engine.Data.SignatureStore.List(key); SigCache[key] = v; }
            return v;
        }
    }

    public static Hit? Match(string cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine)) return null;
        string c = cmdLine.ToLowerInvariant();

        var shadowTools = Sig("shadow_tools");
        var shadowPhrases = Sig("shadow_phrases");

        if (shadowTools.Any(t => c.Contains(t))
            && c.Contains("delete") && (c.Contains("shadow") || c.Contains("catalog") || c.Contains("backup")))
            return new("ShadowCopyDeletion", "Usuwanie kopii w tle / kopii zapasowych");
        if (shadowPhrases.Length > 0 && c.Contains(shadowPhrases[0]) && c.Contains("delete"))
            return new("ShadowCopyDeletion", "Usuwanie kopii w tle (zapytanie WMI)");
        if (shadowPhrases.Length > 3 && c.Contains(shadowPhrases[1])
            && (c.Contains(shadowPhrases[2]) || c.Contains(shadowPhrases[3])))
            return new("ShadowCopyDeletion", "Redukcja magazynu kopii w tle (usuwa istniejące punkty)");

        if (c.Contains("bcdedit") && Sig("boot_tamper").Any(t => c.Contains(t)))
            return new("BootConfigTamper", "Sabotaz konfiguracji rozruchu/odzyskiwania (bcdedit)");

        var usn = Sig("usn_tamper");
        if (usn.Length == 3 && usn.All(t => c.Contains(t)))
            return new("UsnJournalDeletion", "Kasowanie dziennika USN (blokuje wycofanie zmian i analize)");

        if (c.Contains("wevtutil") && (c.Contains(" cl ") || c.Contains(" clear-log")))
            return new("LogTampering", "Czyszczenie dziennikow zdarzen (wevtutil)");
        if (c.Contains("clear-eventlog"))
            return new("LogTampering", "Czyszczenie dziennikow zdarzen (Clear-EventLog)");

        if (c.Contains("cipher") && Regex.IsMatch(c, @"\s/w[:\s]"))
            return new("FreeSpaceWipe", "Zamazywanie wolnego miejsca (cipher /w)");

        var cmdlets = Sig("defender_cmdlets");
        if (cmdlets.Length > 0 && c.Contains(cmdlets[0]) && Sig("defender_disable_switches").Any(x => c.Contains(x)))
            return new("DefenderDisable", "Wylaczanie ochrony Microsoft Defender (polecenie PowerShell)");
        if (cmdlets.Length > 1 && c.Contains(cmdlets[1]) && Sig("defender_exclusion_switches").Any(x => c.Contains(x)))
            return new("DefenderExclusion", "Dodawanie wykluczen Microsoft Defender (polecenie PowerShell)");

        if (c.Contains("netsh") && c.Contains("advfirewall") && c.Contains("set") && c.Contains("state off"))
            return new("FirewallDisable", "Wylaczanie zapory Windows (netsh advfirewall)");
        if (c.Contains("netsh") && c.Contains("firewall") && c.Contains("opmode") && c.Contains("disable"))
            return new("FirewallDisable", "Wylaczanie zapory Windows (netsh firewall)");

        if ((c.Contains("sc ") || c.Contains("sc.exe") || c.Contains("net stop")
             || c.Contains("stop-service") || c.Contains("set-service"))
            && Sig("security_services").Any(x => c.Contains(x)))
            return new("SecurityServiceDisable", "Zatrzymywanie uslug bezpieczenstwa systemu");

        if (c.Contains("reg") && (c.Contains(" add") || c.Contains(" delete"))
            && Sig("defender_reg_values").Any(x => c.Contains(x)))
            return new("DefenderRegTamper", "Rejestrowe wylaczenie Microsoft Defender");

        return null;
    }

    private static readonly Regex RawVolume =
        new(@"\\device\\harddiskvolume\d+$", RegexOptions.Compiled);

    public static bool IsRawDiskPath(string rawFileName)
    {
        if (string.IsNullOrEmpty(rawFileName)) return false;
        string l = rawFileName.ToLowerInvariant();
        if (l.Contains("physicaldrive")) return true;
        if (l.Contains(@"\harddisk") && l.Contains(@"\dr")) return true;   
        if (RawVolume.IsMatch(l)) return true;
        return false;
    }
}
