namespace Malward.ResidentShield.Hips;

public static class HipsSelfGuard
{
    private static readonly string[] OwnServiceNames =
    {
        "MalwardResidentShield", "MalwardNetworkScanner", "MalwardBackupEngine",
    };

    private static readonly string[] OwnTaskNames = { "MalwardGuiAutostart" };

    private const string OwnResolver = "127.0.0.1";

    public static bool IsOwnProcessTree(int pid, int maxDepth = 6)
    {
        try
        {
            if (pid <= 4) return false;
            var img = NativeProcess.GetImagePath(pid);
            if (SystemGuard.IsOwnComponent(img)) return true;

            int depth = 0;
            foreach (var anc in NativeProcess.GetAncestors(pid, maxDepth))
            {
                if (++depth > maxDepth || anc <= 4) break;
                if (SystemGuard.IsOwnComponent(NativeProcess.GetImagePath(anc))) return true;
            }
        }
        catch { }
        return false;
    }

    public static bool IsOwnCommand(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        var c = commandLine.ToLowerInvariant();

        if (OwnTaskNames.Any(t => c.Contains(t.ToLowerInvariant()))) return true;

        if (c.Contains("set-dnsclientserveraddress") &&
            (c.Contains(OwnResolver) || c.Contains("-resetserveraddresses"))) return true;

        return false;
    }

    public static bool IsOwnRegistryFootprint(string ruleId, string location, string? value,
                                              string? previousValue = null)
    {
        if (string.IsNullOrEmpty(location)) return false;
        var loc = location.ToLowerInvariant();
        var val = (value ?? "").Trim();
        var prev = (previousValue ?? "").Trim();

        switch (ruleId)
        {
            case "reg.dns":

                if (val == OwnResolver) return true;

                if (prev == OwnResolver) return true;

                return false;

            case "reg.session_manager":

                return loc.Contains("pendingfilerenameoperations") && MentionsOwnFiles(val);

            case "reg.services":
            case "reg.service_config":

                return OwnServiceNames.Any(s => loc.Contains("\\" + s.ToLowerInvariant()));

            case "reg.run":
            case "reg.shell_folders":
                return MentionsOwnFiles(val);

            default:
                return false;
        }
    }

    public static bool IsOwnTaskFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var name = Path.GetFileName(path);
        return OwnTaskNames.Any(t => string.Equals(name, t, StringComparison.OrdinalIgnoreCase));
    }

    public static bool TargetsOwnService(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        var c = commandLine.ToLowerInvariant();
        return OwnServiceNames.Any(s => c.Contains(s.ToLowerInvariant()));
    }

    public static IReadOnlyList<string> ServiceNames => OwnServiceNames;

    private static bool MentionsOwnFiles(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;

        foreach (var part in text.Split(new[] { '\0', '\n', '\r', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var p = part.Trim();
            if (p.StartsWith(@"\??\")) p = p[4..];
            if (p.StartsWith("*")) p = p.TrimStart('*');
            if (p.StartsWith(@"\??\")) p = p[4..];
            if (SystemGuard.IsOwnComponent(p)) return true;
            if (LooksLikeOwnInstallPath(p)) return true;
        }
        return SystemGuard.IsOwnComponent(text) || LooksLikeOwnInstallPath(text);
    }

    private static bool LooksLikeOwnInstallPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (path.IndexOf(@"\Malward\", StringComparison.OrdinalIgnoreCase) < 0) return false;
        var name = Path.GetFileName(path.TrimEnd('\\'));
        if (string.IsNullOrEmpty(name)) return false;
        string[] own =
        {
            "malward.exe", "malscan.exe", "mwshield.exe", "mwshield.dll",

            "rsmonitor.exe", "rsmonitor.dll", "netmonitor.exe",
            "netmonitor.dll", "bkmonitor.exe", "bkmonitor.dll", "heurscanner.exe",
            "malward.dll", "malscan.dll", "malward.fwmanager.dll",
        };
        return own.Contains(name, StringComparer.OrdinalIgnoreCase);
    }
}
