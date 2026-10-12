using System.Globalization;
using System.Text;
using Malward.Engine.Util;

namespace Malward.Engine.Core;

public static class Masquerade
{
    public sealed record Hit(string Detection, string Reason);

    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "conhost.exe", "csrss.exe", "lsass.exe", "lsaiso.exe", "services.exe",
        "winlogon.exe", "smss.exe", "wininit.exe", "explorer.exe", "spoolsv.exe", "dwm.exe",
        "taskhost.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe", "dllhost.exe", "rundll32.exe",
        "regsvr32.exe", "searchindexer.exe", "searchprotocolhost.exe", "runtimebroker.exe",
        "fontdrvhost.exe", "audiodg.exe", "wuauclt.exe", "userinit.exe", "logonui.exe",
        "wmiprvse.exe", "dashost.exe", "sppsvc.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    };

    private static readonly HashSet<string> GenuineNames = new(ProtectedNames, StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry", "memcompression", "secure system", "msmpeng.exe", "nissrv.exe",
        "mpcmdrun.exe", "securityhealthservice.exe", "trustedinstaller.exe", "searchapp.exe",
        "startmenuexperiencehost.exe", "shellexperiencehost.exe", "applicationframehost.exe",
        "backgroundtaskhost.exe", "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "notepad.exe", "calc.exe", "control.exe", "msdtc.exe", "spoolsv.exe",
    };

    private static readonly string[] SystemDirs =
        { @"\windows\system32\", @"\windows\syswow64\", @"\windows\winsxs\", @"\windows\servicing\" };

    private static readonly HashSet<string> LureExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".rar",
        ".html", ".htm", ".xml", ".json", ".log", ".ini",
    };
    private static readonly HashSet<string> ExecExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".jar", ".hta", ".ps1", ".wsf", ".wsh", ".cpl", ".msi", ".lnk",
    };

    private static readonly HashSet<string> BinaryExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".pif", ".cpl",
    };

    private static readonly char[] BidiControls =
        { '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069' };

    private static readonly Dictionary<char, char> Confusables = new()
    {
        ['\u0430']='a', ['\u0435']='e', ['\u043E']='o', ['\u0441']='c', ['\u0440']='p',
        ['\u0445']='x', ['\u0455']='s', ['\u0456']='i', ['\u0501']='d', ['\u04BB']='h',
        ['\u0410']='A', ['\u0415']='E', ['\u041E']='O', ['\u0421']='C', ['\u0420']='P',
        ['\u0425']='X', ['\u04CF']='l', ['\u0269']='i',
    };

    public static Hit? CheckFile(string path, bool verifySignature = true)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var name = Path.GetFileName(path);

        var byName = NameHit(name);
        if (byName != null) return byName;

        var shortcutHit = ShortcutHit(path, name);
        if (shortcutHit != null) return shortcutHit;

        if (HasTrailingSpaceOrDotComponent(path))
            return new Hit(DetectionNames.ForFile(path),
                $"Nazwa pliku lub folderu z końcową spacją/kropką (ukrywanie prawdziwej ścieżki): {path}");

        if (ProtectedNames.Contains(name) && !InSystemDir(path))
        {
            if (verifySignature && SystemFileCheck.IsGenuineSystemFile(path)) return null;
            return new Hit(DetectionNames.ForFile(path),
                $"Plik o nazwie systemowej ({name}) uruchamiany spoza katalogu systemowego: {path} " +
                "— podszycie pod komponent Windows");
        }
        return null;
    }

    private static bool IsShortcutExt(string ext) =>
        string.Equals(ext, ".lnk", StringComparison.OrdinalIgnoreCase);

    private static Hit? ShortcutHit(string path, string name)
    {
        if (!IsShortcutExt(Path.GetExtension(name))) return null;

        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(name));
        bool lureName = !string.IsNullOrEmpty(inner) && LureExts.Contains(inner);

        var reason = ShortcutTarget.DangerousReason(path);
        if (reason == null) return null;

        return lureName
            ? new Hit(DetectionNames.ForFile(path),
                $"Skrót o nazwie dokumentu ({inner}.lnk), a {reason}: {path}")
            : new Hit(DetectionNames.ForFile(path),
                $"Skrót, który {reason}: {path}");
    }

    public static Hit? NameHit(string name)
    {
        if (string.IsNullOrEmpty(name)) return null;

        if (name.IndexOfAny(BidiControls) >= 0)
            return new Hit(DetectionNames.ForText(name),
                $"Nazwa zawiera znak sterujący kierunkiem tekstu (RTLO) — ukrywa prawdziwe rozszerzenie: {Sanitize(name)}");

        var ext = Path.GetExtension(name);
        if (ExecExts.Contains(ext) && !IsShortcutExt(ext))
        {
            var stem = Path.GetFileNameWithoutExtension(name);
            var inner = Path.GetExtension(stem);
            if (!string.IsNullOrEmpty(inner) && LureExts.Contains(inner))
                return new Hit(DetectionNames.ForText(name),
                    $"Podwójne rozszerzenie {inner}{ext} — plik wykonywalny udający dokument: {name}");
        }

        var canon = DeConfuse(name);
        bool spoofedGlyphs = !string.Equals(canon, name, StringComparison.Ordinal);
        if (!GenuineNames.Contains(name) && ExecExts.Contains(ext))
        {
            if (spoofedGlyphs && ProtectedNames.Contains(canon))
                return new Hit(DetectionNames.ForText(name),
                    $"Nazwa zapisana znakami podobnymi do systemowej ({canon}): {Sanitize(name)}");

            var stem = Path.GetFileNameWithoutExtension(canon);
            if (stem.Length >= 5 && BinaryExts.Contains(ext))
                foreach (var prot in ProtectedNames)
                {
                    var protStem = Path.GetFileNameWithoutExtension(prot);
                    if (Math.Abs(protStem.Length - stem.Length) > 1) continue;
                    if (string.Equals(stem, protStem, StringComparison.OrdinalIgnoreCase)) continue;
                    if (Levenshtein(stem.ToLowerInvariant(), protStem.ToLowerInvariant()) == 1)
                        return new Hit(DetectionNames.ForText(name),
                            $"Nazwa łudząco podobna do systemowej ({prot}): {name}");
                }
        }
        return null;
    }

    public static Hit? CheckProcess(string imagePath) => CheckFile(imagePath, verifySignature: true);

    public static Hit? CheckService(string serviceName, string? displayName, string imagePath)
    {
        var byBinary = CheckFile(imagePath, verifySignature: true);
        if (byBinary != null) return byBinary;

        var dn = (displayName ?? "").ToLowerInvariant();
        bool posesAsWindows = dn.Contains("windows ") || dn.Contains("microsoft ")
                           || dn.Contains("defender") || dn.Contains("windows update")
                           || dn.Contains("security center") || dn.Contains("host process");
        if (posesAsWindows && !string.IsNullOrWhiteSpace(imagePath))
        {
            var lower = imagePath.ToLowerInvariant();
            bool trustedLocation = InSystemDir(imagePath)
                || lower.Contains(@"\program files\") || lower.Contains(@"\program files (x86)\");
            if (!trustedLocation && !SystemFileCheck.IsSignedByMicrosoft(imagePath))
                return new Hit(DetectionNames.ForFile(imagePath),
                    $"Usługa „{serviceName}” podszywa się pod komponent Windows, a jej plik leży poza " +
                    $"zaufaną lokalizacją i nie jest podpisany: {imagePath}");
        }
        return null;
    }

    public static bool CheckFolder(string dir, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(dir)) return false;
        var name = Path.GetFileName(dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        if (name.Length > 0 && (name[^1] == ' ' || name[^1] == '.'))
        {
            reason = $"Folder z końcową spacją/kropką w nazwie (podszycie pod prawdziwy katalog): {dir}";
            return true;
        }

        var spoofRoots = new[] { "windows", "system32", "syswow64", "windows nt", "microsoft" };
        var parent = Path.GetDirectoryName(dir)?.TrimEnd('\\') ?? "";
        bool inDriveRoot = parent.Length <= 3 && parent.EndsWith(":");
        if (inDriveRoot && Array.Exists(spoofRoots, r => string.Equals(r, name, StringComparison.OrdinalIgnoreCase))
            && !string.Equals(dir.TrimEnd('\\'), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            reason = $"Folder o nazwie systemowej w nietypowej lokalizacji: {dir}";
            return true;
        }
        return false;
    }

    private static bool InSystemDir(string path)
    {
        var p = path.ToLowerInvariant();
        return Array.Exists(SystemDirs, d => p.Contains(d));
    }

    private static bool HasTrailingSpaceOrDotComponent(string path)
    {
        foreach (var part in path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (part.Length == 0) continue;

            var trimmed = part.TrimEnd();
            if (trimmed.Length != part.Length) return true;
            if (part.Length >= 2 && part[^1] == '.' && part[^2] != '.') 
            {
                if (Path.GetExtension(part).Length == 0) return true;
            }
        }
        return false;
    }

    private static string DeConfuse(string s)
    {
        if (s.All(c => c < 128)) return s;
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(Confusables.TryGetValue(c, out var r) ? r : c);
        return sb.ToString();
    }

    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(char.IsControl(c) || Array.IndexOf(BidiControls, c) >= 0 ? '\uFFFD' : c);
        return sb.ToString();
    }

    private static int Levenshtein(string a, string b)
    {
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
            {
                int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        return d[a.Length, b.Length];
    }
}
