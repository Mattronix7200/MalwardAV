using System.Text;

namespace Malward.Engine.Util;

public sealed record ShortcutInfo(string Target, string Arguments, bool Readable);

public static class ShortcutTarget
{
    private const int MaxBytes = 2 * 1024 * 1024;

    private static readonly byte[] Magic =
    {
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x46,
    };

    private static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "forfiles.exe",
        "wmic.exe", "curl.exe", "python.exe", "pythonw.exe", "node.exe", "conhost.exe",
        "explorer.exe", "hh.exe", "ieexec.exe", "cmstp.exe", "scriptrunner.exe",
    };

    private static readonly HashSet<string> ScriptExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
        ".scr", ".pif", ".com", ".jar", ".py",
    };

    private static readonly HashSet<string> ExecExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl",
    };

    private static readonly string[] GeneratedShortcutDirs =
    {
        @"\windows\recent\", @"\recent\automaticdestinations\",
        @"\recent\customdestinations\", @"\microsoft\office\recent\",
    };

    private static readonly string[] VolatileDirs =
    {
        @"\appdata\local\temp\", @"\windows\temp\", @"\downloads\",
    };

    private static readonly string[] CommandLineMarkers =
    {
        "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
        "frombase64string", "downloadstring", "downloadfile", "invoke-expression", "iex ",
        "invoke-webrequest", "start-process", "executionpolicy bypass", "http://", "https://",
        "ftp://", "javascript:", "vbscript:", "scrobj.dll", "curl ", "certutil ", "bitsadmin ",
    };

    public static ShortcutInfo Read(string lnkPath)
    {
        try
        {
            using var stream = File.OpenRead(lnkPath);
            int take = (int)Math.Min(stream.Length, MaxBytes);
            var bytes = new byte[take];
            int read = stream.Read(bytes, 0, take);
            if (read < 76 || !StartsWithMagic(bytes))
                return new ShortcutInfo("", "", false);

            var wide = Encoding.Unicode.GetString(bytes, 0, read);
            var narrow = Encoding.Latin1.GetString(bytes, 0, read);

            var paths = new List<string>();
            CollectPaths(paths, wide);
            CollectPaths(paths, narrow);

            string target = paths.FirstOrDefault(p => ExecExts.Contains(SafeExtension(p))
                                                      || ScriptExts.Contains(SafeExtension(p)))
                            ?? paths.FirstOrDefault() ?? "";

            return new ShortcutInfo(target, Readable(wide) + " " + Readable(narrow), true);
        }
        catch
        {
            return new ShortcutInfo("", "", false);
        }
    }

    public static bool IsGeneratedShortcut(string lnkPath)
    {
        foreach (var directory in GeneratedShortcutDirs)
            if (lnkPath.Contains(directory, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    public static string? DangerousReason(string lnkPath)
    {
        if (IsGeneratedShortcut(lnkPath)) return null;

        var info = Read(lnkPath);
        if (!info.Readable) return null;

        string blob = (info.Target + " " + info.Arguments).ToLowerInvariant();
        string fileName = SafeFileName(info.Target);
        string ext = SafeExtension(info.Target);

        foreach (var marker in CommandLineMarkers)
            if (blob.Contains(marker, StringComparison.Ordinal))
                return Interpreters.Contains(fileName) || ScriptExts.Contains(ext)
                    ? $"skrót uruchamia {fileName} z podejrzanymi argumentami ({marker.Trim()})"
                    : $"skrót zawiera podejrzane argumenty ({marker.Trim()})";

        if (info.Target.StartsWith(@"\\", StringComparison.Ordinal))
            return $"skrót wskazuje zasób sieciowy ({info.Target})";

        foreach (var directory in VolatileDirs)
            if (info.Target.Contains(directory, StringComparison.OrdinalIgnoreCase)
                && (ExecExts.Contains(ext) || ScriptExts.Contains(ext)))
                return $"skrót uruchamia plik z katalogu tymczasowego ({info.Target})";

        return null;
    }

    private static string Readable(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var ch in text)
            sb.Append(char.IsControl(ch) ? ' ' : ch);
        return sb.ToString();
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path); }
        catch { return ""; }
    }

    private static string SafeExtension(string path)
    {
        try { return Path.GetExtension(path); }
        catch { return ""; }
    }

    private static bool StartsWithMagic(byte[] bytes)
    {
        if (bytes.Length < Magic.Length) return false;
        for (int i = 0; i < Magic.Length; i++)
            if (bytes[i] != Magic[i]) return false;
        return true;
    }

    private static void CollectPaths(List<string> sink, string text)
    {
        int cursor = 0;
        while (cursor < text.Length)
        {
            int drive = text.IndexOf(":\\", cursor, StringComparison.Ordinal);
            int unc = text.IndexOf(@"\\", cursor, StringComparison.Ordinal);
            int start;
            if (drive >= 1 && (unc < 0 || drive - 1 <= unc)) start = drive - 1;
            else if (unc >= 0) start = unc;
            else return;

            int end = start;
            while (end < text.Length && !char.IsControl(text[end]) && text[end] != '"')
                end++;

            var candidate = text[start..end].Trim();
            if (candidate.Length is >= 4 and <= 1024 && !sink.Contains(candidate))
                sink.Add(candidate);

            cursor = Math.Max(end, start + 1);
        }
    }
}
