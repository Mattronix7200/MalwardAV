using System.Text.RegularExpressions;

namespace Malward.ResidentShield;

public static class LolBin
{
    private static HashSet<string>? _interpreters;

    private static readonly string[] BuiltInHosts =
        { "wscript", "cscript", "mshta", "powershell", "pwsh", "cmd", "rundll32", "regsvr32", "wmic" };

    private static HashSet<string> Interpreters
    {
        get
        {
            if (_interpreters != null) return _interpreters;
            var set = new HashSet<string>(BuiltInHosts, StringComparer.OrdinalIgnoreCase);
            try { foreach (var n in Malward.Engine.Data.SignatureStore.List("script_hosts")) set.Add(n); }
            catch {  }
            return _interpreters = set;
        }
    }

    private static readonly HashSet<string> ScriptExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1",
        ".bat", ".cmd", ".py", ".pyw", ".jar", ".scr", ".com", ".dll", ".exe",
        ".sct", ".xsl", ".lnk",
    };

    public static bool IsInterpreter(string processName)
        => Interpreters.Contains(Strip(processName));

    public static IEnumerable<string> ExtractTargets(string processName, string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) yield break;
        if (!IsInterpreter(processName)) yield break;

        foreach (var tok in Tokenize(commandLine))
        {
            string arg = tok.Trim().Trim('"');
            if (arg.Length < 4) continue;

            int comma = arg.IndexOf(',');
            if (comma > 0 && arg.EndsWith(".dll,", StringComparison.OrdinalIgnoreCase) == false
                && Strip(processName) == "rundll32")
                arg = arg[..comma];

            string ext;
            try { ext = Path.GetExtension(arg); }
            catch { continue; }

            if (string.IsNullOrEmpty(ext) || !ScriptExts.Contains(ext)) continue;

            string full = ResolvePath(arg);
            if (!string.IsNullOrEmpty(full) && File.Exists(full))
                yield return full;
        }
    }

    private static string ResolvePath(string arg)
    {
        try
        {
            if (Path.IsPathRooted(arg)) return arg;

            string expanded = Environment.ExpandEnvironmentVariables(arg);
            return Path.IsPathRooted(expanded) ? expanded : "";
        }
        catch { return ""; }
    }

    private static IEnumerable<string> Tokenize(string cmd)
    {
        var matches = Regex.Matches(cmd, "\"[^\"]*\"|\\S+");
        foreach (Match m in matches)
            yield return m.Value;
    }

    private static string Strip(string name)
        => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
}
