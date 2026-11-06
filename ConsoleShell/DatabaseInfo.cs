using System.Text.Json.Nodes;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public static class DatabaseInfo
{
    public sealed record Entry(string Name, string FileName, string VersionKey);

    public static readonly Entry[] Listed =
    {
        new("Threat signatures",      "vps.vdeb",          "vps"),
        new("Detection signatures",   "rf-whitelist.vdeb", "whitelist"),
        new("Heuristic rules",        "heur.vdeb",         "heur"),
        new("Malicious certificates", "vps-ex02.vdeb",     "cert"),
        new("Vulnerable drivers",     "vps-ex04.vdeb",     "byod"),
    };

    /// <summary>Without the signature database a scan reports nothing at all.</summary>
    public static readonly Entry[] Required = { Listed[0] };

    private static JsonObject? _versions;
    private static bool _read;

    public static string Version(string key)
    {
        if (!_read)
        {
            _read = true;
            try
            {
                var p = Path.Combine(Paths.DataDir, "db-versions-server.json");
                if (File.Exists(p)) _versions = JsonNode.Parse(File.ReadAllText(p)) as JsonObject;
            }
            catch { _versions = null; }
        }

        try
        {
            if (_versions?[key]?.GetValue<string>() is string v && v.Trim().Length > 0) return v.Trim();
        }
        catch { }
        return "";
    }

    public static string PathOf(Entry e) => Path.Combine(Paths.DataDir, e.FileName);

    public static bool Installed(Entry e)
    {
        try { return File.Exists(PathOf(e)); }
        catch { return false; }
    }

    public static string BuildDate(Entry e)
    {
        try { return File.GetLastWriteTime(PathOf(e)).ToString("yyyy-MM-dd"); }
        catch { return ""; }
    }

    public static string SignatureLine()
    {
        var e = Listed[0];
        if (!Installed(e)) return "not installed";
        var v = Version(e.VersionKey);
        var d = BuildDate(e);
        if (v.Length == 0) return d.Length == 0 ? "unknown" : $"unknown ({d})";
        return d.Length == 0 ? v : $"{v} ({d})";
    }
}
