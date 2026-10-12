using System;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.AppGUI.Services;

public sealed class DbVersionStore
{
    private readonly string _cachePath;

    private const string VpsDefault       = "1.200.0.1.62526";
    private const string WhitelistDefault = "1.0.0.5.62526";
    private const string UrlsDefault      = "1.1.0.0.62526";

    public DbVersionStore(string appDataDir)
    {
        _cachePath = Path.Combine(appDataDir, "data", "db-versions-server.json");
    }

    public string VpsVersion(string vpsVdebPath = "")       => Get("vps", VpsDefault, vpsVdebPath);
    public string WhitelistVersion(string wlVdebPath = "")  => Get("whitelist", WhitelistDefault, wlVdebPath);

    public string UrlsVersion(string urlsVdebPath = "")     => Get("urls", UrlsDefault, urlsVdebPath);

    public string ExtraVersion(string key, string dbPath = "") => Get(key, "", dbPath);

    private string Get(string key, string fallback, string dbPath)
    {
        try
        {
            if (!string.IsNullOrEmpty(dbPath) && !File.Exists(dbPath)) return "";
        }
        catch { return ""; }

        try
        {
            if (File.Exists(_cachePath) && JsonNode.Parse(File.ReadAllText(_cachePath)) is JsonObject o
                && o[key]?.GetValue<string>() is string v && !string.IsNullOrWhiteSpace(v))
                return v;
        }
        catch { }
        return fallback;
    }

    public static string CachePathFor(string appDataDir)
        => Path.Combine(appDataDir, "data", "db-versions-server.json");

    public static void WriteServerVersions(string cachePath, string? vps, string? whitelist,
                                           string? urls = null)
    {
        var values = new System.Collections.Generic.Dictionary<string, string?>
        {
            ["vps"] = vps, ["whitelist"] = whitelist, ["urls"] = urls,
        };
        Merge(cachePath, values);
    }

    public static void WriteVersions(string cachePath,
                                     System.Collections.Generic.IDictionary<string, string?> values)
        => Merge(cachePath, values);

    public static string BumpLocal(string cachePath, string key)
    {
        var current = Read(cachePath)?[key]?.GetValue<string>();
        var next = NextVersion(current);
        Merge(cachePath, new System.Collections.Generic.Dictionary<string, string?> { [key] = next });
        return next;
    }

    private static string NextVersion(string? current)
    {
        int a = 0, b = 0, c = 0;
        var parts = (current ?? "").Split('.');
        if (parts.Length == 5
            && int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var pa)
            && int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var pb)
            && int.TryParse(parts[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var pc))
        {
            a = pa; b = pb; c = pc;
        }

        c++;
        if (c > 999) { c = 0; b++; }
        if (b > 999) { b = 0; a++; }

        var now = DateTime.Now;
        int mdd = now.Month * 100 + now.Day;
        int yy = now.Year % 100;
        return string.Format(CultureInfo.InvariantCulture, "1.{0}.{1}.{2}.{3}{4:00}", a, b, c, mdd, yy);
    }

    private static JsonObject? Read(string cachePath)
    {
        try
        {
            if (File.Exists(cachePath) && JsonNode.Parse(File.ReadAllText(cachePath)) is JsonObject o)
                return o;
        }
        catch { }
        return null;
    }

    private static void Merge(string cachePath,
                              System.Collections.Generic.IDictionary<string, string?> values)
    {
        try
        {
            var o = Read(cachePath) ?? new JsonObject();
            foreach (var pair in values)
                if (!string.IsNullOrWhiteSpace(pair.Value))
                    o[pair.Key] = pair.Value;

            var dir = Path.GetDirectoryName(cachePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            using var fs = File.Create(cachePath);
            using var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true });
            o.WriteTo(w);
        }
        catch { }
    }
}
