using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Malward.NetworkScanner.AdBlock;

namespace Malward.AppGUI.Services;

public sealed class AdBlockListStore
{
    private readonly string _dir;
    private readonly object _lock = new();

    public AdBlockListStore(string appDataDir)
    {
        _dir = Path.Combine(appDataDir, "data", "adblock");
    }

    public string FilePath => Path.Combine(_dir, "subscriptions.json");
    public string DatabaseDir => Path.Combine(_dir, "db");

    public JsonObject Read()
    {
        lock (_lock)
        {
            try
            {
                if (File.Exists(FilePath) && JsonNode.Parse(File.ReadAllText(FilePath)) is JsonObject o)
                    return o;
            }
            catch { }
            return new JsonObject
            {
                ["lists"] = DefaultLists(),
                ["user_rules"] = new JsonArray(),
                ["last_update"] = 0,
                ["format"] = 0,
            };
        }
    }

    public void Write(JsonObject obj)
    {
        lock (_lock)
        {
            Directory.CreateDirectory(_dir);
            var tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, obj.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, FilePath, true);
        }
    }

    public static JsonArray DefaultLists()
    {
        var arr = new JsonArray();
        foreach (var e in AdListCatalog.All)
            if (e.DefaultOn)
                arr.Add(new JsonObject
                {
                    ["name"] = e.Name,
                    ["url"] = e.Url,
                    ["enabled"] = true,
                    ["dns_only"] = e.DnsOnly,
                    ["custom"] = false,
                });
        return arr;
    }

    public JsonArray Catalog()
    {
        var arr = new JsonArray();
        foreach (var e in AdListCatalog.All)
            arr.Add(new JsonObject
            {
                ["category"] = e.Category,
                ["name"] = e.Name,
                ["url"] = e.Url,
                ["default_on"] = e.DefaultOn,
                ["dns_only"] = e.DnsOnly,
            });
        return arr;
    }

    public JsonObject Stats()
    {
        var stats = new JsonObject
        {
            ["block"] = 0, ["blockdns"] = 0, ["allow"] = 0, ["net"] = 0, ["bytes"] = 0,
        };
        try
        {
            var meta = Path.Combine(DatabaseDir, "meta.txt");
            if (File.Exists(meta))
                foreach (var line in File.ReadAllLines(meta))
                {
                    var kv = line.Split('=', 2);
                    if (kv.Length == 2 && long.TryParse(kv[1], out var v)) stats[kv[0]] = v;
                }

            long bytes = 0;
            if (Directory.Exists(DatabaseDir))
                foreach (var f in Directory.GetFiles(DatabaseDir)) bytes += new FileInfo(f).Length;
            stats["bytes"] = bytes;
        }
        catch { }
        return stats;
    }

    public string CacheDir => Path.Combine(_dir, "lists");

    private static string CacheName(string url) =>
        Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(
            System.Text.Encoding.UTF8.GetBytes(url)))[..16].ToLowerInvariant() + ".txt";

    public JsonArray Installed()
    {
        var arr = new JsonArray();
        var state = Read();
        if (state["lists"] is not JsonArray lists) return arr;

        foreach (var node in lists)
        {
            if (node is not JsonObject l) continue;
            var url = l["url"]?.GetValue<string>() ?? "";
            if (url.Length == 0) continue;

            long bytes = 0, updated = 0;
            try
            {
                var file = url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? Path.Combine(CacheDir, CacheName(url))
                    : url;
                if (File.Exists(file))
                {
                    var fi = new FileInfo(file);
                    bytes = fi.Length;
                    updated = new DateTimeOffset(fi.LastWriteTimeUtc).ToUnixTimeSeconds();
                }
            }
            catch { }

            arr.Add(new JsonObject
            {
                ["name"] = l["name"]?.GetValue<string>() ?? url,
                ["url"] = url,
                ["enabled"] = l["enabled"]?.GetValue<bool>() ?? true,
                ["dns_only"] = l["dns_only"]?.GetValue<bool>() ?? false,
                ["bytes"] = bytes,
                ["updated"] = updated,
            });
        }
        return arr;
    }

    public List<string> Categories()
    {
        var seen = new List<string>();
        foreach (var e in AdListCatalog.All)
            if (!seen.Contains(e.Category)) seen.Add(e.Category);
        return seen;
    }
}
