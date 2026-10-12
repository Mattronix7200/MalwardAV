using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Malward.AppGUI.Services;

public sealed class NetworkIpc
{
    private readonly string _eventsPath;
    private readonly string _activityPath;
    private readonly object _lock = new();

    public NetworkIpc(string appDataDir)
    {
        var data = Path.Combine(appDataDir, "data");
        _eventsPath   = Path.Combine(data, "network-events.jsonl");
        _activityPath = Path.Combine(data, "network-activity.json");
    }

    public sealed record NetEvent(string Type, string Target, string? Detection, string? Source, long Ts, string? Process = null);

    public List<NetEvent> DrainEvents()
    {
        var list = new List<NetEvent>();
        lock (_lock)
        {
            if (!File.Exists(_eventsPath)) return list;
            string[] lines;
            try { lines = File.ReadAllLines(_eventsPath); }
            catch { return list; }

            try { File.WriteAllText(_eventsPath, ""); } catch { }

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    using var d = JsonDocument.Parse(line);
                    var r = d.RootElement;
                    string type = Get(r, "type");
                    string target = type == "download" ? Get(r, "path") : Get(r, "domain");
                    string? det   = type == "download" ? GetOrNull(r, "detection") : GetOrNull(r, "vendor");
                    string? src   = GetOrNull(r, "source");
                    long ts = r.TryGetProperty("ts", out var t) && t.TryGetInt64(out var v) ? v : 0;
                    list.Add(new NetEvent(type, target, det, src, ts, GetOrNull(r, "process")));
                }
                catch { }
            }
        }
        return list;
    }

    public string? ReadActivityJson()
    {
        try { return File.Exists(_activityPath) ? File.ReadAllText(_activityPath) : null; }
        catch { return null; }
    }

    private static string Get(JsonElement e, string p)
        => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    private static string? GetOrNull(JsonElement e, string p)
        => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
