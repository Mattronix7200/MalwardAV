using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Malward.AppGUI.Services;

public sealed class ResidentIpc
{
    private readonly string _eventsPath;
    private readonly string _decisionsDir;
    private readonly string _activityPath;
    private readonly object _lock = new();

    public ResidentIpc(string appDataDir)
    {
        var data = Path.Combine(appDataDir, "data");
        _eventsPath   = Path.Combine(data, "shield-events.jsonl");
        _decisionsDir = Path.Combine(data, "decisions");
        _activityPath = Path.Combine(data, "shield-activity.json");
    }

    public sealed record ShieldEvent(string Id, string Mode, string File, string Name,
        string Detection, string? Action, long Ts, string Process = "", string Source = "");

    public sealed record RemovableEvent(string Type, string Root, string? Detection, int Threats, long Ts,
        int Pct = 0, int Done = 0, int Total = 0, string? File = null);

    public sealed record RestoredEvent(string Id, string Title, string Body,
        int Restored, int FromBkf, int FromVss, int Pid, string Detection, long Ts,
        System.Collections.Generic.List<string>? Paths = null,
        string? FilePath = null,

        System.Collections.Generic.List<(string Stored, string Original)>? Quarantined = null,
        string Action = "quarantine");

    public (List<ShieldEvent> Threats, List<RemovableEvent> Removable, List<RestoredEvent> Restored) DrainAll()
    {
        var threats = new List<ShieldEvent>();
        var removable = new List<RemovableEvent>();
        var restored = new List<RestoredEvent>();
        lock (_lock)
        {
            if (!File.Exists(_eventsPath)) return (threats, removable, restored);
            string[] lines;
            try { lines = File.ReadAllLines(_eventsPath); }
            catch { return (threats, removable, restored); }

            try { File.WriteAllText(_eventsPath, ""); } catch { }

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    using var d = JsonDocument.Parse(line);
                    var r = d.RootElement;
                    string type = Get(r, "type");
                    string mode = Get(r, "mode");
                    long ts = r.TryGetProperty("ts", out var t) && t.TryGetInt64(out var tv) ? tv : 0;
                    if (type.StartsWith("removable.", StringComparison.OrdinalIgnoreCase))
                    {
                        int threatsN = r.TryGetProperty("threats", out var th) && th.TryGetInt32(out var tn) ? tn : 0;
                        int pct   = r.TryGetProperty("pct",   out var pv) && pv.TryGetInt32(out var pi) ? pi : 0;
                        int done  = r.TryGetProperty("done",  out var dN) && dN.TryGetInt32(out var di) ? di : 0;
                        int total = r.TryGetProperty("total", out var tN) && tN.TryGetInt32(out var ti) ? ti : 0;
                        string? file = r.TryGetProperty("file", out var fv) && fv.ValueKind == JsonValueKind.String ? fv.GetString() : null;
                        removable.Add(new RemovableEvent(
                            type, Get(r, "root"),
                            r.TryGetProperty("detection", out var dv) && dv.ValueKind == JsonValueKind.String ? dv.GetString() : null,
                            threatsN, ts, pct, done, total, file));
                    }
                    else if (mode.Equals("restored", StringComparison.OrdinalIgnoreCase))
                    {
                        int rest = r.TryGetProperty("restored", out var rv) && rv.TryGetInt32(out var ri) ? ri : 0;
                        int bkf  = r.TryGetProperty("from_bkf", out var bv) && bv.TryGetInt32(out var bi) ? bi : 0;
                        int vss  = r.TryGetProperty("from_vss", out var vv) && vv.TryGetInt32(out var vi) ? vi : 0;
                        int pid  = r.TryGetProperty("pid", out var pv2) && pv2.TryGetInt32(out var pi2) ? pi2 : 0;
                        var paths = new List<string>();
                        if (r.TryGetProperty("paths", out var pa) && pa.ValueKind == JsonValueKind.Array)
                            foreach (var pe in pa.EnumerateArray())
                                if (pe.ValueKind == JsonValueKind.String) paths.Add(pe.GetString() ?? "");
                        var quarantined = new List<(string Stored, string Original)>();
                        if (r.TryGetProperty("quarantined", out var qa) && qa.ValueKind == JsonValueKind.Array)
                            foreach (var qe in qa.EnumerateArray())
                            {
                                string st = Get(qe, "stored"), orig = Get(qe, "original");
                                if (st.Length > 0) quarantined.Add((st, orig));
                            }
                        string action = Get(r, "action");
                        restored.Add(new RestoredEvent(
                            Get(r, "id"), Get(r, "title"), Get(r, "body"),
                            rest, bkf, vss, pid, Get(r, "detection"), ts, paths,
                            Get(r, "file_path"), quarantined,
                            action.Length > 0 ? action : "quarantine"));
                    }
                    else
                    {
                        threats.Add(new ShieldEvent(
                            Get(r, "id"), mode, Get(r, "file"), Get(r, "name"),
                            Get(r, "detection"),
                            r.TryGetProperty("action", out var a) ? a.GetString() : null,
                            ts, Get(r, "process"), Get(r, "source")));
                    }
                }
                catch { }
            }
        }
        return (threats, removable, restored);
    }

    public List<ShieldEvent> DrainEvents() => DrainAll().Threats;

    public void WriteDecision(string id, string action)
    {
        try
        {
            Directory.CreateDirectory(_decisionsDir);
            var path = Path.Combine(_decisionsDir, id + ".json");
            File.WriteAllText(path, JsonSerializer.Serialize(new { action }));
        }
        catch { }
    }

    public string? ReadActivityJson()
    {
        try { return File.Exists(_activityPath) ? File.ReadAllText(_activityPath) : null; }
        catch { return null; }
    }

    private static string Get(JsonElement e, string p)
        => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
}
