using System.Text.Json;

namespace Malward.ResidentShield;

public sealed class NotifyBus
{
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data");
    private static readonly string EventsPath   = Path.Combine(DataDir, "shield-events.jsonl");
    private static readonly string DecisionsDir = Path.Combine(DataDir, "decisions");

    private readonly object _lock = new();

    public enum Decision { Quarantine, Delete }

    public static void ClearStale()
    {
        try { if (File.Exists(EventsPath)) File.Delete(EventsPath); } catch { }
        try
        {
            if (Directory.Exists(DecisionsDir))
                foreach (var f in Directory.GetFiles(DecisionsDir, "*.json"))
                    try { File.Delete(f); } catch { }
        }
        catch { }
    }

    public void NotifyAuto(string file, string detection, string actionDone, string process = "",
                           string source = "")
    {
        Append(new
        {
            id = Guid.NewGuid().ToString("N"),
            mode = "auto",
            file,
            name = Path.GetFileName(file),
            detection,
            source,
            process,
            action = actionDone,
            ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }

    public void NotifyRestored(string title, string body, int restoredCount,
                                int fromBkf, int fromVss, int pid, string threat,
                                IEnumerable<string>? paths = null, string? filePath = null,
                                IEnumerable<(string Stored, string Original)>? quarantined = null,
                                bool deleted = false)
    {
        Append(new
        {
            quarantined = (quarantined ?? Array.Empty<(string, string)>()).Take(64)
                .Select(q => new { stored = q.Stored, original = q.Original }).ToArray(),
            action = deleted ? "delete" : "quarantine",

            file_path = filePath ?? "",
            id = Guid.NewGuid().ToString("N"),
            mode = "restored",
            title,
            body,
            restored = restoredCount,
            from_bkf = fromBkf,
            from_vss = fromVss,
            pid,
            detection = threat,

            paths = (paths ?? Array.Empty<string>()).Take(40).ToArray(),
            ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });
    }

    public Decision AskDecision(string file, string detection, CancellationToken ct,
        int timeoutSec = 120, string process = "", string source = "")
    {
        string id = Guid.NewGuid().ToString("N");
        Append(new
        {
            id,
            mode = "ask",
            file,
            name = Path.GetFileName(file),
            detection,
            source,
            process,
            ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        });

        var decisionPath = Path.Combine(DecisionsDir, id + ".json");
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSec);

        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            try
            {
                if (File.Exists(decisionPath))
                {
                    var raw = File.ReadAllText(decisionPath);
                    try { File.Delete(decisionPath); } catch { }
                    using var doc = JsonDocument.Parse(raw);
                    var act = doc.RootElement.TryGetProperty("action", out var a)
                        ? a.GetString() : null;
                    return string.Equals(act, "delete", StringComparison.OrdinalIgnoreCase)
                        ? Decision.Delete : Decision.Quarantine;
                }
            }
            catch { }
            Thread.Sleep(400);
        }

        return Decision.Quarantine;
    }

    private void Append(object ev)
    {
        try
        {
            lock (_lock)
            {
                Directory.CreateDirectory(DataDir);
                File.AppendAllText(EventsPath, JsonSerializer.Serialize(ev) + Environment.NewLine);
            }
        }
        catch {  }
    }
}
