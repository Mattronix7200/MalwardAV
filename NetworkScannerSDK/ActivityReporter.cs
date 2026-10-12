using System.Text;
using System.Text.Json;

namespace Malward.NetworkScanner;

public sealed class ActivityReporter : IDisposable
{
    private static readonly string ActivityFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "network-activity.json");
    private static readonly string EventsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "network-events.jsonl");

    private long _queries;
    private long _blocked;


    private sealed record RecentItem(string Domain, string? Vendor, long Ts, string Source, string? Process);
    private readonly Queue<RecentItem> _recent = new();
    private const int RecentCap = 50;
    private readonly object _lock = new();

    private Thread? _thread;
    private volatile bool _running;

    public void Start()
    {
        try { Directory.CreateDirectory(Path.GetDirectoryName(ActivityFile)!); } catch { }
        _running = true;
        _thread = new Thread(Loop) { IsBackground = true, Name = "Net-Activity", Priority = ThreadPriority.BelowNormal };
        _thread.Start();
    }

    public void Stop()
    {
        _running = false;
        try { _thread?.Join(2000); } catch { }
    }

    public void ReportQuery() => Interlocked.Increment(ref _queries);

    public void ReportBlock(string domain, string? detection, string source, string? process = null)
    {
        Interlocked.Increment(ref _blocked);
        var item = new RecentItem(domain, detection, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), source, process);
        lock (_lock)
        {
            _recent.Enqueue(item);
            while (_recent.Count > RecentCap) _recent.Dequeue();
        }
        try { Directory.CreateDirectory(Path.GetDirectoryName(EventsFile)!); } catch { }
        try
        {
            var json = JsonSerializer.Serialize(new
            {
                ts = item.Ts, type = "block", domain, vendor = detection, source, process,
            });
            File.AppendAllText(EventsFile, json + Environment.NewLine, Encoding.UTF8);
        }
        catch { }
    }

    private void Loop()
    {
        while (_running)
        {
            try { WriteSnapshot(); } catch { }
            try { Thread.Sleep(1000); } catch { }
        }
        try { WriteSnapshot(); } catch { }
    }

    private void WriteSnapshot()
    {
        RecentItem[] recent;
        lock (_lock) recent = _recent.ToArray();
        var snap = new
        {
            queries = Interlocked.Read(ref _queries),
            blocked = Interlocked.Read(ref _blocked),
            ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            recent = recent.Select(r => new {
                domain = r.Domain, vendor = r.Vendor, ts = r.Ts,
                source = r.Source, process = r.Process,
            }).ToArray(),
        };
        var tmp = ActivityFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(snap));

        try { File.Move(tmp, ActivityFile, overwrite: true); }
        catch { try { File.Copy(tmp, ActivityFile, overwrite: true); File.Delete(tmp); } catch { } }
    }

    public void Dispose() { Stop(); }
}
