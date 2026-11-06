using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.AppGUI.Services;

public sealed record ScanStatsData(
    [property: JsonPropertyName("files_scanned")]  long FilesScanned,
    [property: JsonPropertyName("cloud_analyzed")] long CloudAnalyzed,
    [property: JsonPropertyName("total_detections")] long TotalDetections,
    [property: JsonPropertyName("url_blocked")] long UrlBlocked = 0);

public sealed class ScanStatsStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private static readonly JsonSerializerOptions _opts = new()
    {
        WriteIndented = true,
    };

    public ScanStatsStore(string path) { _path = path; }

    public ScanStatsData Read()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_path)) return new ScanStatsData(0, 0, 0);
                var json = File.ReadAllText(_path);
                return JsonSerializer.Deserialize<ScanStatsData>(json) ?? new ScanStatsData(0, 0, 0);
            }
            catch { return new ScanStatsData(0, 0, 0); }
        }
    }

    public void Write(ScanStatsData d)
    {
        lock (_lock)
        {
            try
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(_path, JsonSerializer.Serialize(d, _opts));
            }
            catch {  }
        }
    }

    public void AddFromScan(long filesScanned, long cloudUsed)
    {
        lock (_lock)
        {
            var cur = Read();
            var next = cur with
            {
                FilesScanned = cur.FilesScanned + Math.Max(0, filesScanned),
                CloudAnalyzed = cur.CloudAnalyzed + Math.Max(0, cloudUsed),
            };
            Write(next);
        }
    }

    public void ResetDetections()
    {
        lock (_lock)
        {
            var cur = Read();
            Write(cur with { TotalDetections = 0 });
        }
    }

    public void AddUrlBlocked(long n)
    {
        if (n <= 0) return;
        lock (_lock)
        {
            var cur = Read();
            Write(cur with { UrlBlocked = cur.UrlBlocked + n });
        }
    }

    public void IncDetections(long n = 1)
    {
        lock (_lock)
        {
            var cur = Read();
            Write(cur with { TotalDetections = cur.TotalDetections + n });
        }
    }
}
