using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.AppGUI.Services;

public sealed record HistoryDetection(
    [property: JsonPropertyName("path")]     string Path,
    [property: JsonPropertyName("det")]      string Detection,
    [property: JsonPropertyName("src")]      string Source);

public sealed record ScanHistoryEntry(
    [property: JsonPropertyName("ts")]        long UnixTimeSec,
    [property: JsonPropertyName("target")]    string Target,
    [property: JsonPropertyName("mode")]      string Mode,
    [property: JsonPropertyName("files")]     long FilesTotal,
    [property: JsonPropertyName("threats")]   long Threats,
    [property: JsonPropertyName("blocked")]   long Blocked,
    [property: JsonPropertyName("system")]    long System,
    [property: JsonPropertyName("encrypted")] long Encrypted,
    [property: JsonPropertyName("time")]      string Time,
    [property: JsonPropertyName("bytes")]     string Bytes,
    [property: JsonPropertyName("detections")] List<HistoryDetection> Detections);

public sealed class ScanHistoryStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private static readonly JsonSerializerOptions _opts = new() { WriteIndented = true };
    private const int MAX_ENTRIES = 100;

    public ScanHistoryStore(string engineDir)
    {
        _path = Path.Combine(engineDir, "data", "scan-history.json");
    }

    public List<ScanHistoryEntry> Read()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_path)) return new();
                return JsonSerializer.Deserialize<List<ScanHistoryEntry>>(File.ReadAllText(_path)) ?? new();
            }
            catch { return new(); }
        }
    }

    public void Append(ScanHistoryEntry entry)
    {
        lock (_lock)
        {
            try
            {
                var list = Read();
                list.Add(entry);
                if (list.Count > MAX_ENTRIES)
                    list = list.Skip(list.Count - MAX_ENTRIES).ToList();
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(_path, JsonSerializer.Serialize(list, _opts));
            }
            catch {  }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            try { if (File.Exists(_path)) File.Delete(_path); } catch { }
        }
    }
}
