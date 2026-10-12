using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Malward.AppGUI.Services;

public static class ScanScheduleStore
{
    public sealed class Schedule
    {
        [JsonPropertyName("enabled")] public bool Enabled { get; set; } = false;
        [JsonPropertyName("mode")]    public string Mode { get; set; } = "quick";
        [JsonPropertyName("folders")] public List<string> Folders { get; set; } = new();
        [JsonPropertyName("trigger")] public string Trigger { get; set; } = "logon";
        [JsonPropertyName("day")]     public string Day { get; set; } = "MON";
        [JsonPropertyName("time")]    public string Time { get; set; } = "03:00";
    }

    private static string Path(string appDataDir) =>
        System.IO.Path.Combine(appDataDir, "data", "scan-schedule.json");

    public static Schedule Read(string appDataDir)
    {
        var p = Path(appDataDir);
        try
        {
            if (File.Exists(p))
            {
                var raw = File.ReadAllText(p);
                var s = JsonSerializer.Deserialize<Schedule>(raw,
                    new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip });
                if (s != null) return s;
            }
        }
        catch { }
        return new Schedule();
    }

    public static void Write(string appDataDir, Schedule s)
    {
        var p = Path(appDataDir);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(p)!);

        using var fs = File.Create(p);
        using var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true });
        var node = JsonNode.Parse(JsonSerializer.Serialize(s))!;
        node.WriteTo(w);
    }
}
