using System.Text.Json;

namespace Malward.ResidentShield;

public static class QuarantineStore
{
    private static readonly string IndexPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "quarantine", "index.jsonl");

    private static readonly object _lock = new();

    public sealed class Entry
    {
        public string Stored    { get; set; } = "";
        public string Original  { get; set; } = "";
        public string Detection { get; set; } = "";
        public DateTime Time    { get; set; }
    }

    public static void Record(string storedFullPath, string originalPath, string detection)
    {
        try
        {
            var entry = new Entry
            {
                Stored    = Path.GetFileName(storedFullPath),
                Original  = originalPath,
                Detection = detection,
                Time      = DateTime.UtcNow,
            };
            string line = JsonSerializer.Serialize(entry);
            lock (_lock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(IndexPath)!);
                File.AppendAllText(IndexPath, line + Environment.NewLine);
            }
        }
        catch {  }
    }
}
