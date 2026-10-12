using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.AppGUI.Services;

public sealed class NetworkSettingsStore
{
    private readonly string _path;
    private readonly object _lock = new();

    public NetworkSettingsStore(string appDataDir)
    {
        _path = Path.Combine(appDataDir, "data", "network-settings.json");
    }

    public string FilePath => _path;
    public bool Exists => File.Exists(_path);

    public JsonObject Read()
    {
        lock (_lock)
        {
            try
            {
                if (File.Exists(_path))
                {
                    var raw = File.ReadAllText(_path);
                    if (JsonNode.Parse(raw) is JsonObject obj) return obj;
                }
            }
            catch { }
            return new JsonObject();
        }
    }

    public void Write(JsonObject obj)
    {
        lock (_lock)
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            using var fs = File.Create(_path);
            using var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true });
            obj.WriteTo(w);
        }
    }

    public JsonObject Merge(JsonObject patch)
    {
        lock (_lock)
        {
            var cur = Read();
            foreach (var kv in patch)
                cur[kv.Key] = kv.Value?.DeepClone();
            Write(cur);
            return cur;
        }
    }
}
