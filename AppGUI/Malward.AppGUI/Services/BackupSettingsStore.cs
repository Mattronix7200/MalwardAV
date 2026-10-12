using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.AppGUI.Services;

public sealed class BackupSettingsStore
{
    private readonly string _path;
    private readonly object _lock = new();

    public BackupSettingsStore()
    {
        _path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "backup", "settings.json");
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

    private void Write(JsonObject obj)
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = _path + ".tmp";
        using (var fs = File.Create(tmp))
        using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true }))
        {
            obj.WriteTo(w);
        }
        if (File.Exists(_path))
            File.Replace(tmp, _path, destinationBackupFileName: null, ignoreMetadataErrors: true);
        else
            File.Move(tmp, _path);
    }

    public bool RestartService()
    {
        try
        {
            RunSc("stop MalwardBackupEngine");
            System.Threading.Thread.Sleep(800);
            RunSc("start MalwardBackupEngine");
            return true;
        }
        catch { return false; }
    }

    private static void RunSc(string args)
    {
        var psi = new ProcessStartInfo("sc.exe", args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi);
        p?.WaitForExit(5000);
    }
}
