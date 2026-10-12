using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.AppGUI.Services;

public sealed class SettingsBridge
{
    private readonly string _settingsPath;

    public SettingsBridge(string engineDir)
    {
        _settingsPath = System.IO.Path.Combine(engineDir, "data", "settings.json");
    }

    public string SettingsFilePath => _settingsPath;

    public JsonObject Read()
    {
        if (!File.Exists(_settingsPath))
        {
            return Defaults();
        }
        try
        {
            var json = File.ReadAllText(_settingsPath);
            var node = JsonNode.Parse(json) as JsonObject;
            if (node == null) return Defaults();

            var def = Defaults();
            foreach (var (k, v) in def)
                if (!node.ContainsKey(k)) node[k] = v!.DeepClone();
            return node;
        }
        catch
        {
            return Defaults();
        }
    }

    public void Write(JsonObject data)
    {
        var dir = Path.GetDirectoryName(_settingsPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        using var fs = File.Create(_settingsPath);
        using var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true });
        data.WriteTo(w);
    }

    private static JsonObject? _profileDefaults;

    public static void UseProfileDefaults(JsonObject? scannerSection)
    {
        _profileDefaults = scannerSection is null ? null : (JsonObject)scannerSection.DeepClone();
    }

    public static JsonObject Defaults()
    {
        if (_profileDefaults is not null) return (JsonObject)_profileDefaults.DeepClone();
        return new JsonObject
        {
            ["max_file_size_mb"] = 100,
            ["max_scan_time_per_file_sec"] = 30,
            ["max_upload_to_cloud_sec"] = 60,
            ["ext_filter_mode"] = "all",
            ["ext_list_common"] = new JsonArray("EXE","DLL","DRV","SYS","VBS","VBE","JS","BAT","CMD","PS1","SH",
                "COM","SCR","HTA","MSI","JAR","WSF","WSH","DOC","DOCM","XLS","XLSM","PPT","PPTM","PDF","ZIP",
                "RAR","7Z","CAB","ISO","LNK","CHM","HTML","HTM"),
            ["ext_blacklist"] = new JsonArray(),
            ["scan_archives"] = true,
            ["heuristic_enabled"] = false,
            ["heuristic_realtime_enabled"] = true,

            ["script_analysis_enabled"] = true,
            ["background_scan_enabled"] = true,
            ["cloud_scan_enabled"] = true,
            ["cloud_verify_detections"] = true,
            ["scan_optimization"] = true,
            ["quarantine_size_limit_mb"] = 5120,
            ["trust_whitelist"] = true,
            ["skip_ms_signed"] = false,
            ["repair_mode"] = 1,
            ["archive_repair_mode"] = 1,
            ["memory_scan"] = true,
            ["memory_scan_check_whitelist"] = false,
            ["exceptions"] = new JsonArray(),
            ["gui_theme"] = "light",
        };
    }

    public void Sanitize()
    {
        if (!File.Exists(_settingsPath)) return;
        try
        {
            var json = File.ReadAllText(_settingsPath);
            if (JsonNode.Parse(json) is not JsonObject node) return;
            string[] deadKeys =
            {
                "heuristic_model", "code_script_analysis_enabled", "openrouter_api_key",
                "scan_level", "server_ip", "server_port",
                "server_cert_pin_sha256", "client_token",
                "skip_trusted_files",

                "archive_passwords", "archive_prompt_password",

                "pup_detection_enabled",

                "emulation_heuristic_enabled", "emulation_realtime_enabled", "emulation_max_threads",
                "mla_script_scan_enabled", "heur_sensitivity",
                "idle_scan_enabled", "idle_scan_minutes",
            };
            bool changed = false;
            foreach (var k in deadKeys)
                if (node.ContainsKey(k)) { node.Remove(k); changed = true; }
            if (changed) Write(node);
        }
        catch {  }
    }
}
