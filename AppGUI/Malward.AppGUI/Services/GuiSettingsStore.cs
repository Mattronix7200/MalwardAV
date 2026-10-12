using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.AppGUI.Services;

public sealed record GuiSettings(
    [property: JsonPropertyName("theme")] string Theme = "light",  
    [property: JsonPropertyName("lang")]  string Lang  = "pl",     
    [property: JsonPropertyName("auto_update_enabled")] bool AutoUpdateEnabled = true,
    [property: JsonPropertyName("auto_update_minutes")] int AutoUpdateMinutes = 60,
    [property: JsonPropertyName("last_update_check_unix")] long LastUpdateCheckUnix = 0,

    [property: JsonPropertyName("active_profile")] string? ActiveProfile = null,

    [property: JsonPropertyName("autostart")]     bool? Autostart = null,
    [property: JsonPropertyName("context_menu")]  bool? ContextMenu = null,

    [property: JsonPropertyName("gui_mode")]      string GuiMode = "window");

public sealed class GuiSettingsStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private static readonly JsonSerializerOptions _opts = new() { WriteIndented = true };

    public GuiSettingsStore(string engineDir)
    {
        _path = Path.Combine(engineDir, "data", "gui-settings.json");
    }

    public bool Exists => File.Exists(_path);

    public GuiSettings Read()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_path)) return new GuiSettings();
                var json = File.ReadAllText(_path);
                return JsonSerializer.Deserialize<GuiSettings>(json) ?? new GuiSettings();
            }
            catch { return new GuiSettings(); }
        }
    }

    public void Write(GuiSettings s)
    {
        lock (_lock)
        {
            try
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(_path, JsonSerializer.Serialize(s, _opts));
            }
            catch {  }
        }
    }
}
