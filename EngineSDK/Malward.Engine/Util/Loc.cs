using System.Text.Json;

namespace Malward.Engine.Util;

public static class Loc
{
    private static readonly object _gate = new();
    private static Dictionary<string, string>? _dict;
    private static bool _english;
    private static bool _ready;

    public static string DictionaryPath => Path.Combine(Paths.DataDir, "i18n-en.json");

    private static string GuiSettingsPath => Path.Combine(Paths.DataDir, "gui-settings.json");

    public static bool English { get { EnsureReady(); return _english; } }

    public static void Init(byte[]? enJson, bool? english = null)
    {
        lock (_gate)
        {
            if (enJson is { Length: > 0 }) _dict = Parse(enJson);
            _english = english ?? ReadEnglishFlag();
            _ready = true;
        }
    }

    public static void Refresh()
    {
        lock (_gate) { _english = ReadEnglishFlag(); _ready = true; }
    }

    private static void EnsureReady()
    {
        if (_ready) return;
        lock (_gate)
        {
            if (_ready) return;
            _english = ReadEnglishFlag();
            if (_dict == null)
            {
                try
                {
                    if (File.Exists(DictionaryPath)) _dict = Parse(File.ReadAllBytes(DictionaryPath));
                }
                catch {  }
            }
            _ready = true;
        }
    }

    private static Dictionary<string, string>? Parse(byte[] json)
    {
        try
        {
            var d = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (d == null) return null;

            foreach (var k in new List<string>(d.Keys))
                if (k.StartsWith('_')) d.Remove(k);
            return d;
        }
        catch { return null; }
    }

    private static bool ReadEnglishFlag()
    {
        try
        {
            if (!File.Exists(GuiSettingsPath)) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(GuiSettingsPath));
            return doc.RootElement.TryGetProperty("lang", out var l)
                && string.Equals(l.GetString(), "en", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public static string T(string pl)
    {
        if (string.IsNullOrEmpty(pl)) return pl;
        EnsureReady();
        if (!_english || _dict == null) return pl;
        return _dict.TryGetValue(pl, out var en) ? en : pl;
    }

    public static string F(string plPattern, params object?[] args)
    {
        var wzor = T(plPattern);

        var kultura = _english
            ? System.Globalization.CultureInfo.InvariantCulture
            : System.Globalization.CultureInfo.CurrentCulture;
        try { return string.Format(kultura, wzor, args); }
        catch (FormatException) { return wzor; }
    }
}
