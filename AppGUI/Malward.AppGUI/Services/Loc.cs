using System;
using System.IO;

namespace Malward.AppGUI.Services;

public static class Loc
{
    public static bool English => Malward.Engine.Util.Loc.English;

    public static void Init(byte[]? enJson, string? lang)
    {
        var english = string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase);
        Malward.Engine.Util.Loc.Init(enJson, english);

        if (enJson is not { Length: > 0 }) return;
        try
        {
            var cel = Malward.Engine.Util.Loc.DictionaryPath;
            Directory.CreateDirectory(Path.GetDirectoryName(cel)!);

            var tmp = cel + ".tmp";
            File.WriteAllBytes(tmp, enJson);
            File.Move(tmp, cel, overwrite: true);
        }
        catch (Exception ex) { CrashLog.Write("i18n", ex, "exporting the shared dictionary"); }
    }

    public static void Refresh(string appDataDir) => Malward.Engine.Util.Loc.Refresh();

    public static string ReadLang(string appDataDir)
    {
        try
        {
            var p = Path.Combine(appDataDir, "data", "gui-settings.json");
            if (!File.Exists(p)) return "pl";
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(p));
            var lang = doc.RootElement.TryGetProperty("lang", out var l) ? l.GetString() : null;
            return string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase) ? "en" : "pl";
        }
        catch { return "pl"; }
    }

    public static string T(string pl) => Malward.Engine.Util.Loc.T(pl);

    public static string F(string plPattern, params object?[] args)
        => Malward.Engine.Util.Loc.F(plPattern, args);
}
