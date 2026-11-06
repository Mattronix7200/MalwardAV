using System;
using System.Globalization;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public static class UiLanguage
{
    public const string Polish = "pl";
    public const string English = "en";

    public static string FromCulture(string? cultureName)
    {
        var name = (cultureName ?? "").Trim();
        if (name.Length == 0) return English;

        int cut = name.IndexOfAny(new[] { '-', '_' });
        var two = (cut > 0 ? name[..cut] : name).ToLowerInvariant();
        return two == Polish ? Polish : English;
    }

    public static string FromSystem()
    {
        try
        {
            var ui = CultureInfo.CurrentUICulture;
            if (string.IsNullOrEmpty(ui?.Name)) ui = CultureInfo.InstalledUICulture;
            return FromCulture(ui?.Name);
        }
        catch { return English; }
    }

    public static string SeedOnFirstRun(string appDataDir)
    {
        try
        {
            var store = new GuiSettingsStore(appDataDir);
            if (store.Exists) return store.Read().Lang;

            var lang = FromSystem();
            store.Write(store.Read() with { Lang = lang });
            return lang;
        }
        catch { return Polish; }
    }
}
