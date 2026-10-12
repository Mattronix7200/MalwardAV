using System;

namespace Malward.AppGUI.Services;

public interface IFilePicker
{
    string? OpenFile(string title, string? filter = null, bool mustExist = false);
    string[]? OpenFiles(string title, string? filter = null);
    string? SaveFile(string title, string? filter = null, string? suggestedName = null);
    string? PickFolder(string title);
}

public sealed class HeadlessFilePicker : IFilePicker
{
    private readonly Action<string> _powiedz;

    public HeadlessFilePicker(Action<string> powiedz) => _powiedz = powiedz;

    private T? Odmowa<T>() where T : class
    {
        try { _powiedz("Wybór pliku wymaga okna programu — w trybie przeglądarki jest niedostępny."); }
        catch { }
        return null;
    }

    public string? OpenFile(string title, string? filter = null, bool mustExist = false) => Odmowa<string>();
    public string[]? OpenFiles(string title, string? filter = null) => Odmowa<string[]>();
    public string? SaveFile(string title, string? filter = null, string? suggestedName = null) => Odmowa<string>();
    public string? PickFolder(string title) => Odmowa<string>();
}
