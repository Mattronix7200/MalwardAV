using System;

namespace Malward.AppGUI.Services;

public interface IShell
{
    bool IsVisible { get; }
    bool IsMinimized { get; }

    void Reveal();
    void HideToTray();

    void SplashFadeOut();
    void SplashCollapse();
    void SetBackgroundColor(byte r, byte g, byte b);

    void SetTaskbarProgress(string state, double value);

    void Minimize();
    void StartDrag();

    void Shutdown();

    bool Confirm(string text, string caption);
    void Alert(string text, string caption);
}

public sealed class HeadlessShell : IShell
{
    private readonly Action _openBrowser;
    private readonly Action _shutdown;

    public HeadlessShell(Action openBrowser, Action shutdown)
    {
        _openBrowser = openBrowser;
        _shutdown = shutdown;
    }

    public bool IsVisible => false;
    public bool IsMinimized => true;

    public void Reveal() { try { _openBrowser(); } catch { } }
    public void HideToTray() { }

    public void SplashFadeOut() { }
    public void SplashCollapse() { }
    public void SetBackgroundColor(byte r, byte g, byte b) { }

    public void SetTaskbarProgress(string state, double value) { }

    public void Minimize() { }
    public void StartDrag() { }

    public void Shutdown() { try { _shutdown(); } catch { } }

    public bool Confirm(string text, string caption) => false;

    public void Alert(string text, string caption)
        => CrashLog.Write("headless-alert", null, $"{caption}: {text}");
}
