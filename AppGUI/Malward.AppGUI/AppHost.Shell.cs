using System;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private IShell? _shell;
    private IFilePicker? _picker;
    private IWebViewHost? _host;

    internal void AttachWindow(ShellWindow window)
    {
        _shell = window;
        _picker = window;
        _host = window;
    }

    internal Microsoft.Web.WebView2.Wpf.WebView2? WebView
        => _host?.WebViewControl as Microsoft.Web.WebView2.Wpf.WebView2;

    private void CreateWebViewControl() => _host?.CreateWebViewControl();

    private IShell Shell => _shell ??= new HeadlessShell(() => OpenInBrowser(), ShutdownHeadless);

    private IFilePicker Picker => _picker ??=
        new HeadlessFilePicker(msg => PostToJs("toast", new { level = "warn", msg }));

    internal bool PrefersDarkTheme()
    {
        try { return ResolveDark(new GuiSettingsStore(_appDataDir).Read().Theme); }
        catch { return true; }
    }

    private void ShutdownHeadless()
    {
        try { StopWebUi(); } catch { }
        try { _tray?.Dispose(); } catch { }
        (Ui.Current as PumpUiThread)?.Shutdown();
    }

    internal IntPtr WindowHandle => _host?.Hwnd ?? IntPtr.Zero;

    internal async System.Threading.Tasks.Task OnShellLoadedAsync() => await ShellLoadedAsync();

    internal void OnShellClosing(System.ComponentModel.CancelEventArgs e) => ShellClosing(e);

    internal void OnShellClosed() => _closed = true;

    internal void OnShellDrop(System.Collections.Generic.List<string> files)
    {
        if (files.Count > 0) PostToJs("tools.analyze.dropped", new { paths = files });
        else CrashLog.Write("drop", null, "drop carried no existing file paths");
    }

    internal void OnShellVisibilityChanged(bool visible)
    {
        if (!visible) { SetWebViewBackground(true); return; }
        SetWebViewBackground(false);
        CloseMiniScanPopup();
        if (_revealed) RecomposeWebView();
    }

    internal void OnShellStateChanged(bool minimized, bool normal)
    {
        if (minimized) { SetWebViewBackground(true); return; }
        SetWebViewBackground(false);
        if (!normal) return;
        CloseMiniScanPopup();
        if (_revealed) RecomposeWebView();
    }
}
