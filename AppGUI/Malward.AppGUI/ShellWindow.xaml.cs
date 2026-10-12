using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Windows;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class ShellWindow : Window, IShell, IFilePicker, IWebViewHost
{
    private readonly AppHost _core;

    public Microsoft.Web.WebView2.Wpf.WebView2? WebView { get; private set; }

    public IntPtr Hwnd
    {
        get
        {
            try { return new System.Windows.Interop.WindowInteropHelper(this).Handle; }
            catch { return IntPtr.Zero; }
        }
    }

    public ShellWindow(AppHost core)
    {
        _core = core;
        InitializeComponent();
        _core.AttachWindow(this);

        Left = -32000; Top = -32000;

        Loaded += async (_, _) =>
        {
            try { await _core.OnShellLoadedAsync(); }
            catch (Exception ex) { CrashLog.Write("gui-init", ex, null); }
        };
        Closing += (_, e) => _core.OnShellClosing(e);
        Closed += (_, _) => _core.OnShellClosed();
        SourceInitialized += (_, _) => AllowDragDropFromLowerIntegrity();

        DragOver += (_, e) =>
        {
            e.Effects = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop)
                ? System.Windows.DragDropEffects.Copy : System.Windows.DragDropEffects.None;
            e.Handled = true;
        };
        Drop += (_, e) =>
        {
            try { _core.OnShellDrop(AppHost.PathsFromDrop(e.Data)); }
            catch (Exception ex) { CrashLog.Write("drop", ex); }
            e.Handled = true;
        };

        IsVisibleChanged += (_, _) =>
        {
            if (Left < -10000 && IsVisible) CenterOnScreen();
            _core.OnShellVisibilityChanged(IsVisible);
        };
        StateChanged += (_, _) => _core.OnShellStateChanged(WindowState == WindowState.Minimized,
                                                            WindowState == WindowState.Normal);

        ApplyThemeBackground();
    }

    public object? WebViewControl => WebView;

    public void CreateWebViewControl()
    {
        if (WebView != null) return;
        WebView = new Microsoft.Web.WebView2.Wpf.WebView2
        {
            AllowExternalDrop = true,
            DefaultBackgroundColor = System.Drawing.Color.FromArgb(0x0E, 0x11, 0x16),
        };
        RootGrid.Children.Insert(0, WebView);
    }

    private void ApplyThemeBackground()
    {
        try
        {
            bool dark = _core.PrefersDarkTheme();
            var (r, g, b) = dark ? (0x0E, 0x11, 0x16) : (0xF4, 0xF5, 0xF7);
            ((IShell)this).SetBackgroundColor((byte)r, (byte)g, (byte)b);
        }
        catch { }
    }

    private void CenterOnScreen()
    {
        try
        {
            var wa = SystemParameters.WorkArea;
            Left = wa.Left + Math.Max(0, (wa.Width - Width) / 2);
            Top = wa.Top + Math.Max(0, (wa.Height - Height) / 2);
        }
        catch { Left = 100; Top = 100; }
    }

    private void FadeOutSplash()
    {
        if (SplashOverlay == null) return;
        var anim = new System.Windows.Media.Animation.DoubleAnimation(
            1.0, 0.0, new Duration(TimeSpan.FromMilliseconds(220)));
        anim.Completed += (_, _) => ((IShell)this).SplashCollapse();
        SplashOverlay.BeginAnimation(OpacityProperty, anim);
    }

    private const uint WM_DROPFILES = 0x0233;
    private const uint WM_COPYDATA = 0x004A;
    private const uint WM_COPYGLOBALDATA = 0x0049;
    private const uint MSGFLT_ALLOW = 1;

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct CHANGEFILTERSTRUCT
    {
        public uint cbSize;
        public uint ExtStatus;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilterEx(
        IntPtr hwnd, uint message, uint action, ref CHANGEFILTERSTRUCT changeInfo);

    private void AllowDragDropFromLowerIntegrity()
    {
        try
        {
            var hwnd = Hwnd;
            if (hwnd == IntPtr.Zero) return;
            var info = new CHANGEFILTERSTRUCT { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<CHANGEFILTERSTRUCT>() };
            foreach (var msg in new[] { WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA })
                ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, ref info);
        }
        catch (Exception ex) { CrashLog.Write("drop-filter", ex); }
    }

    bool IShell.IsVisible => IsVisible;
    bool IShell.IsMinimized => WindowState == WindowState.Minimized;

    void IShell.Reveal()
    {
        CenterOnScreen();
        ShowInTaskbar = true;
        Visibility = Visibility.Visible;
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Opacity = 1;
        Activate();
    }

    void IShell.HideToTray()
    {
        ShowInTaskbar = false;
        Hide();
    }

    void IShell.SplashFadeOut() => FadeOutSplash();

    void IShell.SplashCollapse()
    {
        if (SplashOverlay == null) return;
        SplashOverlay.Visibility = Visibility.Collapsed;
    }

    void IShell.SetBackgroundColor(byte r, byte g, byte b)
    {
        var wpf = System.Windows.Media.Color.FromRgb(r, g, b);
        var brush = new System.Windows.Media.SolidColorBrush(wpf);
        Background = brush;
        if (SplashOverlay != null) SplashOverlay.Background = brush;
        try { if (WebView != null) WebView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(r, g, b); }
        catch { }
    }

    void IShell.SetTaskbarProgress(string state, double value)
    {
        if (TaskbarInfo == null) return;
        TaskbarInfo.ProgressState = state switch
        {
            "indeterminate" => System.Windows.Shell.TaskbarItemProgressState.Indeterminate,
            "normal"        => System.Windows.Shell.TaskbarItemProgressState.Normal,
            "paused"        => System.Windows.Shell.TaskbarItemProgressState.Paused,
            "error"         => System.Windows.Shell.TaskbarItemProgressState.Error,
            _               => System.Windows.Shell.TaskbarItemProgressState.None,
        };
        TaskbarInfo.ProgressValue = Math.Clamp(value, 0, 1);
    }

    void IShell.Minimize() => WindowChromeHelper.Minimize(this);
    void IShell.StartDrag() => WindowChromeHelper.StartDrag(this);

    void IShell.Shutdown() => System.Windows.Application.Current.Shutdown();

    bool IShell.Confirm(string text, string caption)
        => System.Windows.MessageBox.Show(this, text, caption,
               System.Windows.MessageBoxButton.YesNo,
               System.Windows.MessageBoxImage.Question,
               System.Windows.MessageBoxResult.Yes) == System.Windows.MessageBoxResult.Yes;

    void IShell.Alert(string text, string caption)
        => System.Windows.MessageBox.Show(text, caption,
               System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);

    [MethodImpl(MethodImplOptions.NoInlining)]
    string? IFilePicker.OpenFile(string title, string? filter, bool mustExist)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = title, CheckFileExists = mustExist };
        if (!string.IsNullOrEmpty(filter)) dlg.Filter = filter;
        return dlg.ShowDialog(this) == true ? dlg.FileName : null;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    string[]? IFilePicker.OpenFiles(string title, string? filter)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = title, Multiselect = true };
        if (!string.IsNullOrEmpty(filter)) dlg.Filter = filter;
        return dlg.ShowDialog(this) == true ? dlg.FileNames : null;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    string? IFilePicker.SaveFile(string title, string? filter, string? suggestedName)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog { Title = title };
        if (!string.IsNullOrEmpty(filter)) dlg.Filter = filter;
        if (!string.IsNullOrEmpty(suggestedName)) dlg.FileName = suggestedName;
        return dlg.ShowDialog(this) == true ? dlg.FileName : null;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    string? IFilePicker.PickFolder(string title)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = title };
        return dlg.ShowDialog(this) == true ? dlg.FolderName : null;
    }

    public ITray CreateWindowsFormsTray()
    {
        var iconResUri = new Uri("pack://application:,,,/Resources/icon.ico", UriKind.Absolute);
        var sri = System.Windows.Application.GetResourceStream(iconResUri);
        return new TrayService(this, sri?.Stream);
    }
}
