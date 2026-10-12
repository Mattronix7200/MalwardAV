using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Forms;
using WinForms = System.Windows.Forms;

namespace Malward.AppGUI.Services;

public enum BusyKind { None, Scan, Update }

public enum HealthBadge { None, Warn, Error }

public sealed class TrayService : ITray
{
    private readonly Window _window;
    private readonly WinForms.NotifyIcon _notify;
    private readonly Icon _iconIdle;
    private Icon[] _scanFrames;
    private Icon[] _updateFrames;
    private readonly WinForms.Timer _busyTimer;
    private BusyKind _busyKind = BusyKind.None;
    private int _frameIdx;

    private HealthBadge _healthBadge = HealthBadge.None;
    private Bitmap? _warnBadge, _crossBadge;
    private Icon? _composedHealthIcon;
    public Action? OnOpen { get; set; }
    public Action? OnScan { get; set; }
    public Action? OnQuarantine { get; set; }
    public Action? OnUpdate { get; set; }
    public Action? OnExit { get; set; }

    public Action? OnQuickScanBg { get; set; }

    public Action? OnFullScan { get; set; }

    public Action? OnCustomScan { get; set; }

    public Action? OnUpdateBg { get; set; }

    public Action<bool>? OnToggleProtection { get; set; }

    public Action<bool>? OnToggleNetworkProtection { get; set; }

    public Action<bool>? OnToggleBackup { get; set; }

    public Action<bool>? OnToggleSnapshots { get; set; }

    public Action<bool>? OnToggleRemovable { get; set; }

    private bool _protEnabled, _protAvailable, _protRunning;
    private bool _netEnabled,  _netAvailable,  _netRunning;
    private bool _backupAvailable, _backupOn;
    private bool _snapAvailable,   _snapOn;
    private bool _remAvailable,    _remOn;
    private string _lastUpdateStr = "—";
    private string _versionStr    = "—";
    private string _dbVersionStr  = "—";
    private TrayMenuForm? _menuForm;
    private Image? _logoForMenu;
    private readonly Dictionary<string, Image> _menuIcons = new();

    public Func<bool>? GetIsDarkTheme { get; set; }

    public TrayService(Window window, Stream? iconStream = null)
    {
        _window = window;
        _iconIdle = LoadIcon(iconStream) ?? SystemIcons.Application;

        _scanFrames = LoadGifFrames("scan.gif") ?? new[] { _iconIdle };
        _updateFrames = LoadGifFrames("update.gif") ?? new[] { _iconIdle };

        _notify = new WinForms.NotifyIcon
        {
            Text = "Malward",
            Visible = true,
            Icon = _iconIdle,
        };

        _notify.MouseClick += (_, e) =>
        {
            if (e.Button == WinForms.MouseButtons.Right) ShowMenuForm();
            else if (e.Button == WinForms.MouseButtons.Left) Restore();
        };
        _notify.DoubleClick += (_, _) => Restore();

        _notify.BalloonTipClicked += (_, _) => { try { OnBalloonClick?.Invoke(); } catch { } };

        _busyTimer = new WinForms.Timer { Interval = 80 };
        _busyTimer.Tick += (_, _) => AdvanceFrame();
    }

    private Icon? LoadIcon(Stream? s)
    {
        try { return s != null ? new Icon(s) : null; }
        catch { return null; }
    }

    public void ApplyBusyFrames(Func<string, byte[]?> assetResolver)
    {
        try
        {
            var scan   = LoadGifFrames("scan.gif", assetResolver);
            var update = LoadGifFrames("update.gif", assetResolver);
            if (scan   != null) _scanFrames   = scan;
            if (update != null) _updateFrames = update;
        }
        catch { }
    }

    private static Icon[]? LoadGifFrames(string name, Func<string, byte[]?>? assetResolver = null)
    {
        try
        {
            byte[]? bytes = null;
            try { bytes = assetResolver?.Invoke(name); } catch { }
            if (bytes != null && bytes.Length > 0)
            {
                using var ms = new MemoryStream(bytes, writable: false);
                using var imgPack = Image.FromStream(ms);
                return ExtractFrames(imgPack);
            }

            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "wwwroot", "assets", name),
                Path.Combine(AppContext.BaseDirectory, "assets", "assets", name),
                Path.Combine(AppContext.BaseDirectory, "..", "Extras", name),
                Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "Extras", name),
            };
            string? path = candidates.FirstOrDefault(File.Exists);
            if (path == null) return null;

            using var img = Image.FromFile(path);
            return ExtractFrames(img);
        }
        catch { return null; }
    }

    private static Icon[]? ExtractFrames(Image img)
    {
        var dim = new FrameDimension(img.FrameDimensionsList[0]);
        int count = img.GetFrameCount(dim);
        if (count <= 0) return null;

        int max = Math.Min(count, 60);
        var icons = new Icon[max];
        for (int i = 0; i < max; i++)
        {
            img.SelectActiveFrame(dim, i);
            using var bmp = new Bitmap(32, 32);
            using (var g = Graphics.FromImage(bmp))
            {
                g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                g.DrawImage(img, 0, 0, 32, 32);
            }
            IntPtr hi = bmp.GetHicon();
            try { icons[i] = (Icon)Icon.FromHandle(hi).Clone(); }
            finally { DestroyIcon(hi); }
        }
        return icons;
    }

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    private void AdvanceFrame()
    {
        var frames = _busyKind switch
        {
            BusyKind.Scan => _scanFrames,
            BusyKind.Update => _updateFrames,
            _ => null,
        };
        if (frames == null || frames.Length == 0) return;
        _frameIdx = (_frameIdx + 1) % frames.Length;
        _notify.Icon = frames[_frameIdx];
    }

    public void SetBusy(bool busy) => SetBusy(busy ? BusyKind.Scan : BusyKind.None);

    public void SetBusy(BusyKind kind)
    {
        if (_busyKind == kind) return;
        _busyKind = kind;
        _frameIdx = 0;
        if (kind == BusyKind.None)
        {
            _busyTimer.Stop();
            _notify.Icon = _composedHealthIcon ?? _iconIdle;
            _notify.Text = "Malward";
        }
        else
        {
            _notify.Text = kind switch
            {
                BusyKind.Scan => "Malward — skanowanie w toku…",
                BusyKind.Update => "Malward — aktualizacja w toku…",
                _ => "Malward"
            };
            _busyTimer.Start();
        }
    }

    public Action? RestoreOverride { get; set; }

    public bool MenuEnabled { get; set; } = true;

    public void Restore()
    {
        if (RestoreOverride != null) { try { RestoreOverride(); } catch { } return; }

        _window.ShowInTaskbar = true;
        _window.Opacity = 1;

        if (!_window.IsVisible) _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true; _window.Topmost = false;
    }

    public void SetProtectionState(bool available, bool enabled, bool running)
    {
        _protAvailable = available; _protEnabled = enabled; _protRunning = running;
    }

    public void SetNetworkState(bool available, bool enabled, bool running)
    {
        _netAvailable = available; _netEnabled = enabled; _netRunning = running;
    }

    public void SetBackupState(bool available, bool on)
    {
        _backupAvailable = available; _backupOn = on;
    }

    public void SetSnapshotsState(bool available, bool on)
    {
        _snapAvailable = available; _snapOn = on;
    }

    public void SetRemovableState(bool available, bool on)
    {
        _remAvailable = available; _remOn = on;
    }

    public void SetFooterInfo(string lastUpdate, string version, string dbVersion = "—")
    {
        _lastUpdateStr = lastUpdate;
        _versionStr    = version;
        _dbVersionStr  = dbVersion;
    }

    public void ApplyMenuLogo(Func<string, byte[]?> assetResolver)
    {
        try
        {
            var bytes = assetResolver("logo.png");
            if (bytes != null && bytes.Length > 0)
            {
                using var ms = new MemoryStream(bytes, writable: false);
                using var tmp = Image.FromStream(ms);
                _logoForMenu?.Dispose();
                _logoForMenu = new Bitmap(tmp);
            }
        }
        catch { }
    }

    public void ApplyMenuIcons(Func<string, byte[]?> assetResolver)
    {
        foreach (var name in new[] { "search", "refresh", "chest", "shield", "url" })
        {
            try
            {
                var bytes = assetResolver(name + ".png");
                if (bytes == null || bytes.Length == 0)
                {
                    CrashLog.Write("tray", null, $"menu icon missing from the asset pack: {name}.png");
                    continue;
                }
                {
                    using var ms = new MemoryStream(bytes, writable: false);
                    using var tmp = Image.FromStream(ms);
                    if (_menuIcons.TryGetValue(name, out var old)) { try { old.Dispose(); } catch { } }

                    _menuIcons[name] = new Bitmap(tmp);
                }
            }
            catch { }
        }
    }

    public void ApplyHealthIcons(Func<string, byte[]?> assetResolver)
    {
        Bitmap? Load(string name)
        {
            try
            {
                var bytes = assetResolver(name + ".png");
                if (bytes == null || bytes.Length == 0) return null;
                using var ms = new MemoryStream(bytes, writable: false);
                using var tmp = Image.FromStream(ms);
                return new Bitmap(tmp);
            }
            catch { return null; }
        }

        var w = Load("warning"); if (w != null) { _warnBadge?.Dispose();  _warnBadge = w; }
        var c = Load("cross");   if (c != null) { _crossBadge?.Dispose(); _crossBadge = c; }
        try { RebuildHealthIcon(); } catch { }
    }

    public void SetHealthOverlay(HealthBadge kind)
    {
        if (_healthBadge == kind) return;
        _healthBadge = kind;
        RebuildHealthIcon();
    }

    private void RebuildHealthIcon()
    {
        Bitmap? badge = _healthBadge switch
        {
            HealthBadge.Warn  => _warnBadge,
            HealthBadge.Error => _crossBadge,
            _                 => null,
        };
        var old = _composedHealthIcon;
        _composedHealthIcon = badge != null ? ComposeBadge(_iconIdle, badge) : null;
        if (old != null) { try { old.Dispose(); } catch { } }

        if (_busyKind == BusyKind.None)
            _notify.Icon = _composedHealthIcon ?? _iconIdle;
    }

    private static Icon ComposeBadge(Icon baseIcon, Bitmap badge)
    {
        using var canvas = new Bitmap(32, 32, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(canvas))
        {
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            using (var baseBmp = baseIcon.ToBitmap())
                g.DrawImage(baseBmp, 0, 0, 32, 32);
            const int bs = 18;
            g.DrawImage(badge, 32 - bs, 32 - bs, bs, bs);
        }
        IntPtr hi = canvas.GetHicon();
        try { return (Icon)Icon.FromHandle(hi).Clone(); }
        finally { DestroyIcon(hi); }
    }

    private void ShowMenuForm()
    {
        if (!MenuEnabled) return;
        try
        {
            if (_menuForm != null && !_menuForm.IsDisposed) { _menuForm.Close(); _menuForm = null; }

            bool dark = false;
            try { dark = GetIsDarkTheme?.Invoke() ?? false; } catch { }
            if (GetIsDarkTheme == null)
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                    dark = key?.GetValue("AppsUseLightTheme") is int v && v == 0;
                }
                catch { }
            }
            _menuForm = new TrayMenuForm(dark, _logoForMenu, _menuIcons);
            _menuForm.OnOpen            = () => Restore();
            _menuForm.OnQuickScan       = () => OnQuickScanBg?.Invoke();
            _menuForm.OnFullScan        = () => OnFullScan?.Invoke();
            _menuForm.OnCustomScan      = () => OnCustomScan?.Invoke();
            _menuForm.OnUpdate          = () => OnUpdateBg?.Invoke();
            _menuForm.OnQuarantine      = () => { Restore(); OnQuarantine?.Invoke(); };
            _menuForm.OnExit            = () => OnExit?.Invoke();
            _menuForm.OnToggleResident  = want => OnToggleProtection?.Invoke(want);
            _menuForm.OnToggleNetwork   = want => OnToggleNetworkProtection?.Invoke(want);
            _menuForm.OnToggleBackup    = want => OnToggleBackup?.Invoke(want);
            _menuForm.OnToggleSnapshots = want => OnToggleSnapshots?.Invoke(want);
            _menuForm.OnToggleRemovable = want => OnToggleRemovable?.Invoke(want);
            _menuForm.SetStatus(
                _protAvailable, _protEnabled, _protRunning,
                _netAvailable,  _netEnabled,  _netRunning,
                _lastUpdateStr, _versionStr, _dbVersionStr);
            _menuForm.SetToggleStates(
                _backupAvailable, _backupOn,
                _snapAvailable,   _snapOn,
                _remAvailable,    _remOn);
            _menuForm.ShowAtCursor();
        }
        catch { }
    }

    public Action? OnBalloonClick { get; set; }

    public void NotifyBalloon(string title, string message, Action? onClick = null)
    {
        OnBalloonClick = onClick;
        if (!_notify.Visible) _notify.Visible = true;
        _notify.BalloonTipIcon = WinForms.ToolTipIcon.Warning;
        _notify.BalloonTipTitle = title;
        _notify.BalloonTipText = message;
        _notify.ShowBalloonTip(4000);
    }

    public void Dispose()
    {
        try { _busyTimer.Stop(); _busyTimer.Dispose(); } catch { }
        try { _notify.Visible = false; _notify.Dispose(); } catch { }
        foreach (var ic in _scanFrames.Concat(_updateFrames))
            try { ic.Dispose(); } catch { }
        try { _composedHealthIcon?.Dispose(); } catch { }
        try { _warnBadge?.Dispose(); } catch { }
        try { _crossBadge?.Dispose(); } catch { }
    }
}
