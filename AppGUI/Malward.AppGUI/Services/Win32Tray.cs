using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Malward.AppGUI.Services;

public sealed class Win32Tray : ITray
{
    private const int WM_APP_TRAY = 0x0400 + 1;
    private const int WM_LBUTTONUP = 0x0202;
    private const int WM_RBUTTONUP = 0x0205;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_DESTROY = 0x0002;
    private const int NIN_BALLOONUSERCLICK = 0x0405;

    private const int NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2;
    private const int NIF_MESSAGE = 0x01, NIF_ICON = 0x02, NIF_TIP = 0x04, NIF_INFO = 0x10;
    private const int NIIF_INFO = 0x01;
    private const int IMAGE_ICON = 1;
    private const int LR_LOADFROMFILE = 0x0010, LR_DEFAULTSIZE = 0x0040;
    private const int IDI_APPLICATION = 32512;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WNDCLASS
    {
        public int style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpszClassName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public int message;
        public IntPtr wParam;
        public IntPtr lParam;
        public int time;
        public int ptX;
        public int ptY;
    }

    private delegate IntPtr WndProc(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int dwMessage, ref NOTIFYICONDATA pnid);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassW(ref WNDCLASS lpWndClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(int dwExStyle, string lpClassName, string lpWindowName,
        int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu,
        IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int GetMessageW(out MSG lpMsg, IntPtr hWnd, int wMsgFilterMin, int wMsgFilterMax);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern bool PostMessageW(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImageW(IntPtr hinst, string lpszName, int uType,
        int cxDesired, int cyDesired, int fuLoad);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadIconW(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr ExtractIconW(IntPtr hInst, string lpszExeFileName, int nIconIndex);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);

    private readonly WndProc _proc;
    private readonly string _klasa = "MalwardTray_" + Guid.NewGuid().ToString("N");
    private IntPtr _hwnd;
    private IntPtr _icon;
    private NOTIFYICONDATA _dane;
    private Thread? _watek;
    private readonly ManualResetEventSlim _gotowy = new(false);
    private Action? _klikDymka;
    private volatile bool _zamkniety;

    public Action? OnOpen { get; set; }
    public Action? OnScan { get; set; }
    public Action? OnQuarantine { get; set; }
    public Action? OnUpdate { get; set; }
    public Action? OnExit { get; set; }
    public Action? OnQuickScanBg { get; set; }
    public Action? OnUpdateBg { get; set; }
    public Action? OnFullScan { get; set; }
    public Action? OnCustomScan { get; set; }
    public Action? OnBalloonClick { get; set; }
    public Action<bool>? OnToggleProtection { get; set; }
    public Action<bool>? OnToggleNetworkProtection { get; set; }
    public Action<bool>? OnToggleBackup { get; set; }
    public Action<bool>? OnToggleSnapshots { get; set; }
    public Action<bool>? OnToggleRemovable { get; set; }
    public Func<bool>? GetIsDarkTheme { get; set; }

    public Action? RestoreOverride { get; set; }
    public bool MenuEnabled { get; set; }

    public Win32Tray(string? iconPath)
    {
        _proc = Procedura;
        _watek = new Thread(() => Petla(iconPath))
        {
            IsBackground = true,
            Name = "Malward-Tray",
        };
        _watek.SetApartmentState(ApartmentState.STA);
        _watek.Start();
        _gotowy.Wait(5000);
    }

    private void Petla(string? iconPath)
    {
        try
        {
            var hInst = GetModuleHandleW(null);

            var klasa = new WNDCLASS
            {
                lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_proc),
                hInstance = hInst,
                lpszClassName = _klasa,
                lpszMenuName = string.Empty,
            };
            RegisterClassW(ref klasa);

            _hwnd = CreateWindowExW(0, _klasa, "Malward", 0, 0, 0, 0, 0,
                                    new IntPtr(-3), IntPtr.Zero, hInst, IntPtr.Zero);

            _icon = WczytajIkone(iconPath);

            _dane = new NOTIFYICONDATA
            {
                cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
                hWnd = _hwnd,
                uID = 1,
                uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
                uCallbackMessage = WM_APP_TRAY,
                hIcon = _icon,
                szTip = "Malward",
                szInfo = string.Empty,
                szInfoTitle = string.Empty,
            };
            Shell_NotifyIcon(NIM_ADD, ref _dane);
        }
        catch (Exception ex) { CrashLog.Write("tray-win32", ex, "start"); }
        finally { _gotowy.Set(); }

        while (!_zamkniety && GetMessageW(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
    }

    private static IntPtr WczytajIkone(string? sciezka)
    {
        try
        {
            if (!string.IsNullOrEmpty(sciezka)
                && sciezka!.EndsWith(".ico", StringComparison.OrdinalIgnoreCase)
                && System.IO.File.Exists(sciezka))
            {
                var h = LoadImageW(IntPtr.Zero, sciezka, IMAGE_ICON, 0, 0,
                                   LR_LOADFROMFILE | LR_DEFAULTSIZE);
                if (h != IntPtr.Zero) return h;
            }
        }
        catch { }

        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe))
            {
                var h = ExtractIconW(IntPtr.Zero, exe!, 0);
                if (h != IntPtr.Zero && h.ToInt64() != 1) return h;
            }
        }
        catch { }

        return LoadIconW(IntPtr.Zero, new IntPtr(IDI_APPLICATION));
    }

    private IntPtr Procedura(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            if (msg == WM_APP_TRAY)
            {
                int zdarzenie = (int)(lParam.ToInt64() & 0xFFFF);
                switch (zdarzenie)
                {
                    case WM_LBUTTONUP:
                    case WM_LBUTTONDBLCLK:
                        Restore();
                        break;
                    case WM_RBUTTONUP:
                        if (MenuEnabled) Restore();
                        break;
                    case NIN_BALLOONUSERCLICK:
                        var k = _klikDymka ?? OnBalloonClick;
                        _klikDymka = null;
                        try { k?.Invoke(); } catch { }
                        break;
                }
                return IntPtr.Zero;
            }
            if (msg == WM_DESTROY) { _zamkniety = true; return IntPtr.Zero; }
        }
        catch (Exception ex) { CrashLog.Write("tray-win32", ex, "wndproc"); }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    public void Restore()
    {
        var o = RestoreOverride;
        if (o != null) { try { o(); } catch { } return; }
        try { OnOpen?.Invoke(); } catch { }
    }

    public void SetBusy(BusyKind kind)
    {
        SetTooltip(kind switch
        {
            BusyKind.Scan => "Malward — skanowanie…",
            BusyKind.Update => "Malward — aktualizacja…",
            _ => "Malward",
        });
    }

    private void SetTooltip(string text)
    {
        if (_hwnd == IntPtr.Zero) return;
        try
        {
            _dane.uFlags = NIF_TIP;
            _dane.szTip = text.Length > 120 ? text[..120] : text;
            Shell_NotifyIcon(NIM_MODIFY, ref _dane);
        }
        catch { }
    }

    public void NotifyBalloon(string title, string message, Action? onClick = null)
    {
        if (_hwnd == IntPtr.Zero) return;
        try
        {
            _klikDymka = onClick;
            _dane.uFlags = NIF_INFO;
            _dane.szInfoTitle = title.Length > 60 ? title[..60] : title;
            _dane.szInfo = message.Length > 250 ? message[..250] : message;
            _dane.dwInfoFlags = NIIF_INFO;
            Shell_NotifyIcon(NIM_MODIFY, ref _dane);
        }
        catch (Exception ex) { CrashLog.Write("tray-win32", ex, "balloon"); }
    }

    public void ApplyBusyFrames(Func<string, byte[]?> assetResolver) { }
    public void ApplyMenuLogo(Func<string, byte[]?> assetResolver) { }
    public void ApplyMenuIcons(Func<string, byte[]?> assetResolver) { }
    public void ApplyHealthIcons(Func<string, byte[]?> assetResolver) { }

    public void SetProtectionState(bool available, bool enabled, bool running) { }
    public void SetNetworkState(bool available, bool enabled, bool running) { }
    public void SetBackupState(bool available, bool on) { }
    public void SetSnapshotsState(bool available, bool on) { }
    public void SetRemovableState(bool available, bool on) { }
    public void SetFooterInfo(string lastUpdate, string version, string dbVersion = "—") { }
    public void SetHealthOverlay(HealthBadge kind) { }

    public void Dispose()
    {
        if (_zamkniety) return;
        _zamkniety = true;
        try { if (_hwnd != IntPtr.Zero) Shell_NotifyIcon(NIM_DELETE, ref _dane); } catch { }
        try { if (_icon != IntPtr.Zero) DestroyIcon(_icon); } catch { }
        try
        {
            if (_hwnd != IntPtr.Zero)
            {
                PostMessageW(_hwnd, WM_DESTROY, IntPtr.Zero, IntPtr.Zero);
                DestroyWindow(_hwnd);
            }
        }
        catch { }
        _hwnd = IntPtr.Zero;
    }
}
