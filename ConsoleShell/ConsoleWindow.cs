using System.Runtime.InteropServices;

namespace Malward.ConsoleShell;

public static class ConsoleWindow
{
    public const int DesiredWidth = 116;
    public const int DesiredHeight = 40;
    public const int MinimumWidth = 80;
    public const int MinimumHeight = 28;

    private const int GwlStyle = -16;
    private const int WsSizeBox = 0x00040000;
    private const int WsMaximizeBox = 0x00010000;
    private const uint SwpNoMove = 0x0002;
    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpFrameChanged = 0x0020;
    private const uint ScSize = 0xF000;
    private const uint ScMaximize = 0xF030;
    private const uint MfByCommand = 0x0000;

    private const int StdInputHandle = -10;
    private const int StdOutputHandle = -11;
    private const uint EnableQuickEdit = 0x0040;
    private const uint EnableExtendedFlags = 0x0080;
    private const uint EnableMouseInput = 0x0010;
    private const uint EnableVirtualTerminalProcessing = 0x0004;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr handle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleCtrlHandler(HandlerRoutine? handler, bool add);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassName(IntPtr window, System.Text.StringBuilder name, int count);

    [DllImport("user32.dll")]
    private static extern IntPtr GetSystemMenu(IntPtr window, bool revert);

    [DllImport("user32.dll")]
    private static extern bool DeleteMenu(IntPtr menu, uint position, uint flags);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr(IntPtr window, int index);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW")]
    private static extern IntPtr SetWindowLongPtr(IntPtr window, int index, IntPtr value);

    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y,
                                            int cx, int cy, uint flags);

    private delegate bool HandlerRoutine(uint signal);

    private static HandlerRoutine? _ctrlHandler;
    private static int _busy;
    private static bool _entered;
    private static bool _sizeSaved;
    private static bool? _classic;
    private static bool? _vt;
    private static TextWriter? _out;
    private static int _savedWindowWidth, _savedWindowHeight;
    private static int _savedBufferWidth, _savedBufferHeight;
    private static int _resizeTries;
    private static long _lastResize;

    public static int TargetWidth { get; private set; }
    public static int TargetHeight { get; private set; }

    public static TextWriter Out => _out ?? Console.Out;

    public static bool Busy
    {
        get => Volatile.Read(ref _busy) != 0;
        set => Volatile.Write(ref _busy, value ? 1 : 0);
    }

    public static bool InterruptBlocked { get; private set; }

    public static bool FullScreenUsed { get; private set; }

    public static void InstallInterruptGuard()
    {
        _out ??= Console.Out;

        if (_ctrlHandler != null) return;
        _ctrlHandler = Signal;
        try { SetConsoleCtrlHandler(_ctrlHandler, true); }
        catch { _ctrlHandler = null; }

        try { Console.CancelKeyPress += (_, e) => e.Cancel = Busy; }
        catch { }
    }

    private static bool Signal(uint signal)
    {
        if (signal > 1) return false;
        if (!Busy) return false;
        InterruptBlocked = true;
        return true;
    }

    public static bool ClearInterruptFlag()
    {
        bool was = InterruptBlocked;
        InterruptBlocked = false;
        return was;
    }

    public static bool ClassicConsole
    {
        get
        {
            if (_classic.HasValue) return _classic.Value;
            bool classic = false;
            try
            {
                var window = GetConsoleWindow();
                if (window != IntPtr.Zero)
                {
                    var name = new System.Text.StringBuilder(64);
                    if (GetClassName(window, name, name.Capacity) > 0)
                        classic = name.ToString() == "ConsoleWindowClass";
                }
            }
            catch { }
            _classic = classic;
            return classic;
        }
    }

    public static bool VirtualTerminal
    {
        get
        {
            if (_vt.HasValue) return _vt.Value;
            bool on = false;
            try
            {
                if (!Console.IsOutputRedirected)
                {
                    var handle = GetStdHandle(StdOutputHandle);
                    if (handle != IntPtr.Zero && handle != new IntPtr(-1)
                        && GetConsoleMode(handle, out uint mode))
                    {
                        on = (mode & EnableVirtualTerminalProcessing) != 0
                             || SetConsoleMode(handle, mode | EnableVirtualTerminalProcessing);
                    }
                }
            }
            catch { }
            _vt = on;
            return on;
        }
    }

    // Konsola sprzed Windows 10 nie zna sekwencji VT ani nie rysuje poprawnie ramek
    // z Unicode: "│" wychodzi z niej jako "ŕöé", bo bajty UTF-8 ladują w stronie kodowej
    // 852. Na takiej konsoli rysujemy samym ASCII i chowamy pasek boczny z logiem.
    public static bool LegacyConsole => !VirtualTerminal;

    public static void Enter()
    {
        if (_entered) return;
        _entered = true;
        FullScreenUsed = true;

        try { Console.Title = "Malward Command Tool Utility"; } catch { }

        if (Console.IsOutputRedirected) return;

        _out ??= Console.Out;
        SaveSize();
        Resize();
        LockFrame();
        DisableQuickEdit();

        try { Console.Clear(); } catch { }
        try { Console.CursorVisible = false; } catch { }
    }

    public static void Restore()
    {
        if (!_entered) return;
        _entered = false;

        try
        {
            if (VirtualTerminal) { Out.Write("\u001b[0m\u001b[?25h"); Out.Flush(); }
        }
        catch { }
        try { Console.ResetColor(); } catch { }
        try { Console.CursorVisible = true; } catch { }
        if (!_sizeSaved || Con.OwnsConsoleWindow()) return;

        try
        {
            if (ClassicConsole)
            {
                Console.SetWindowSize(Math.Min(_savedWindowWidth, Console.WindowWidth),
                                      Math.Min(_savedWindowHeight, Console.WindowHeight));
                Console.SetBufferSize(_savedBufferWidth, _savedBufferHeight);
                Console.SetWindowSize(_savedWindowWidth, _savedWindowHeight);
            }
            else RequestSize(_savedWindowWidth, _savedWindowHeight);
        }
        catch { }
    }

    private static void SaveSize()
    {
        try
        {
            _savedWindowWidth = Console.WindowWidth;
            _savedWindowHeight = Console.WindowHeight;
            _savedBufferWidth = Console.BufferWidth;
            _savedBufferHeight = Console.BufferHeight;
            _sizeSaved = true;
        }
        catch { _sizeSaved = false; }
    }

    private static void RequestSize(int width, int height)
    {
        if (!VirtualTerminal) return;
        try
        {
            Out.Write("\u001b[8;" + height + ";" + width + "t");
            Out.Flush();
        }
        catch { }
    }

    private static void Resize()
    {
        if (ClassicConsole)
        {
            try
            {
                int width = Math.Max(MinimumWidth, Math.Min(DesiredWidth, Console.LargestWindowWidth));
                int height = Math.Max(MinimumHeight, Math.Min(DesiredHeight, Console.LargestWindowHeight));

                Console.SetWindowSize(Math.Min(width, Console.WindowWidth),
                                      Math.Min(height, Console.WindowHeight));
                Console.SetBufferSize(width, height);
                Console.SetWindowSize(width, height);
            }
            catch
            {
                try { Console.SetBufferSize(Console.WindowWidth, Console.WindowHeight); } catch { }
            }
            Remember();
            return;
        }

        RequestSize(DesiredWidth, DesiredHeight);
        for (int i = 0; i < 15; i++)
        {
            Thread.Sleep(40);
            try
            {
                if (Console.WindowHeight == DesiredHeight && Console.WindowWidth == DesiredWidth) break;
            }
            catch { break; }
        }
        Thread.Sleep(150);
        try { Console.SetBufferSize(Console.WindowWidth, Console.WindowHeight); } catch { }
        Remember();
    }

    private static void Remember()
    {
        try
        {
            TargetWidth = Console.WindowWidth;
            TargetHeight = Console.WindowHeight;
        }
        catch
        {
            TargetWidth = DesiredWidth;
            TargetHeight = DesiredHeight;
        }
        _resizeTries = 0;
    }

    public static void KeepSize()
    {
        if (!_entered || ClassicConsole || !VirtualTerminal) return;
        if (TargetWidth <= 0 || TargetHeight <= 0) return;

        int width, height;
        try { width = Console.WindowWidth; height = Console.WindowHeight; }
        catch { return; }

        if (width == TargetWidth && height == TargetHeight) { _resizeTries = 0; return; }

        if (_resizeTries >= 5)
        {
            TargetWidth = width;
            TargetHeight = height;
            _resizeTries = 0;
            try { Console.SetBufferSize(width, height); } catch { }
            return;
        }

        long now = Environment.TickCount64;
        if (now - _lastResize < 350) return;
        _lastResize = now;
        _resizeTries++;
        RequestSize(TargetWidth, TargetHeight);
    }

    private static void LockFrame()
    {
        if (!ClassicConsole) return;
        try
        {
            var window = GetConsoleWindow();
            if (window == IntPtr.Zero) return;

            var menu = GetSystemMenu(window, false);
            if (menu != IntPtr.Zero)
            {
                DeleteMenu(menu, ScSize, MfByCommand);
                DeleteMenu(menu, ScMaximize, MfByCommand);
            }

            long style = GetWindowLongPtr(window, GwlStyle).ToInt64();
            long locked = style & ~(long)(WsSizeBox | WsMaximizeBox);
            if (locked != style)
            {
                SetWindowLongPtr(window, GwlStyle, new IntPtr(locked));
                SetWindowPos(window, IntPtr.Zero, 0, 0, 0, 0,
                             SwpNoMove | SwpNoSize | SwpNoZOrder | SwpFrameChanged);
            }
        }
        catch { }
    }

    private static void DisableQuickEdit()
    {
        try
        {
            var input = GetStdHandle(StdInputHandle);
            if (input == IntPtr.Zero || input == new IntPtr(-1)) return;
            if (!GetConsoleMode(input, out uint mode)) return;
            uint wanted = (mode | EnableExtendedFlags) & ~(EnableQuickEdit | EnableMouseInput);
            if (wanted != mode) SetConsoleMode(input, wanted);
        }
        catch { }
    }
}
