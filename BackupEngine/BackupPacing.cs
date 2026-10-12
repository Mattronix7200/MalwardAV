using System.Runtime.InteropServices;

namespace Malward.BackupEngine;

public sealed record BackupProgress(
    long DoneFiles,
    long TotalFiles,
    long DoneBytes,
    long TotalBytes,
    string CurrentPath);

public static class BackupPacing
{
    private const uint BackgroundBegin = 0x00100000;
    private const uint BackgroundEnd   = 0x00200000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetPriorityClass(IntPtr handle, uint priorityClass);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    private static bool _background;

    public static bool EnterBackgroundMode()
    {
        if (_background) return true;
        try
        {
            _background = SetPriorityClass(GetCurrentProcess(), BackgroundBegin);
            return _background;
        }
        catch { return false; }
    }

    public static void LeaveBackgroundMode()
    {
        if (!_background) return;
        try { SetPriorityClass(GetCurrentProcess(), BackgroundEnd); } catch { }
        _background = false;
    }

    public static TimeSpan IdleFor()
    {
        try
        {
            var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
            if (!GetLastInputInfo(ref info)) return TimeSpan.Zero;
            uint delta = unchecked((uint)Environment.TickCount - info.Time);
            return TimeSpan.FromMilliseconds(delta);
        }
        catch { return TimeSpan.Zero; }
    }

    public static readonly TimeSpan IdleThreshold = TimeSpan.FromSeconds(45);

    public const int ActiveUserSleepMs = 12;

    public static bool UserIsActive => IdleFor() < IdleThreshold;

    public static void Pace()
    {
        if (!UserIsActive) return;
        Thread.Sleep(ActiveUserSleepMs);
    }
}
