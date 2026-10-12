using System.Management;
using System.Runtime.InteropServices;

namespace Malward.ResidentShield;

public sealed class WmiProcessMonitor : IDisposable
{
    private readonly ShieldConfig       _config;
    private readonly ProcessTracker     _tracker;
    private readonly Action<ScanEvent>? _scanCallback;

    private ManagementEventWatcher? _watcher;

    public WmiProcessMonitor(ShieldConfig config, ProcessTracker tracker,
        Action<ScanEvent>? scanCallback = null)
    {
        _config       = config;
        _tracker      = tracker;
        _scanCallback = scanCallback;
    }

    public void Start()
    {
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            _watcher = new ManagementEventWatcher(
                new ManagementScope(@"\\.\root\CIMV2"), query);
            _watcher.EventArrived += OnProcessStart;
            _watcher.Start();
            Log.Info("WMI", "Process start monitor active (Win32_ProcessStartTrace)");
        }
        catch (Exception ex)
        {
            Log.Warn("WMI", $"Failed to start the WMI monitor: {ex.Message}");
        }
    }

    private void OnProcessStart(object sender, EventArrivedEventArgs e)
    {
        if (!_config.ProcessMonitorEnabled) return;

        int pid, ppid;
        string name;
        try
        {
            var p = e.NewEvent;
            pid  = Convert.ToInt32(p["ProcessID"]);
            ppid = Convert.ToInt32(p["ParentProcessID"]);
            name = p["ProcessName"]?.ToString() ?? "";
        }
        catch { return; }

        Task.Run(() => Resolve(pid, ppid, name));
    }

    private void Resolve(int pid, int ppid, string name)
    {
        string image   = QueryImagePath(pid);
        string cmdLine = QueryCommandLine(pid);

        _tracker.Register(pid, ppid, name, image, cmdLine);

        if (_scanCallback == null) return;

        if (!string.IsNullOrEmpty(image) && File.Exists(image))
        {
            _scanCallback(new ScanEvent(ScanEventKind.ProcessStarted,
                image, pid, name, DateTimeOffset.UtcNow));
        }

        foreach (var target in LolBin.ExtractTargets(name, cmdLine))
            _scanCallback(new ScanEvent(ScanEventKind.FileCreated,
                target, pid, name, DateTimeOffset.UtcNow));
    }

    private static string QueryImagePath(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return "";
        try
        {
            var sb  = new System.Text.StringBuilder(1024);
            int len = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref len) ? sb.ToString() : "";
        }
        finally { CloseHandle(h); }
    }

    private static string QueryCommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject mo in searcher.Get())
                return mo["CommandLine"]?.ToString() ?? "";
        }
        catch { }
        return "";
    }

    public void Dispose()
    {
        try { _watcher?.Stop(); _watcher?.Dispose(); } catch { }
        _watcher = null;
    }

    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess, int flags, System.Text.StringBuilder lpExeName, ref int size);
}
