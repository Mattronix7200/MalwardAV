using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace Malward.FWManager;

public sealed class ConnectionInfo
{
    public int Pid { get; init; }
    public string ProcessName { get; init; } = "";
    public string? ImagePath { get; init; }
    public string LocalAddress { get; init; } = "";
    public int LocalPort { get; init; }
    public string RemoteAddress { get; init; } = "";
    public int RemotePort { get; init; }
    public string State { get; init; } = "";
    public string Protocol { get; init; } = "TCP";

    public string? IconDataUrl { get; init; }

    public bool IsSystemCritical { get; init; }
}

internal static class AppIconCache
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> _cache
        = new(StringComparer.OrdinalIgnoreCase);

    private const int MaxEntries = 512;

    public static string? Get(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        if (_cache.TryGetValue(path, out var cached)) return cached;
        try
        {
            if (!System.IO.File.Exists(path)) { _cache[path] = null; return null; }
            using var ic = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (ic == null) { _cache[path] = null; return null; }
            using var bmp = ic.ToBitmap();

            using var small = new System.Drawing.Bitmap(bmp, 32, 32);
            using var ms = new System.IO.MemoryStream();
            small.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
            string b64 = "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
            if (_cache.Count > MaxEntries) _cache.Clear();
            _cache[path] = b64;
            return b64;
        }
        catch { _cache[path] = null; return null; }
    }
}

public static class SystemCriticalProcesses
{
    private static readonly HashSet<string> _names = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsaiso.exe", "fontdrvhost.exe",
        "svchost.exe", "dwm.exe", "memcompression", "secure system",
        "spoolsv.exe", "audiodg.exe", "ntoskrnl.exe", "idle",
    };
    public static bool IsCritical(int pid, string processName)
    {
        if (pid <= 4) return true;
        return !string.IsNullOrEmpty(processName) && _names.Contains(processName);
    }
}

public static class ConnectionEnumerator
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder,
        int ulAf, int TableClass, int Reserved);

    public static List<ConnectionInfo> EnumerateTcp()
    {
        var list = new List<ConnectionInfo>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            uint rc = GetExtendedTcpTable(buf, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc != 0) return list;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var rowPtr = (IntPtr)(buf.ToInt64() + 4);
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = (IntPtr)(rowPtr.ToInt64() + rowSize);

                var local = new IPAddress(row.localAddr);
                var remote = new IPAddress(row.remoteAddr);
                int lp = (int)(((row.localPort & 0xFF00) >> 8) | ((row.localPort & 0xFF) << 8));
                int rp = (int)(((row.remotePort & 0xFF00) >> 8) | ((row.remotePort & 0xFF) << 8));
                int pid = (int)row.owningPid;
                var (pname, ppath) = ResolveProcess(pid);
                list.Add(new ConnectionInfo
                {
                    Pid = pid,
                    ProcessName = pname,
                    ImagePath = ppath,
                    LocalAddress = local.ToString(),
                    LocalPort = lp,
                    RemoteAddress = remote.ToString(),
                    RemotePort = rp,
                    State = StateName((int)row.state),
                    IconDataUrl = AppIconCache.Get(ppath),
                    IsSystemCritical = SystemCriticalProcesses.IsCritical(pid, pname + ".exe"),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    private static (string name, string? path) ResolveProcess(int pid)
    {
        if (pid <= 4) return ("System", null);
        try
        {
            using var p = Process.GetProcessById(pid);
            string name = p.ProcessName;
            string? path = null;
            try { path = p.MainModule?.FileName; } catch {  }
            return (name, path);
        }
        catch { return ("(zakończony)", null); }
    }

    private static string StateName(int s) => s switch
    {
        1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RCVD",
        5 => "ESTABLISHED", 6 => "FIN_WAIT1", 7 => "FIN_WAIT2", 8 => "CLOSE_WAIT",
        9 => "CLOSING", 10 => "LAST_ACK", 11 => "TIME_WAIT", 12 => "DELETE_TCB",
        _ => "?",
    };
}
