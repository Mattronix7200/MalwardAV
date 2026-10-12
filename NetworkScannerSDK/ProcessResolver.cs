using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace Malward.NetworkScanner;

public static class ProcessResolver
{
    private static Dictionary<int, int> _udpPortToPid = new();
    private static Dictionary<int, int> _tcpPortToPid = new();
    private static DateTime _udpCacheTime = DateTime.MinValue;
    private static DateTime _tcpCacheTime = DateTime.MinValue;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMilliseconds(250);
    private static readonly object _udpLock = new();
    private static readonly object _tcpLock = new();

    private static readonly Dictionary<int, (string Name, DateTime At)> _pidNames = new();
    private static readonly TimeSpan NameTtl = TimeSpan.FromSeconds(5);
    private static readonly object _pidLock = new();

    public static int GetUdpProcessId(int localPort)
    {
        RefreshUdpIfStale();
        lock (_udpLock)
        {
            return _udpPortToPid.TryGetValue(localPort, out var pid) ? pid : 0;
        }
    }

    public static int GetTcpProcessId(int localPort)
    {
        RefreshTcpIfStale();
        lock (_tcpLock)
        {
            return _tcpPortToPid.TryGetValue(localPort, out var pid) ? pid : 0;
        }
    }

    public static string? GetProcessName(int pid)
    {
        if (pid <= 4) return null;
        lock (_pidLock)
        {
            if (_pidNames.TryGetValue(pid, out var c) && (DateTime.UtcNow - c.At) < NameTtl)
                return c.Name;
        }
        string? name = null;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName;
            if (!string.IsNullOrEmpty(name) && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                name += ".exe";
        }
        catch (ArgumentException) {  }
        catch (System.ComponentModel.Win32Exception) { name = $"elevated:{pid}"; }
        catch { }
        lock (_pidLock)
        {
            if (!string.IsNullOrEmpty(name)) _pidNames[pid] = (name, DateTime.UtcNow);

            if (_pidNames.Count > 512)
            {
                var cutoff = DateTime.UtcNow - NameTtl;
                var stale = _pidNames.Where(kv => kv.Value.At < cutoff).Select(kv => kv.Key).ToList();
                foreach (var k in stale) _pidNames.Remove(k);
            }
        }
        return name;
    }

    public static string? ResolveUdpProcess(int localPort) => GetProcessName(GetUdpProcessId(localPort));

    public static string? ResolveTcpProcess(int localPort) => GetProcessName(GetTcpProcessId(localPort));

    private const int AF_INET = 2;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    private static void RefreshUdpIfStale()
    {
        if ((DateTime.UtcNow - _udpCacheTime) < CacheTtl) return;
        var map = SnapshotUdpTable();
        lock (_udpLock) { _udpPortToPid = map; _udpCacheTime = DateTime.UtcNow; }
    }
    private static void RefreshTcpIfStale()
    {
        if ((DateTime.UtcNow - _tcpCacheTime) < CacheTtl) return;
        var map = SnapshotTcpTable();
        lock (_tcpLock) { _tcpPortToPid = map; _tcpCacheTime = DateTime.UtcNow; }
    }

    private static Dictionary<int, int> SnapshotUdpTable()
    {
        var result = new Dictionary<int, int>(256);
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size <= 0) return result;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0) != 0)
                return result;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(
                    buf + sizeof(int) + i * rowSize);
                int port = ((int)row.LocalPort & 0xFF) << 8 | ((int)row.LocalPort >> 8) & 0xFF;
                result[port] = (int)row.OwningPid;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static Dictionary<int, int> SnapshotTcpTable()
    {
        var result = new Dictionary<int, int>(512);
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return result;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return result;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                    buf + sizeof(int) + i * rowSize);
                int port = ((int)row.LocalPort & 0xFF) << 8 | ((int)row.LocalPort >> 8) & 0xFF;
                result[port] = (int)row.OwningPid;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }

    private const uint MIB_TCP_STATE_SYN_SENT = 3;
    private const uint MIB_TCP_STATE_ESTAB    = 5;

    public readonly record struct TcpConn(string RemoteIp, int RemotePort, int LocalPort, int Pid, uint State,
        uint LocalAddrRaw = 0, uint LocalPortRaw = 0, uint RemoteAddrRaw = 0, uint RemotePortRaw = 0);

    public static List<TcpConn> SnapshotTcpConnections()
    {
        var result = new List<TcpConn>(256);
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return result;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return result;
            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                    buf + sizeof(int) + i * rowSize);
                if (row.State != MIB_TCP_STATE_ESTAB && row.State != MIB_TCP_STATE_SYN_SENT) continue;
                if (row.RemoteAddr == 0) continue;
                int rport = ((int)row.RemotePort & 0xFF) << 8 | ((int)row.RemotePort >> 8) & 0xFF;
                int lport = ((int)row.LocalPort  & 0xFF) << 8 | ((int)row.LocalPort  >> 8) & 0xFF;
                if (rport == 0) continue;

                var ip = new IPAddress(BitConverter.GetBytes(row.RemoteAddr)).ToString();
                result.Add(new TcpConn(ip, rport, lport, (int)row.OwningPid, row.State,
                    row.LocalAddr, row.LocalPort, row.RemoteAddr, row.RemotePort));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }
}
