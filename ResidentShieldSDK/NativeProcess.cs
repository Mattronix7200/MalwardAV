using System.Runtime.InteropServices;

namespace Malward.ResidentShield;

public static class NativeProcess
{
    public static bool EnableDebugPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token))
            return false;
        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out LUID luid)) return false;
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED,
            };
            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(token); }
    }

    public static List<int> GetDescendantsLeafFirst(int rootPid)
    {
        var childrenOf = BuildChildMap();
        var ordered = new List<int>();
        var visited = new HashSet<int>();

        void Recurse(int pid)
        {
            if (!childrenOf.TryGetValue(pid, out var kids)) return;
            foreach (var k in kids)
            {
                if (!visited.Add(k)) continue;
                Recurse(k);
                ordered.Add(k);
            }
        }

        Recurse(rootPid);
        return ordered;
    }

    private static Dictionary<int, List<int>> BuildChildMap()
    {
        var map = new Dictionary<int, List<int>>();
        foreach (var (pid, parent, _) in Snapshot())
        {
            if (!map.TryGetValue(parent, out var list))
                map[parent] = list = new List<int>();
            list.Add(pid);
        }
        return map;
    }

    public static List<(int pid, int parent, string name)> Snapshot()
    {
        var list = new List<(int, int, string)>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return list;
        try
        {
            var pe = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
            if (!Process32First(snap, ref pe)) return list;
            do { list.Add(((int)pe.th32ProcessID, (int)pe.th32ParentProcessID, pe.szExeFile)); }
            while (Process32Next(snap, ref pe));
        }
        finally { CloseHandle(snap); }
        return list;
    }

    public static List<int> GetAncestors(int pid, int maxDepth = 12)
    {
        var snap = Snapshot();
        var parentOf = new Dictionary<int, int>();
        foreach (var (p, par, _) in snap) parentOf[p] = par;

        var result = new List<int>();
        var seen = new HashSet<int> { pid };
        int cur = pid;
        for (int i = 0; i < maxDepth; i++)
        {
            if (!parentOf.TryGetValue(cur, out int par) || par <= 4) break;
            if (!seen.Add(par)) break;
            result.Add(par);
            cur = par;
        }
        return result;
    }

    public static List<int> FindPidsByImagePaths(ICollection<string> paths)
    {
        var result = new List<int>();
        if (paths.Count == 0) return result;
        var set = new HashSet<string>(paths, StringComparer.OrdinalIgnoreCase);
        foreach (var (pid, _, _) in Snapshot())
        {
            if (pid <= 4) continue;
            var img = GetImagePath(pid);
            if (!string.IsNullOrEmpty(img) && set.Contains(img)) result.Add(pid);
        }
        return result;
    }

    public static List<int> FindPidsUnderDirectory(string dir)
    {
        var result = new List<int>();
        if (string.IsNullOrEmpty(dir)) return result;
        foreach (var (pid, _, _) in Snapshot())
        {
            if (pid <= 4) continue;
            var img = GetImagePath(pid);
            if (!string.IsNullOrEmpty(img) && img.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                result.Add(pid);
        }
        return result;
    }

    public static void Suspend(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return;
        try { NtSuspendProcess(h); } catch { } finally { CloseHandle(h); }
    }

    public static void Resume(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return;
        try { NtResumeProcess(h); } catch { } finally { CloseHandle(h); }
    }

    public static bool Terminate(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, false, pid);
        if (h == IntPtr.Zero)
            return true;
        try
        {
            TerminateProcess(h, 1);
            WaitForSingleObject(h, 2000);
            return true;
        }
        catch { return false; }
        finally { CloseHandle(h); }
    }

    public static string GetImagePath(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return "";
        try
        {
            var sb = new System.Text.StringBuilder(1024);
            int len = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref len) ? sb.ToString() : "";
        }
        finally { CloseHandle(h); }
    }

    private const uint  TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    private const int PROCESS_TERMINATE                   = 0x0001;
    private const int PROCESS_SUSPEND_RESUME              = 0x0800;
    private const int PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000;
    private const int SYNCHRONIZE                         = 0x00100000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32First(IntPtr snap, ref PROCESSENTRY32 pe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32Next(IntPtr snap, ref PROCESSENTRY32 pe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr h, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr h, uint ms);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr h, int flags,
        System.Text.StringBuilder name, ref int size);

    [DllImport("ntdll.dll")] private static extern int NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")] private static extern int NtResumeProcess(IntPtr h);

    private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string existing, string? newName, uint flags);

    public static bool ScheduleDeleteOnReboot(string path)
    {
        try { return MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT); }
        catch { return false; }
    }

    private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const int TOKEN_QUERY             = 0x0008;
    private const int SE_PRIVILEGE_ENABLED    = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID Luid;
        public int Attributes;
    }

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr prev, IntPtr returnLength);
}
