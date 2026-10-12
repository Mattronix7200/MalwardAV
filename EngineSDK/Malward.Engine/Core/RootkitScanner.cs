using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Malward.Engine.Core;

public static class RootkitScanner
{
    public sealed record Finding(string Kind, int Pid, string ImagePath, string Description);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcesses(int[] processIds, int cb, out int bytesReturned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr proc, uint flags,
                                                          StringBuilder name, ref int size);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
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

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private static HashSet<int> ViaEnumProcesses()
    {
        var set = new HashSet<int>();
        try
        {
            var buf = new int[4096];
            if (EnumProcesses(buf, buf.Length * sizeof(int), out int returned))
                for (int i = 0; i < returned / sizeof(int); i++)
                    if (buf[i] > 0) set.Add(buf[i]);
        }
        catch { }
        return set;
    }

    private static HashSet<int> ViaToolhelp()
    {
        var set = new HashSet<int>();
        IntPtr snap = IntPtr.Zero;
        try
        {
            snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return set;
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref e))
                do { if (e.th32ProcessID > 0) set.Add((int)e.th32ProcessID); }
                while (Process32NextW(snap, ref e));
        }
        catch { }
        finally { if (snap != IntPtr.Zero && snap != new IntPtr(-1)) CloseHandle(snap); }
        return set;
    }

    private static HashSet<int> ViaDotNet()
    {
        var set = new HashSet<int>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try { if (p.Id > 0) set.Add(p.Id); } catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }
        return set;
    }

    private static string ImageOf(int pid)
    {
        IntPtr h = IntPtr.Zero;
        try
        {
            h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return "";
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString() : "";
        }
        catch { return ""; }
        finally { if (h != IntPtr.Zero) CloseHandle(h); }
    }

    public static List<Finding> Scan()
    {
        var findings = new List<Finding>();
        try
        {
            var enumP = ViaEnumProcesses();
            var tool  = ViaToolhelp();
            var net   = ViaDotNet();

            var views = new List<(string Name, HashSet<int> Set)>();
            if (enumP.Count > 0) views.Add(("EnumProcesses", enumP));
            if (tool.Count  > 0) views.Add(("Toolhelp32", tool));
            if (net.Count   > 0) views.Add(("Process.GetProcesses", net));
            if (views.Count < 2) return findings;

            var union = new HashSet<int>();
            foreach (var v in views) union.UnionWith(v.Set);

            foreach (int pid in union)
            {
                if (pid <= 4) continue;
                var missing = views.Where(v => !v.Set.Contains(pid)).Select(v => v.Name).ToList();
                if (missing.Count == 0) continue;

                string image = ImageOf(pid);
                if (image.Length == 0) continue;

                findings.Add(new Finding("HiddenProcess", pid, image,
                    $"PID {pid} ({Path.GetFileName(image)}) jest niewidoczny dla: {string.Join(", ", missing)} " +
                    "— typowe dla ukrywania procesu przez rootkit"));
            }

            foreach (int pid in union)
            {
                if (pid <= 4) continue;
                string image = ImageOf(pid);
                if (image.Length == 0) continue;
                bool exists;
                try { exists = File.Exists(image); } catch { continue; }
                if (exists) continue;
                if (findings.Any(f => f.Pid == pid)) continue;
                findings.Add(new Finding("GhostImage", pid, image,
                    $"PID {pid} działa z pliku, którego nie ma na dysku: {image}"));
            }
        }
        catch {  }
        return findings;
    }

    public sealed record ProcHit(int Pid, string Image, string Detection, string Reason);

    public static List<ProcHit> ScanProcessMasquerades()
    {
        var hits = new List<ProcHit>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id <= 4) continue;
                string image = ImageOf(p.Id);
                if (image.Length == 0 || !seen.Add(image)) continue;
                var mq = Masquerade.CheckProcess(image);
                if (mq != null) hits.Add(new ProcHit(p.Id, image, mq.Detection, mq.Reason));
            }
            catch { }
            finally { p.Dispose(); }
        }
        return hits;
    }
}
