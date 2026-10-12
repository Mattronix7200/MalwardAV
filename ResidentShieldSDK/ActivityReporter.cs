using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Malward.ResidentShield;

public sealed class ActivityReporter : IDisposable
{
    private static readonly string OutPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-activity.json");

    private static readonly string WinDir =
        (Environment.GetFolderPath(Environment.SpecialFolder.Windows) ?? @"C:\Windows").TrimEnd('\\');
    private static readonly string ProgFilesWinApps =
        (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) ?? @"C:\Program Files").TrimEnd('\\')
        + @"\WindowsApps";

    private static bool IsSystemNoise(string path)
    {
        if (string.IsNullOrEmpty(path)) return true;

        if (path.IndexOf('\\') < 0 && path.IndexOf('/') < 0) return true;
        return path.StartsWith(WinDir + "\\", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(ProgFilesWinApps + "\\", StringComparison.OrdinalIgnoreCase)

            || path.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase)
            || path.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly HashSet<string> MalwardProcs = new(StringComparer.OrdinalIgnoreCase)
    {
        "malward", "malscan", "mwshield", "rsmonitor", "netmonitor", "bkmonitor",
        "heurscanner", "mla_scanner", "cehelper", "hcodebox",
        "malwardctx", "7z", "7za",
    };

    private static readonly HashSet<string> SearchProcs = new(StringComparer.OrdinalIgnoreCase)
    { "searchindexer", "searchprotocolhost", "searchfilterhost" };

    private readonly int _cpuCount = Environment.ProcessorCount;
    private volatile string _currentFile = "";
    private long _scannedTotal;
    private long _blockedTotal;
    private long _cloudTotal;

    private readonly ConcurrentQueue<RecentItem> _recent = new();
    private const int RecentMax = 25;

    private readonly Dictionary<int, (TimeSpan cpu, DateTime at)> _procCpu = new();

    private (long mal, long search, long os, DateTime at) _diskPrev;

    private Thread? _thread;
    private volatile bool _running;

    public sealed record RecentItem(string Path, string Verdict, string? Detection, long Ts);

    public void SetCurrentFile(string path) => _currentFile = path ?? "";

    public void ReportHips(string ruleId, string ruleName, string procName, string? procPath,
                           string description, string action,
                           System.Text.Json.Nodes.JsonObject? undo = null,
                           System.Text.Json.Nodes.JsonObject? fix = null)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data");
            Directory.CreateDirectory(dir);

            var rec = new System.Text.Json.Nodes.JsonObject
            {
                ["ts"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                ["rule"] = ruleId,
                ["name"] = ruleName,
                ["process"] = procName,
                ["path"] = procPath ?? "",
                ["detail"] = description,
                ["action"] = action,
            };
            if (undo != null) rec["undo"] = undo;

            if (fix != null) rec["fix"] = fix;
            var line = JsonText.Compact(rec);

            var file = Path.Combine(dir, "hips-events.jsonl");
            try
            {
                if (File.Exists(file) && new FileInfo(file).Length > 512 * 1024)
                {
                    var keep = File.ReadAllLines(file);
                    File.WriteAllLines(file, keep.Skip(Math.Max(0, keep.Length - 500)));
                }
            }
            catch { }
            File.AppendAllText(file, line + Environment.NewLine, System.Text.Encoding.UTF8);
        }
        catch (Exception ex)
        {
            Log.Warn("HIPS", $"Failed to save the event: {ex.GetType().Name}: {ex.Message}");
        }
    }

    public void ReportScanned(string path, string verdict, string? detection,
                              bool cloudChecked = false, bool showInFeed = true)
    {
        Interlocked.Increment(ref _scannedTotal);
        bool threat = string.Equals(verdict, "Threat", StringComparison.OrdinalIgnoreCase);
        if (threat)
            Interlocked.Increment(ref _blockedTotal);
        if (cloudChecked)
            Interlocked.Increment(ref _cloudTotal);

        if (threat || (showInFeed && !IsSystemNoise(path)))
            PushRecent(path, verdict, detection);
    }

    private void PushRecent(string path, string verdict, string? detection)
    {
        _recent.Enqueue(new RecentItem(path, verdict, detection,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        while (_recent.Count > RecentMax) _recent.TryDequeue(out _);
    }

    public void ReportDownloadScanned(string path, string verdict, string? detection)
    {
        Interlocked.Increment(ref _scannedTotal);
        if (string.Equals(verdict, "Threat", StringComparison.OrdinalIgnoreCase))
            Interlocked.Increment(ref _blockedTotal);
        PushRecent(path, verdict, detection);
    }

    public void Start()
    {
        _running = true;
        _thread = new Thread(Loop)
        { Name = "ActivityReporter", IsBackground = true, Priority = ThreadPriority.BelowNormal };
        _thread.Start();
    }

    public void Stop()
    {
        _running = false;
        try { _thread?.Join(TimeSpan.FromSeconds(2)); } catch { }

        try { if (File.Exists(OutPath)) File.Delete(OutPath); } catch { }
    }

    private void Loop()
    {
        SampleCpuBaseline();
        _diskPrev = (0, 0, 0, default);

        while (_running)
        {
            try { WriteSnapshot(); }
            catch {  }
            for (int i = 0; i < 10 && _running; i++) Thread.Sleep(100);
        }
    }

    private void SampleCpuBaseline()
    {
        foreach (var p in SafeProcesses())
        {
            try { _procCpu[p.Id] = (p.TotalProcessorTime, DateTime.UtcNow); } catch { }
            finally { p.Dispose(); }
        }
    }

    private void WriteSnapshot()
    {
        double cpuMalward = 0, cpuSearch = 0, cpuOs = 0;
        long ramMalward = 0, ramSearch = 0, ramOs = 0;

        long ioMal = 0, ioSearch = 0, ioOs = 0;

        var now = DateTime.UtcNow;
        var seen = new HashSet<int>();

        foreach (var p in SafeProcesses())
        {
            try
            {
                int id = p.Id;
                seen.Add(id);
                string name = SafeName(p);
                var cat = Categorize(name);

                TimeSpan cpuNow;
                try { cpuNow = p.TotalProcessorTime; } catch { continue; }
                double cpuPct = 0;
                if (_procCpu.TryGetValue(id, out var prev))
                {
                    double dtMs = (now - prev.at).TotalMilliseconds;
                    if (dtMs > 0)
                        cpuPct = (cpuNow - prev.cpu).TotalMilliseconds / (dtMs * _cpuCount) * 100.0;
                }
                _procCpu[id] = (cpuNow, now);
                if (cpuPct < 0) cpuPct = 0;

                long ram = 0;
                try { ram = p.WorkingSet64; } catch { }

                long io = ProcessIoBytes(p);

                switch (cat)
                {
                    case Cat.Malward: cpuMalward += cpuPct; ramMalward += ram; ioMal    += io; break;
                    case Cat.Search:  cpuSearch  += cpuPct; ramSearch  += ram; ioSearch += io; break;
                    default:          cpuOs      += cpuPct; ramOs      += ram; ioOs     += io; break;
                }
            }
            catch { }
            finally { p.Dispose(); }
        }

        foreach (var dead in _procCpu.Keys.Where(k => !seen.Contains(k)).ToList())
            _procCpu.Remove(dead);

        double dt = (now - _diskPrev.at).TotalSeconds;
        double diskMalBps = 0, diskSearchBps = 0, diskOsBps = 0;
        if (dt > 0 && _diskPrev.at != default)
        {
            diskMalBps    = Math.Max(0, (ioMal    - _diskPrev.mal)    / dt);
            diskSearchBps = Math.Max(0, (ioSearch - _diskPrev.search) / dt);
            diskOsBps     = Math.Max(0, (ioOs     - _diskPrev.os)     / dt);
        }
        _diskPrev = (ioMal, ioSearch, ioOs, now);

        long totalRam = Math.Max(1, GetTotalRamBytes());

        var snapshot = new
        {
            ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            cpu = new
            {
                malward = Clamp(cpuMalward),
                search  = Clamp(cpuSearch),
                os      = Clamp(cpuOs),
            },
            ram = new
            {
                malward = Pct(ramMalward, totalRam),
                search  = Pct(ramSearch, totalRam),
                os      = Pct(ramOs, totalRam),
            },
            disk = new { malwardBps = diskMalBps, searchBps = diskSearchBps, osBps = diskOsBps },
            net  = SampleNet(),
            current = _currentFile,
            scanned = Interlocked.Read(ref _scannedTotal),
            blocked = Interlocked.Read(ref _blockedTotal),

            cloud = Interlocked.Read(ref _cloudTotal),
            detections = Interlocked.Read(ref _blockedTotal),
            recent = _recent.Reverse().Take(RecentMax).Select(r => new
            {
                path = r.Path, verdict = r.Verdict, detection = r.Detection, ts = r.Ts
            }).ToList(),
        };

        var json = JsonSerializer.Serialize(snapshot);
        AtomicWrite(OutPath, json);
    }

    private enum Cat { Malward, Search, Os }
    private static Cat Categorize(string name)
    {
        if (MalwardProcs.Contains(name)) return Cat.Malward;
        if (SearchProcs.Contains(name)) return Cat.Search;
        return Cat.Os;
    }

    private (long read, long write, DateTime at) _netPrev;
    private object SampleNet()
    {
        long total = 0;
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                var s = ni.GetIPv4Statistics();
                total += s.BytesReceived + s.BytesSent;
            }
        }
        catch { }

        var now = DateTime.UtcNow;
        double bps = 0;
        double dt = (now - _netPrev.at).TotalSeconds;
        if (dt > 0 && _netPrev.read > 0)
            bps = Math.Max(0, (total - _netPrev.read) / dt);
        _netPrev = (total, 0, now);
        return new { bps };
    }

    private static IEnumerable<Process> SafeProcesses()
    {
        Process[] arr;
        try { arr = Process.GetProcesses(); } catch { yield break; }
        foreach (var p in arr) yield return p;
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return ""; }
    }

    private static long ProcessIoBytes(Process p)
    {
        IntPtr h = IntPtr.Zero;
        try
        {
            h = OpenProcess(0x1000, false, p.Id);
            if (h == IntPtr.Zero) return 0;
            if (GetProcessIoCounters(h, out IO_COUNTERS c))
                return (long)(c.ReadTransferCount + c.WriteTransferCount);
        }
        catch { }
        finally { if (h != IntPtr.Zero) CloseHandle(h); }
        return 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS counters);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    private static long GetTotalRamBytes()
    {
        try
        {
            var gcInfo = GC.GetGCMemoryInfo();
            if (gcInfo.TotalAvailableMemoryBytes > 0) return gcInfo.TotalAvailableMemoryBytes;
        }
        catch { }
        return 16L * 1024 * 1024 * 1024;
    }

    private static double Clamp(double v) => Math.Round(Math.Clamp(v, 0, 100), 1);
    private static double Pct(long part, long total) => Math.Round(Math.Clamp(part * 100.0 / total, 0, 100), 1);

    private static void AtomicWrite(string path, string content)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        try { File.Move(tmp, path, overwrite: true); }
        catch { try { File.Copy(tmp, path, overwrite: true); File.Delete(tmp); } catch { } }
    }

    public void Dispose() => Stop();
}
