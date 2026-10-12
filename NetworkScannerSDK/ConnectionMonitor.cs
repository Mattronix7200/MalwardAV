using System.Diagnostics;

namespace Malward.NetworkScanner;

public sealed class ConnectionMonitor
{
    private readonly NetworkConfig _config;
    private readonly ActivityReporter _activity;
    private readonly BlockPageServer? _blockPage;

    private readonly BotIpBlocklist _botIps;

    private readonly Dictionary<string, DateTime> _handled = new(StringComparer.Ordinal);
    private static readonly TimeSpan ReAlertAfter = TimeSpan.FromMinutes(30);
    private const int PollMs = 3000;

    private Thread? _thread;
    private volatile bool _running;

    public ConnectionMonitor(NetworkConfig config, ActivityReporter activity, BlockPageServer? blockPage,
                             BotIpBlocklist? botIps = null)
    {
        _config    = config;
        _activity  = activity;
        _blockPage = blockPage;
        _botIps    = botIps ?? new BotIpBlocklist(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "vps-ex01.vdeb"));
    }

    public void Start()
    {
        _running = true;
        _thread = new Thread(Loop)
        {
            IsBackground = true,
            Name = "Net-ConnMon",
            Priority = ThreadPriority.BelowNormal,
        };
        _thread.Start();
        Log.Info("ConnMon", "Direct-IP (C2) connection monitor started.");
    }

    public void Stop()
    {
        _running = false;
        try { _thread?.Join(2000); } catch { }
    }

    private void Loop()
    {
        while (_running)
        {
            try { Scan(); } catch (Exception ex) { Log.Warn("ConnMon", $"scan error: {ex.Message}"); }

            for (int slept = 0; slept < PollMs && _running; slept += 100)
                try { Thread.Sleep(100); } catch { }
        }
    }

    private void Scan()
    {
        List<ProcessResolver.TcpConn> conns;
        try { conns = ProcessResolver.SnapshotTcpConnections(); }
        catch { return; }

        var now = DateTime.UtcNow;
        foreach (var c in conns)
        {
            bool badIp = !_botIps.IsEmpty && _botIps.Contains(c.RemoteIp);

            string? procImg = QueryImagePath(c.Pid);
            string? malwareName = null;
            if (!badIp && IsUntrustedPath(procImg))
                malwareName = CheckImageMalware(procImg);
            bool malwareProc = malwareName != null;

            if (!badIp && !malwareProc) continue;

            string dedupKey = badIp ? c.RemoteIp : ("proc:" + (procImg ?? c.Pid.ToString()));
            lock (_handled)
            {
                if (_handled.TryGetValue(dedupKey, out var last) && (now - last) < ReAlertAfter) continue;
                _handled[dedupKey] = now;
                if (_handled.Count > 4096) PruneHandled(now);
            }

            string? proc = ProcessResolver.GetProcessName(c.Pid);
            string label = $"{c.RemoteIp}:{c.RemotePort}";

            string det = badIp ? "MaliciousIP@" + MapConnShorthand(proc) : malwareName!;

            try { _activity.ReportBlock(label, detection: det, source: "dangerous-ip", process: proc); } catch { }

            SeverConnection(c);
            if (malwareProc)
            {
                try { using var p = Process.GetProcessById(c.Pid); p.Kill(entireProcessTree: true); } catch { }
            }
            else
            {
                TryKillFetchTool(c.Pid, proc);
            }
            Log.Alert("ConnMon", $"BLOCK [{(badIp ? "dangerous-ip" : "malware-proc")}] {label} " +
                                 $"({proc ?? "?"}, pid {c.Pid}) → connection severed (no firewall rule)");

            if (badIp) RaiseDangerousConnection(c, procImg, proc, now);
        }
    }

    private void RaiseDangerousConnection(ProcessResolver.TcpConn c, string? image, string? proc,
                                          DateTime now)
    {
        if (string.IsNullOrEmpty(image)) return;
        if (!DangerousConnectionBus.HasHandler) return;

        lock (_handled)
        {
            string key = "danger:" + image.ToLowerInvariant();
            if (_handled.TryGetValue(key, out var last) && (now - last) < ReAlertAfter) return;
            _handled[key] = now;
        }

        DangerousConnectionBus.Raise(new DangerousConnection(
            c.Pid, proc ?? Path.GetFileNameWithoutExtension(image), image!,
            c.RemoteIp, c.RemotePort, "Behaviour.DangerousConnections"));
    }

    private static readonly HashSet<string> FetchTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "curl", "curl.exe", "wget", "wget.exe",
        "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe",
    };

    private static string MapConnShorthand(string? proc)
    {
        if (string.IsNullOrEmpty(proc)) return "GenericConn";
        string n = proc.Contains('\\') ? Path.GetFileName(proc) : proc;
        if (n.StartsWith("elevated:", StringComparison.OrdinalIgnoreCase)) return "SystemConn";
        if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) n = n[..^4];
        switch (n.ToLowerInvariant())
        {
            case "powershell": case "pwsh":            return "PowershellConn";
            case "cmd":                                return "BatchConn";
            case "svchost": case "services":
            case "system": case "lsass": case "wininit": return "SystemConn";
            case "python": case "pythonw": case "py":  return "PythonConn";
            case "curl":                               return "CurlConn";
            case "wget":                               return "WgetConn";
            case "certutil":                           return "CertutilConn";
            case "bitsadmin":                          return "BitsConn";
            case "mshta":                              return "MshtaConn";
            case "wscript": case "cscript":            return "ScriptConn";
            case "rundll32":                           return "Rundll32Conn";
            case "regsvr32":                           return "Regsvr32Conn";
            default:
                if (n.Length == 0) return "GenericConn";
                return char.ToUpperInvariant(n[0]) + n[1..].ToLowerInvariant() + "Conn";
        }
    }

    private static void TryKillFetchTool(int pid, string? proc)
    {
        if (string.IsNullOrEmpty(proc)) return;
        string name = proc.Contains('\\') ? Path.GetFileName(proc) : proc;
        if (!FetchTools.Contains(name)) return;
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
            Log.Alert("ConnMon", $"Connection severed: terminated {name} (pid {pid}) — MaliciousIP.");
        }
        catch {  }
    }

    private void PruneHandled(DateTime now)
    {
        var stale = _handled.Where(kv => (now - kv.Value) >= ReAlertAfter).Select(kv => kv.Key).ToList();
        foreach (var k in stale) _handled.Remove(k);
    }

    private static bool SeverConnection(ProcessResolver.TcpConn c)
    {
        if (c.RemoteAddrRaw == 0) return false;
        var row = new MIB_TCPROW
        {
            dwState      = MIB_TCP_STATE_DELETE_TCB,
            dwLocalAddr  = c.LocalAddrRaw,
            dwLocalPort  = c.LocalPortRaw,
            dwRemoteAddr = c.RemoteAddrRaw,
            dwRemotePort = c.RemotePortRaw,
        };
        try { return SetTcpEntry(ref row) == 0; }
        catch { return false; }
    }

    private const uint MIB_TCP_STATE_DELETE_TCB = 12;

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort;
    }

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll")]
    private static extern int SetTcpEntry(ref MIB_TCPROW row);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> _imgVerdict =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _imgInflight =
        new(StringComparer.OrdinalIgnoreCase);

    private static string QueryImagePath(int pid)
    {
        if (pid <= 4) return "";
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return "";
        try
        {
            var sb = new System.Text.StringBuilder(1024);
            int len = sb.Capacity;
            return QueryFullProcessImageNameW(h, 0, sb, ref len) ? sb.ToString() : "";
        }
        finally { CloseHandle(h); }
    }

    private static bool IsUntrustedPath(string? img)
    {
        if (string.IsNullOrEmpty(img) || !img.Contains('\\')) return false;
        string l = img.ToLowerInvariant();
        if (l.Contains(@"\windows\") || l.Contains(@"\program files\")
            || l.Contains(@"\program files (x86)\")) return false;
        return true;
    }

    private string? CheckImageMalware(string? img)
    {
        if (string.IsNullOrEmpty(img)) return null;
        if (_imgVerdict.TryGetValue(img, out var v)) return v;
        if (_imgInflight.TryAdd(img, 1))
            _ = Task.Run(() =>
            {
                string? name = RunMalscanCheck(img);
                _imgVerdict[img] = name;
                _imgInflight.TryRemove(img, out _);
            });
        return null;
    }

    private static string? _malscanPath;
    private static bool _malscanResolved;
    private static string? RunMalscanCheck(string img)
    {
        try
        {
            if (!_malscanResolved)
            {
                _malscanResolved = true;
                var cand = Path.Combine(AppContext.BaseDirectory, "malscan.exe");
                _malscanPath = File.Exists(cand) ? cand : null;
            }
            if (!File.Exists(img)) return null;

            var pipe = SharedPipeline();
            if (pipe == null) return null;
            var r = pipe.ScanRealtime(img);
            return r.Verdict == Malward.Engine.Core.Verdict.Malware
                ? (string.IsNullOrEmpty(r.Detection) ? "Malware" : r.Detection)
                : null;
        }
        catch { return null; }
    }

    private static Malward.Engine.Core.ScanPipeline? SharedPipeline() => SharedScanPipeline.Get();

    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, int flags, System.Text.StringBuilder lpExeName, ref int size);
}
