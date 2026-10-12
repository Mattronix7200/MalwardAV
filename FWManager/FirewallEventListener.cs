using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Xml;

namespace Malward.FWManager;

public sealed class BlockedConnectionInfo
{
    public string ProcessId { get; set; } = "";
    public string AppPath { get; set; } = "";
    public string AppName => string.IsNullOrEmpty(AppPath) ? "(unknown)" : Path.GetFileName(AppPath);
    public string ServiceName { get; set; } = "";
    public string Direction { get; set; } = "";       
    public string RemoteAddress { get; set; } = "";
    public string RemotePort { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string LayerId { get; set; } = "";
    public string FilterId { get; set; } = "";
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

public sealed class FirewallEventListener : IDisposable
{
    private const int BlockedConnectionEventId = 5157;

    private const string WfpAuditSubcategoryGuid = "{0CCE9226-69AE-11D9-BED3-505054503030}";

    private static readonly HashSet<string> OutboundLayers = new(StringComparer.Ordinal) { "48", "50" };
    private static readonly HashSet<string> InboundLayers  = new(StringComparer.Ordinal) { "44", "46" };

    private EventLogWatcher? _watcher;
    private readonly Action<string>? _log;

    private readonly ConcurrentDictionary<string, DateTime> _seen = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, DateTime> _snoozed = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _dedupWindow = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, byte> _decidedApps = new(StringComparer.OrdinalIgnoreCase);

    public string Granularity { get; set; } = "app";

    public void MarkAppDecided(string appPath)
    {
        if (!string.IsNullOrEmpty(appPath)) _decidedApps[appPath] = 1;
    }

    public event Action<BlockedConnectionInfo>? BlockedConnectionDetected;

    public FirewallEventListener(Action<string>? log = null) { _log = log; }

    public bool Start()
    {
        if (_watcher != null) { _watcher.Enabled = true; _log?.Invoke("[FwListener] already started — re-enabled"); return true; }
        try
        {
            EnableWfpAuditing();

            VerifyAuditState();

            var query = new EventLogQuery(
                "Security", PathType.LogName,
                $"*[System[(EventID={BlockedConnectionEventId})]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecord;
            _watcher.Enabled = true;
            _log?.Invoke("[FwListener] started OK — listening for Event 5157 on the Security log");

            _ = Task.Run(async () =>
            {
                await Task.Delay(10_000);
                _log?.Invoke($"[FwListener] +10s status: events_received={_eventCount} fired={_firedCount}");
                if (_eventCount == 0)
                {
                    _log?.Invoke("[FwListener] WARNING: no events for 10 s.");
                    _log?.Invoke("[FwListener]   Possible causes:");
                    _log?.Invoke("[FwListener]   1) auditpol lacks permissions (GPO override) — check the auditpol /get stdout above");
                    _log?.Invoke("[FwListener]   2) master-block mode is not active (check netsh advfirewall show allprofiles state)");
                    _log?.Invoke("[FwListener]   3) no network traffic to block (run e.g. ping 1.1.1.1)");
                }
            });
            return true;
        }
        catch (EventLogException ex)
        {
            _log?.Invoke($"[FwListener] EventLog access denied: {ex.GetType().Name}: {ex.Message}");
            _log?.Invoke("[FwListener] Requires Administrator privileges and SeAuditPrivilege.");
            return false;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[FwListener] start failed: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
            return false;
        }
    }

    private void VerifyAuditState()
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe",
                $"/get /subcategory:\"{WfpAuditSubcategoryGuid}\"")
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            string so = p?.StandardOutput.ReadToEnd() ?? "";
            string se = p?.StandardError.ReadToEnd() ?? "";
            p?.WaitForExit(2000);
            int code = p?.ExitCode ?? -1;
            _log?.Invoke($"[FwListener] auditpol /get → exit={code}");
            if (!string.IsNullOrWhiteSpace(so)) _log?.Invoke("[FwListener] stdout: " + so.Trim());
            if (!string.IsNullOrWhiteSpace(se)) _log?.Invoke("[FwListener] stderr: " + se.Trim());
        }
        catch (Exception ex) { _log?.Invoke("[FwListener] verify failed: " + ex.Message); }
    }

    public void Stop()
    {
        try
        {
            if (_watcher != null)
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= OnEventRecord;
                _watcher.Dispose();
                _watcher = null;
            }
            DisableWfpAuditing();
            _seen.Clear();
            _snoozed.Clear();
            _log?.Invoke("[FwListener] stopped");
        }
        catch (Exception ex) { _log?.Invoke("[FwListener] stop error: " + ex.Message); }
    }

    public void Dispose() => Stop();

    public void Snooze(string appPath, string direction, TimeSpan duration)
    {
        if (string.IsNullOrEmpty(appPath)) return;
        _snoozed[$"{appPath}|{direction}"] = DateTime.UtcNow.Add(duration);
    }

    private void EnableWfpAuditing()
    {
        RunAuditPol($"/set /subcategory:\"{WfpAuditSubcategoryGuid}\" /success:disable /failure:enable");
    }

    private void DisableWfpAuditing()
    {
        RunAuditPol($"/set /subcategory:\"{WfpAuditSubcategoryGuid}\" /success:disable /failure:disable");
    }

    private void RunAuditPol(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe", args)
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            string so = p?.StandardOutput.ReadToEnd() ?? "";
            string se = p?.StandardError.ReadToEnd() ?? "";
            p?.WaitForExit(2000);
            int code = p?.ExitCode ?? -1;
            _log?.Invoke($"[FwListener] auditpol {args} → exit={code}");
            if (!string.IsNullOrWhiteSpace(so)) _log?.Invoke("[FwListener] stdout: " + so.Trim());
            if (!string.IsNullOrWhiteSpace(se)) _log?.Invoke("[FwListener] stderr: " + se.Trim());
        }
        catch (Exception ex) { _log?.Invoke("[FwListener] auditpol exec failed: " + ex.Message); }
    }

    private long _eventCount;
    private long _firedCount;

    private void OnEventRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) { _log?.Invoke("[FwListener] event: EventRecord null"); return; }
        long n = Interlocked.Increment(ref _eventCount);
        try
        {
            string xml = e.EventRecord.ToXml();

            if (n == 1)
            {
                _log?.Invoke("[FwListener] === RAW XML of the first event (for parser diagnostics) ===");
                foreach (var ln in xml.Split('\n'))
                    _log?.Invoke("[FwListener]   " + ln.TrimEnd('\r'));
                _log?.Invoke("[FwListener] === END OF RAW XML ===");
            }
            var info = ParseEvent(xml, out string? skipReason);
            if (info == null)
            {
                _log?.Invoke($"[FwListener] event #{n}: skipped — {skipReason}");
                return;
            }
            if (!ShouldFire(info, out string? notFireReason))
            {
                _log?.Invoke($"[FwListener] event #{n}: {info.AppName} {info.Direction} → {info.RemoteAddress}:{info.RemotePort} — filtered ({notFireReason})");
                return;
            }
            Interlocked.Increment(ref _firedCount);
            _log?.Invoke($"[FwListener] event #{n} → FIRE: {info.AppName} {info.Direction} → {info.RemoteAddress}:{info.RemotePort}");
            try { BlockedConnectionDetected?.Invoke(info); }
            catch (Exception ex) { _log?.Invoke("[FwListener] consumer threw: " + ex.Message); }
        }
        catch (Exception ex) { _log?.Invoke($"[FwListener] event #{n} parse error: {ex.GetType().Name}: {ex.Message}"); }
    }

    private static BlockedConnectionInfo? ParseEvent(string xml, out string? skipReason)
    {
        skipReason = null;
        string appPath = NormalizePath(GetXmlData(xml, "Application"));
        if (string.IsNullOrEmpty(appPath)) { skipReason = "AppPath empty"; return null; }

        string dirCode = GetXmlData(xml, "Direction");
        string direction = dirCode.Contains("14593") ? "OUT"
                         : dirCode.Contains("14592") ? "IN" : "?";

        string src = GetXmlData(xml, "SourceAddress");
        string dst = GetXmlData(xml, "DestAddress");
        string srcPort = GetXmlData(xml, "SourcePort");
        string dstPort = GetXmlData(xml, "DestPort");
        string remoteAddr = direction == "IN" ? src : dst;
        string remotePort = direction == "IN" ? srcPort : dstPort;
        if (string.IsNullOrEmpty(remoteAddr)) remoteAddr = !string.IsNullOrEmpty(dst) ? dst : src;
        if (string.IsNullOrEmpty(remotePort)) remotePort = !string.IsNullOrEmpty(dstPort) ? dstPort : srcPort;

        var info = new BlockedConnectionInfo
        {
            AppPath       = appPath,
            ProcessId     = GetXmlData(xml, "ProcessID"),
            ServiceName   = GetXmlData(xml, "ServiceName"),
            RemoteAddress = remoteAddr,
            RemotePort    = remotePort,
            Protocol      = GetXmlData(xml, "Protocol"),
            LayerId       = GetXmlData(xml, "LayerRTID"),
            FilterId      = GetXmlData(xml, "FilterRTID"),
            Direction     = direction,
        };
        if (string.IsNullOrEmpty(info.RemoteAddress)) { skipReason = "RemoteAddress empty"; return null; }

        if (IsNoise(info.RemoteAddress)) { skipReason = $"noise (remote={info.RemoteAddress})"; return null; }
        if (info.ServiceName == "N/A") info.ServiceName = "";

        var fname = Path.GetFileName(info.AppPath);
        if (fname.Equals("malward.exe", StringComparison.OrdinalIgnoreCase) ||
            fname.Equals("netmonitor.exe", StringComparison.OrdinalIgnoreCase) ||
            fname.Equals("mwshield.exe", StringComparison.OrdinalIgnoreCase) ||
            fname.Equals("malscan.exe", StringComparison.OrdinalIgnoreCase))
        { skipReason = "own process"; return null; }

        return info;
    }

    private bool ShouldFire(BlockedConnectionInfo info, out string? reason)
    {
        reason = null;
        bool appMode = !string.Equals(Granularity, "ip", StringComparison.OrdinalIgnoreCase);

        if (appMode && _decidedApps.ContainsKey(info.AppPath))
        { reason = "app already decided"; return false; }

        string snoozeKey = appMode ? info.AppPath : $"{info.AppPath}|{info.Direction}";
        if (_snoozed.TryGetValue(snoozeKey, out var until))
        {
            if (DateTime.UtcNow < until) { reason = "snoozed"; return false; }
            _snoozed.TryRemove(snoozeKey, out _);
        }

        string dedupKey = appMode ? info.AppPath : $"{info.AppPath}|{info.RemoteAddress}";
        var now = DateTime.UtcNow;
        if (_seen.TryGetValue(dedupKey, out var seenUntil) && now < seenUntil)
        { reason = "deduped (same host in last 30s)"; return false; }
        _seen[dedupKey] = now.Add(_dedupWindow);

        if (_seen.Count > 200) PruneExpired();
        return true;
    }

    private void PruneExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var k in _seen.Keys)
        {
            if (_seen.TryGetValue(k, out var t) && now > t) _seen.TryRemove(k, out _);
        }
    }

    private static bool IsNoise(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return true;
        if (ip == "255.255.255.255") return true;
        if (ip.StartsWith("224.") || ip.StartsWith("239.")) return true;          
        if (ip.StartsWith("ff", StringComparison.OrdinalIgnoreCase)) return true; 
        if (ip == "0.0.0.0" || ip == "::") return true;
        return false;
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        if (!path.StartsWith("\\Device\\HarddiskVolume", StringComparison.OrdinalIgnoreCase))
            return path;
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                string letter = d.Name.TrimEnd('\\');           
                string? device = QueryDosDevicePath(letter);
                if (string.IsNullOrEmpty(device)) continue;
                if (path.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
                    return letter + path.Substring(device.Length);
            }
        }
        catch { }
        return path;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint ucchMax);

    private static string? QueryDosDevicePath(string driveLetter)
    {
        var sb = new System.Text.StringBuilder(260);
        uint n = QueryDosDevice(driveLetter, sb, 260);
        return n == 0 ? null : sb.ToString();
    }

    private static string GetXmlData(string xml, string name)
    {
        try
        {
            using var sr = new StringReader(xml);
            using var rdr = XmlReader.Create(sr, new XmlReaderSettings { ConformanceLevel = ConformanceLevel.Fragment });
            while (rdr.Read())
            {
                if (rdr.NodeType == XmlNodeType.Element && rdr.LocalName == "Data"
                    && rdr.GetAttribute("Name") == name)
                {
                    if (rdr.IsEmptyElement) return "";

                    return rdr.ReadElementContentAsString() ?? "";
                }
            }
        }
        catch { }
        return "";
    }
}
