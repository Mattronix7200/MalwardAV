using System.Diagnostics;
using System.Runtime.Versioning;
using Malward.Engine.Config;
using Malward.Engine.Core;
using Malward.Engine.Util;

namespace Malward.Engine.Memory;

[SupportedOSPlatform("windows")]
public sealed class ProcessScanner
{
    private readonly Settings _settings;

    private static readonly HashSet<string> OwnProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
        { "malscan", "malward", "heurscanner", "hcodebox",
          "mwshield", "rsmonitor", "netmonitor", "bkmonitor", "mwupdate" };

    public ProcessScanner(Settings settings) { _settings = settings; }

    public IEnumerable<DetectionResult> ScanRunningProcesses(ScanPipeline pipeline, StatusBar? status = null)
    {
        var targets = new List<(string path, List<int> pids)>();
        var seen = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in Process.GetProcesses())
        {
            string? path = null;
            int pid = 0;
            bool eligible = false;
            try
            {
                pid = p.Id;
                if (ProcessOwnership.IsScannableProcess(p))
                {
                    try { if (OwnProcessNames.Contains(p.ProcessName)) continue; }
                    catch {  }

                    path = ProcessOwnership.TryGetImagePath(p);
                    eligible = !string.IsNullOrEmpty(path);
                }
            }
            catch {  }
            finally { p.Dispose(); }

            if (!eligible || string.IsNullOrEmpty(path)) continue;
            if (seen.TryGetValue(path!, out var pids)) { pids.Add(pid); continue; }
            pids = new List<int> { pid };
            seen[path!] = pids;
            targets.Add((path!, pids));
        }

        bool ignoreWhitelist = !_settings.MemoryScanCheckWhitelist;
        status?.SetTotal(targets.Count);
        foreach (var (path, pids) in targets)
        {
            int pid = pids[0];
            bool systemowy = false;
            status?.State("skan procesu", path);
            DetectionResult r;
            try { r = pipeline.ScanProcessImage(path, ignoreWhitelist); }
            catch (Exception ex)
            {
                r = new DetectionResult(path, "", Verdict.Error, null, "Memory:error", 0, 0, ex.Message);
            }

            if (r.Verdict == Verdict.Malware)
            {
                if (ProcessOwnership.IsSystemPath(path))
                {
                    systemowy = true;
                }
                else
                {
                    foreach (var victimPid in pids)
                    {
                        try
                        {
                            using var victim = Process.GetProcessById(victimPid);
                            victim.Kill(entireProcessTree: true);
                            victim.WaitForExit(3000);
                        }
                        catch {  }
                    }
                }
            }
            status?.Step(path);
            var pidLabel = pids.Count == 1 ? pid.ToString() : $"{pid}+{pids.Count - 1}";
            if (systemowy) pidLabel += ", systemowy - nie zatrzymano";
            yield return r with { Source = $"Memory(pid={pidLabel}):{r.Source}" };
        }
    }
}
