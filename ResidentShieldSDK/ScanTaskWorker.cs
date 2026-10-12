using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Malward.Engine.Core;

namespace Malward.ResidentShield;

public sealed class ScanTaskWorker : BackgroundService
{
    private readonly ShieldConfig _config;

    public const int MaxConcurrentScans = 2;

    private static string DataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "data");
    private static string RequestPath => Path.Combine(DataDir, "scan-request.json");
    private static string CancelAllPath => Path.Combine(DataDir, "scan-cancel");

    private static string ActivePath  => Path.Combine(DataDir, "scan-active");

    private static string LeasePath(string id) => Path.Combine(DataDir, $"scan-active-{id}");
    private static string CancelPathFor(string id) => Path.Combine(DataDir, $"scan-cancel-{id}");
    private static string QueuePath(string id) => Path.Combine(DataDir, $"scan-queue-{id}.json");

    private readonly ConcurrentDictionary<string, byte> _running = new();

    public ScanTaskWorker(ShieldConfig config) => _config = config;

    private sealed record Request(string Id, List<string> Targets, int Parallelism,
                                  string? Profile = null, string? Plan = null);

    private static readonly TimeSpan TrimInterval = TimeSpan.FromMinutes(5);
    private DateTime _lastTrim = DateTime.UtcNow;

    private void TrimWhenIdle()
    {
        if (DateTime.UtcNow - _lastTrim < TrimInterval) return;
        _lastTrim = DateTime.UtcNow;
        try
        {
            if (!_running.IsEmpty) return;
            long released = Malward.Engine.Util.MemoryTrim.AfterLongRun();
            if (released > 8 * 1024 * 1024)
                Log.Info("Shield", $"Idle memory trim released {released / 1048576} MB.");
        }
        catch { }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        SweepOldScanOutputs(null);
        SweepStaleLeases();

        while (!stoppingToken.IsCancellationRequested)
        {
            TrimWhenIdle();
            try
            {
                Ingest();
                StartQueued(stoppingToken);
            }
            catch (Exception ex) { Log.Error("ScanTask", ex.Message); }

            try { await Task.Delay(500, stoppingToken); } catch { break; }
        }
    }

    private void Ingest()
    {
        if (!File.Exists(RequestPath)) return;

        var req = ReadRequest();
        try { File.Delete(RequestPath); } catch { }
        if (req == null) return;

        var queued = new System.Text.Json.Nodes.JsonObject
        {
            ["id"] = req.Id,
            ["parallelism"] = req.Parallelism,
            ["queuedUnix"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };
        var targets = new System.Text.Json.Nodes.JsonArray();
        foreach (var t in req.Targets) targets.Add(t);
        queued["targets"] = targets;
        if (!string.IsNullOrEmpty(req.Profile)) queued["profile"] = req.Profile;
        if (!string.IsNullOrEmpty(req.Plan)) queued["plan"] = req.Plan;

        try
        {
            File.WriteAllText(QueuePath(req.Id), JsonText.Indented(queued));
            TouchScanLease(req.Id);

            var outPath = Path.Combine(DataDir, $"scan-{req.Id}.out");
            if (!File.Exists(outPath))
                File.WriteAllText(outPath, $"SCANQUEUED\tid={req.Id}{Environment.NewLine}");

            Log.Info("ScanTask", $"Scan {req.Id} accepted ({req.Targets.Count} target(s)).");
        }
        catch (Exception ex) { Log.Error("ScanTask", $"Queueing scan {req.Id} failed: {ex.Message}"); }
    }

    private void StartQueued(CancellationToken stoppingToken)
    {
        if (!Directory.Exists(DataDir)) return;

        var waiting = Directory.EnumerateFiles(DataDir, "scan-queue-*.json")
            .OrderBy(p => { try { return new FileInfo(p).CreationTimeUtc; } catch { return DateTime.MaxValue; } })
            .ToList();

        foreach (var path in waiting)
        {
            if (_running.Count >= MaxConcurrentScans) return;

            var req = ReadQueued(path);
            if (req == null) { try { File.Delete(path); } catch { } continue; }
            if (!_running.TryAdd(req.Id, 0)) continue;

            try { File.Delete(path); } catch { }

            _ = Task.Run(async () =>
            {
                try { await RunScanAsync(req, stoppingToken); }
                catch (Exception ex) { Log.Error("ScanTask", $"Scan {req.Id} failed: {ex.Message}"); }
                finally { _running.TryRemove(req.Id, out _); }
            }, CancellationToken.None);
        }
    }

    private static Request? ReadQueued(string path)
    {
        try { return ParseRequest(File.ReadAllText(path)); }
        catch { return null; }
    }

    private static Request? ReadRequest()
    {
        try { return ParseRequest(File.ReadAllText(RequestPath)); }
        catch { return null; }
    }

    private static Request? ParseRequest(string json)
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse(json);
        if (node == null) return null;
        var id = node["id"]?.GetValue<string>() ?? Guid.NewGuid().ToString("N");
        var targets = new List<string>();
        if (node["targets"] is System.Text.Json.Nodes.JsonArray arr)
            foreach (var t in arr)
            {
                var v = t?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(v)) targets.Add(v!);
            }
        int par = node["parallelism"]?.GetValue<int>() ?? 0;
        var profile = node["profile"]?.GetValue<string>();
        var plan = node["plan"]?.GetValue<string>();

        if (targets.Count == 0 && string.IsNullOrEmpty(profile) && string.IsNullOrEmpty(plan))
            return null;
        return new Request(id, targets, par, profile, plan);
    }

    private List<string> BuildArguments(Request req, out string? planFile)
    {
        planFile = null;
        var args = new List<string> { "scan" };

        if (!string.IsNullOrEmpty(req.Plan))
        {
            if (req.Targets.Count > 0) args.Add(req.Targets[0]);
            args.Add("--plan");
            args.Add(req.Plan!);
        }
        else if (!string.IsNullOrEmpty(req.Profile))
        {
            if (req.Targets.Count > 0) args.Add(req.Targets[0]);
            args.Add("--profile");
            args.Add(req.Profile!);
        }
        else if (req.Targets.Count == 1)
        {
            args.Add(req.Targets[0]);
        }
        else
        {
            planFile = Path.Combine(DataDir, $"scan-{req.Id}.plan.json");
            var folders = new System.Text.Json.Nodes.JsonArray();
            foreach (var t in req.Targets)
                folders.Add(new System.Text.Json.Nodes.JsonObject { ["path"] = t });
            var plan = new System.Text.Json.Nodes.JsonObject
            {
                ["name"] = "custom",
                ["folders"] = folders,
            };
            File.WriteAllText(planFile, JsonText.Indented(plan));
            args.Add(req.Targets[0]);
            args.Add("--plan");
            args.Add(planFile);
        }
        args.Add("-vs");
        return args;
    }

    private int CpuBudgetPercent()
    {
        int limit = 50;
        try { limit = Malward.Engine.Config.Settings.Load().ScanCpuLimitPercent; } catch { }
        if (limit <= 0 || limit > 100) limit = 100;

        int share = Math.Max(1, _running.Count);
        return Math.Max(10, limit / share);
    }

    private async Task RunScanAsync(Request req, CancellationToken ct)
    {
        var outPath = Path.Combine(DataDir, $"scan-{req.Id}.out");
        try { File.Delete(CancelPathFor(req.Id)); } catch { }
        try { File.Delete(CancelAllPath); } catch { }

        string? planFile = null;
        try
        {
            var args = BuildArguments(req, out planFile);

            Log.Info("ScanTask", $"Scan {req.Id}: {req.Targets.Count} target(s), result → {Path.GetFileName(outPath)}");

            var scanner = ScanEngine.LocateMalscan(_config.MalscanPath);
            int rc = string.IsNullOrEmpty(scanner)
                ? await RunInsideServiceAsync(req, args, outPath, ct)
                : await RunDetachedAsync(req, scanner, args, outPath, ct);

            try { File.AppendAllText(outPath, $"SCANEND\trc={rc}{Environment.NewLine}"); } catch { }
            Log.Info("ScanTask", $"Scan {req.Id} finished (code {rc}).");
        }
        catch (Exception ex)
        {
            Log.Error("ScanTask", $"Scan {req.Id} failed: {ex.Message}");

            try
            {
                File.AppendAllText(outPath,
                    $"ERROR\tmsg={ex.Message}{Environment.NewLine}SCANEND\trc=2{Environment.NewLine}");
            }
            catch { }
        }
        finally
        {
            if (planFile != null) { try { File.Delete(planFile); } catch { } }
            try { File.Delete(CancelPathFor(req.Id)); } catch { }
            try { File.Delete(LeasePath(req.Id)); } catch { }
            if (_running.Count <= 1)
            {
                try { File.Delete(CancelAllPath); } catch { }
                try { File.Delete(ActivePath); } catch { }

                long released = Malward.Engine.Util.MemoryTrim.AfterLongRun();
                if (released > 0)
                    Log.Info("ScanTask", $"Memory released after the scan: {released / 1048576} MB.");
            }
            _ = CompactWhenReaderIsDoneAsync(outPath, req.Id);
        }
    }

    private async Task<int> RunDetachedAsync(Request req, string scanner, List<string> args,
                                             string outPath, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(scanner)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding  = System.Text.Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";
        psi.Environment["MALWARD_SCAN_CPU_PERCENT"] = CpuBudgetPercent().ToString();
        if (!_config.CloudEnabled) psi.Environment["MALWARD_NO_CLOUD"] = "1";

        using var proc = new Process { StartInfo = psi, EnableRaisingEvents = false };
        proc.Start();
        try { proc.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }

        var reader = Task.Run(async () =>
        {
            using var sw = new StreamWriter(
                new FileStream(outPath, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024),
                System.Text.Encoding.UTF8);
            long lastFlush = Environment.TickCount64;
            string? line;
            while ((line = await proc.StandardOutput.ReadLineAsync()) != null)
            {
                await sw.WriteLineAsync(line);
                if (Environment.TickCount64 - lastFlush >= 200)
                {
                    try { await sw.FlushAsync(); } catch { }
                    lastFlush = Environment.TickCount64;
                }
            }
            try { await sw.FlushAsync(); } catch { }
        }, CancellationToken.None);

        var drainErrors = Task.Run(async () =>
        {
            var text = await proc.StandardError.ReadToEndAsync();
            if (!string.IsNullOrWhiteSpace(text))
                Log.Warn("ScanTask", $"Scan {req.Id} stderr: {text.Trim()}");
        }, CancellationToken.None);

        bool cancelled = false;
        while (!proc.HasExited)
        {
            TouchScanLease(req.Id);
            if (CancelRequested(req.Id))
            {
                cancelled = true;
                try { proc.Kill(entireProcessTree: true); } catch { }
                break;
            }
            if (ct.IsCancellationRequested)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                break;
            }
            try { await Task.Delay(1000, CancellationToken.None); } catch { }
        }

        try { proc.WaitForExit(); } catch { }
        try { await reader; } catch { }
        try { await drainErrors; } catch { }

        if (cancelled) return -1;
        try { return proc.ExitCode; } catch { return 2; }
    }

    private async Task<int> RunInsideServiceAsync(Request req, List<string> args,
                                                  string outPath, CancellationToken ct)
    {
        Log.Warn("ScanTask", "malscan.exe was not found — running the scan inside the service process.");

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);

        TouchScanLease(req.Id);
        using var cancelWatch = new Timer(_ =>
        {
            if (CancelRequested(req.Id)) { try { linked.Cancel(); } catch { } }
            TouchScanLease(req.Id);
        }, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

        return await Task.Run(() =>
        {
            using var sw = new StreamWriter(
                new FileStream(outPath, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024),
                System.Text.Encoding.UTF8);
            sw.AutoFlush = false;

            try { return Malward.Engine.EngineHost.RunScan(args.ToArray(), sw, linked.Token); }
            finally { try { sw.Flush(); } catch { } }
        }, CancellationToken.None);
    }

    private static bool CancelRequested(string id)
    {
        try
        {
            if (File.Exists(CancelPathFor(id))) return true;
            if (!File.Exists(CancelAllPath)) return false;
            var wanted = File.ReadAllText(CancelAllPath).Trim();
            return wanted.Length == 0 || string.Equals(wanted, id, StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private static async Task CompactWhenReaderIsDoneAsync(string outPath, string id)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            if (!File.Exists(outPath)) return;

            if (File.Exists(Path.Combine(DataDir, "keep-scan-trace")))
            {
                Log.Info("ScanTask", $"Report scan-{id}.out left untrimmed (keep-scan-trace present).");
                return;
            }

            long before = new FileInfo(outPath).Length;
            var tmp = outPath + ".compact.tmp";
            int kept = 0, dropped = 0;

            using (var src = new FileStream(outPath, FileMode.Open, FileAccess.Read,
                                            FileShare.ReadWrite | FileShare.Delete))
            using (var r = new StreamReader(src, System.Text.Encoding.UTF8))
            using (var w = new StreamWriter(tmp, false, System.Text.Encoding.UTF8))
            {
                string? line;
                while ((line = await r.ReadLineAsync().ConfigureAwait(false)) != null)
                {
                    if (line.StartsWith("PROGRESS\t", StringComparison.Ordinal)
                     || line.StartsWith("SKIP\t", StringComparison.Ordinal))
                    {
                        dropped++;
                        continue;
                    }
                    await w.WriteLineAsync(line).ConfigureAwait(false);
                    kept++;
                }
            }
            File.Move(tmp, outPath, overwrite: true);
            long after = new FileInfo(outPath).Length;
            Log.Info("ScanTask", $"Report scan-{id}.out trimmed to detections: "
                                 + $"{kept} lines kept, {dropped} dropped, "
                                 + $"{before / 1024} KB -> {after / 1024} KB.");
        }
        catch (Exception ex)
        {
            Log.Warn("ScanTask", $"Could not trim scan-{id}.out: {ex.Message}");
            try { File.Delete(outPath + ".compact.tmp"); } catch { }
        }
    }

    private static void SweepStaleLeases()
    {
        try
        {
            if (!Directory.Exists(DataDir)) return;
            foreach (var f in Directory.EnumerateFiles(DataDir, "scan-active*"))
            {
                try { File.Delete(f); } catch { }
            }
            foreach (var f in Directory.EnumerateFiles(DataDir, "scan-queue-*.json"))
            {
                try { File.Delete(f); } catch { }
            }
            foreach (var f in Directory.EnumerateFiles(DataDir, "scan-cancel*"))
            {
                try { File.Delete(f); } catch { }
            }
        }
        catch { }
    }

    private static void SweepOldScanOutputs(string? currentId)
    {
        try
        {
            if (!Directory.Exists(DataDir)) return;
            var cutoff = DateTime.UtcNow - TimeSpan.FromDays(7);
            foreach (var f in Directory.EnumerateFiles(DataDir, "scan-*.out"))
            {
                var name = Path.GetFileNameWithoutExtension(f);
                if (currentId != null && name.Equals("scan-" + currentId, StringComparison.Ordinal)) continue;
                try
                {
                    var fi = new FileInfo(f);

                    if (fi.LastWriteTimeUtc > cutoff) continue;
                    fi.Delete();
                    Log.Info("ScanTask", $"Removed old scan output {fi.Name} ({fi.Length / 1024} KB).");
                }
                catch { }
            }
            foreach (var f in Directory.EnumerateFiles(DataDir, "scan-*.out.compact.tmp"))
            {
                try { File.Delete(f); } catch { }
            }
        }
        catch { }
    }

    private static void TouchScanLease(string id)
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            File.WriteAllText(LeasePath(id), id);
            File.WriteAllText(ActivePath, id);
        }
        catch { }
    }
}
