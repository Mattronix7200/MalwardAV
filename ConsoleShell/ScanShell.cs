using Malward.Engine.Config;
using Malward.Engine.Core;
using Malward.Engine.Repair;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

/// <summary>The /scan shell: builds settings from switches only, never from the GUI configuration.
/// Only the local signature database and the file whitelist are on by default; every other layer
/// has to be asked for, so each switch on the command line actually changes something.</summary>
public static class ScanShell
{
    private enum FixMode { Quarantine, Delete, Ask, Ignore }

    /// <summary>A size no real file reaches, used where the engine wants a number but the user
    /// asked for no limit at all.</summary>
    private const int NoLimitMb = 1_000_000;

    private const int MaxNesting = 12;

    private static string Limit(int? value) => value.HasValue ? value.Value + " MB" : "unlimited";

    public static int Run(CommandLine cl)
    {
        var settings = new Settings();

        bool quick  = cl.Has("q", "quick");
        bool full   = cl.Has("f", "full");
        bool custom = cl.Has("c", "custom");

        settings.MemoryScan               = cl.Flag(false, "m", "memory");
        settings.ScanArchives             = cl.Flag(false, "a", "archive");
        settings.HeuristicEnabled         = cl.Flag(false, "h", "heur");

        settings.CloudScanEnabled         = cl.Flag(false, "cs", "enable-cloud-scan");
        settings.CloudVerifyDetections    = cl.Flag(false, "cv", "enable-cloud-verify");
        settings.ScanOptimization         = cl.Flag(false, "cc", "use-cloud-cache");
        settings.SkipMsSigned             = cl.Flag(false, "ss", "skip-signed");

        int? fileLimit    = cl.Number("mfs", "max-file-size");
        int? archiveLimit = cl.Number("amfs", "archive-max-file-size");
        int? nesting      = cl.Number("amn", "archive-max-nesting");

        settings.MaxFileSizeMb        = fileLimit    ?? NoLimitMb;
        settings.MaxUploadToCloudSec  = cl.Number("mct", "max-cloud-time")  ?? 30;
        settings.MaxScanTimePerFileSec = cl.Number("mut", "max-upload-time") ?? 60;
        settings.ArchiveMaxSizeMb     = archiveLimit ?? NoLimitMb;
        settings.ArchiveMaxDepth      = nesting      ?? MaxNesting;

        int threads = cl.Number("t", "threads") ?? 0;
        if (threads <= 0) threads = Environment.ProcessorCount;
        settings.ScanMaxParallelism = threads;

        int cpuLimit = cl.Number("cpu", "cpu-limit") ?? 100;
        settings.ScanCpuLimitPercent = cpuLimit;

        bool autoReport = cl.Has("log", "log-output");

        if (!ApplyExtensionFilter(cl, settings)) return 2;

        var fix = ResolveFixMode(cl, out string? fixError);
        if (fixError != null) { Con.ErrorLine("[!] " + fixError); return 2; }
        settings.RepairMode = fix switch
        {
            FixMode.Quarantine => 2,
            FixMode.Delete     => 3,
            _                  => 1,
        };
        settings.ArchiveRepairMode = ResolveArchiveFix(cl);

        bool degraded = false;
        if (fix is FixMode.Quarantine or FixMode.Delete or FixMode.Ask && !Elevation.IsAdministrator)
        {
            Elevation.WarnNotElevated("moving threats to quarantine or deleting them");
            Con.ErrorLine("    The scan continues in detect-only mode.");
            fix = FixMode.Ignore;
            settings.RepairMode = 1;
            degraded = true;
        }

        ScanPlan plan;
        if (full) plan = ScanPlan.Full();
        else if (quick) plan = ScanPlan.Quick();
        else if (custom)
        {
            var targets = cl.Positional();
            if (targets.Count == 0)
            {
                Con.ErrorLine("[!] /custom needs a path: malcsm /scan /c \"C:\\folder\"");
                return 2;
            }
            plan = ScanPlan.SingleTarget(targets[0]);
            for (int i = 1; i < targets.Count; i++)
                plan.Folders.Add(new ScanPlan.FolderTarget(targets[i], Array.Empty<string>()));
        }
        else
        {
            Con.ErrorLine("[!] Pick a mode: /q (quick), /f (full) or /c <path> (custom).");
            return 2;
        }

        plan.Memory = settings.MemoryScan;

        string limits = "file " + Limit(fileLimit) + "   archive " + Limit(archiveLimit)
                        + "   nesting " + (nesting?.ToString() ?? MaxNesting.ToString());

        if (!DatabasesReady()) return 5;

        return Execute(plan, settings, fix, autoReport, degraded, limits);
    }

    /// <summary>Without the signature database a scan reports nothing and looks like a clean
    /// result, which is worse than refusing to run.</summary>
    private static bool DatabasesReady()
    {
        var missing = DatabaseInfo.Required.Where(e => !DatabaseInfo.Installed(e)).ToList();
        if (missing.Count == 0) return true;

        Con.Banner("");
        Con.Line("No detection databases installed.", Tone.Warn);
        Con.Line();
        foreach (var e in missing) Con.Line($"  missing: {e.Name} ({e.FileName})", Tone.Dim);
        Con.Line();
        Con.Line("Run  malcsm.exe /update  first.", Tone.Info);
        return false;
    }

    private static bool ApplyExtensionFilter(CommandLine cl, Settings settings)
    {
        var values = cl.ValuesAfter("ext", "extension-list");
        if (values.Count == 0) { settings.ExtFilterMode = "all"; return true; }

        if (values[0] == "0") { settings.ExtFilterMode = "common"; return true; }
        if (values[0] == "1") { settings.ExtFilterMode = "all"; return true; }
        if (values[0] == "2")
        {
            settings.ExtFilterMode = "blacklist";
            settings.ExtBlacklist = values.Skip(1).Select(Clean).Where(v => v.Length > 0).ToList();
            if (settings.ExtBlacklist.Count == 0)
            {
                Con.ErrorLine("[!] /ext 2 needs a list of extensions to exclude.");
                return false;
            }
            return true;
        }

        settings.ExtFilterMode = "common";
        settings.ExtListCommon = values.Select(Clean).Where(v => v.Length > 0).ToList();
        return true;

        static string Clean(string v) => v.Trim().TrimStart('.', '*').ToLowerInvariant();
    }

    private static FixMode ResolveFixMode(CommandLine cl, out string? error)
    {
        error = null;
        if (cl.Has("fix-quar")) return FixMode.Quarantine;
        if (cl.Has("fix-del"))  return FixMode.Delete;
        if (cl.Has("fix-ask"))  return FixMode.Ask;
        if (cl.Has("fix-ignore")) return FixMode.Ignore;

        var n = cl.Value("fix");
        if (n != null)
        {
            switch (n.Trim().ToLowerInvariant())
            {
                case "1": case "quar": return FixMode.Quarantine;
                case "2": case "del":  return FixMode.Delete;
                case "3": case "ask":  return FixMode.Ask;
                case "4": case "ignore": return FixMode.Ignore;
                default: error = $"unknown repair mode: {n} (use 1..4 or quar/del/ask/ignore)"; return FixMode.Quarantine;
            }
        }

        return cl.Flag(false, "auto", "autofix") ? FixMode.Quarantine : FixMode.Ignore;
    }

    private static int ResolveArchiveFix(CommandLine cl)
    {
        if (cl.Has("archive-fix-copy")) return 1;
        if (cl.Has("archive-fix-del"))  return 2;
        var n = cl.Value("afix");
        return n?.Trim().ToLowerInvariant() switch
        {
            "1" or "copy" => 1,
            "2" or "del"  => 2,
            _ => 1,
        };
    }

    private const int LogLines = 6;

    /// <summary>Everything in the frame except the log rows.</summary>
    private const int FrameOverhead = 25;

    private static int LogCapacityForWindow()
    {
        try
        {
            if (Console.IsOutputRedirected) return LogLines;
            return Math.Clamp(Console.WindowHeight - 1 - FrameOverhead, 1, LogLines);
        }
        catch { return LogLines; }
    }

    private sealed class Finding
    {
        public Finding(DetectionResult result) => Result = result;

        public DetectionResult Result { get; }

        public string Detection => Result.Detection ?? "unknown";
        public string Source => Result.Source ?? "";
        public string Path => Result.Path;
        public string Entry => Result.ArchiveEntry ?? "";

        public string Action = "none";
        public string Detail = "";

        public string RegistryLocation = "";
        public bool RegistryOnly;
    }

    private sealed class Status
    {
        public string Memory = "";
        public string Stage = "Starting...";
        public DateTime Started = DateTime.Now;
        public string Vps = "";
        public string Cloud = "";
        public string Current = "";
        public string Profile = "";
        public string Layers = "";
        public string Limits = "";
        public int LogCapacity = LogLines;
        public int Scanned, Infections, Errors, Total;
        public bool Counting = true;
        public bool Finished;

        private readonly List<(string Text, Tone Tone)> _log = new();
        private readonly List<string> _full = new();

        public IReadOnlyList<string> FullLog { get { lock (_log) return _full.ToArray(); } }

        public void Log(string line, Tone tone = Tone.Plain)
        {
            line = line.TrimEnd();
            if (line.Length == 0) return;
            if (IsNoise(line)) return;
            lock (_log)
            {
                _log.Add((line, tone == Tone.Plain ? ToneOf(line) : tone));
                while (_log.Count > LogCapacity) _log.RemoveAt(0);
                if (_full.Count < 20000) _full.Add(line);
            }
        }

        /// <summary>Which database format was loaded is engine bookkeeping, not scan output.</summary>
        private static bool IsNoise(string line)
            => line.Contains("database loaded", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Whitelist loaded", StringComparison.OrdinalIgnoreCase)
            || line.Contains("heuristic rules loaded", StringComparison.OrdinalIgnoreCase);

        private static Tone ToneOf(string line)
        {
            if (line.StartsWith("[i]", StringComparison.Ordinal)) return Tone.Dim;
            if (line.StartsWith("[+]", StringComparison.Ordinal)) return Tone.Info;
            if (line.Contains("Heur", StringComparison.OrdinalIgnoreCase)) return Tone.Heuristic;
            if (line.StartsWith("[!]", StringComparison.Ordinal)) return Tone.Warn;
            return Tone.Plain;
        }

        private List<(string Text, Tone Tone)> LogSnapshot()
        {
            lock (_log) return new List<(string, Tone)>(_log);
        }

        public IReadOnlyList<StatusLine> Lines()
        {
            var bar = new string('_', 22);
            var l = new List<StatusLine>
            {
                new(Memory, Tone.Info),
                new($"Status: {(Infections > 0 ? "Threats detected" : "OK")}",
                    Infections > 0 ? Tone.Threat : Tone.Dim),
                "",
                new($"Stage: {Stage}", Tone.Info),
                new($"Scan started at: {Started:yyyy-MM-dd HH:mm:ss}", Tone.Dim),
                new($"VPS Version: {Vps}", Tone.Dim),
                new($"Cloud: {Cloud}", Cloud == "Unavailable" ? Tone.Warn : Tone.Dim),
                new($"Profile: {Profile}", Tone.Dim),
                new($"Layers: {Layers}", Tone.Dim),
                new($"Limits: {Limits}", Tone.Dim),
                "",
                new(bar, Tone.Dim),
                "",
                new($"Actually scanning: {Current}", Tone.Plain),
                new($"Scanned: {Scanned}" + (Counting || Total <= 0 ? "" : $" of {Total}"), Tone.Plain),
                new($"Infections: {Infections}", Infections > 0 ? Tone.Threat : Tone.Plain),
                new($"Errors: {Errors}", Errors > 0 ? Tone.Warn : Tone.Plain),
                new(bar, Tone.Dim),
                "",
                new("Log data:", Tone.Dim),
                "",
            };

            var log = LogSnapshot();
            for (int i = 0; i < LogCapacity; i++)
                l.Add(i < log.Count ? new StatusLine("  " + log[i].Text, log[i].Tone) : "");

            l.Add("");
            l.Add(new StatusLine(bar, Tone.Dim));
            l.Add("");
            l.Add(new StatusLine($"Completed: {Percent():F1}%", Tone.Info));
            return l;
        }

        public double Percent()
        {
            if (Finished) return 100;
            if (Counting || Total <= 0) return 0;
            return Math.Min(100.0, Scanned * 100.0 / Total);
        }
    }

    private sealed class LogSink : TextWriter
    {
        private readonly Status _status;
        private readonly System.Text.StringBuilder _buf = new();

        public LogSink(Status status) { _status = status; }

        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;

        public override void Write(char value)
        {
            if (value == '\n') { Flush(); return; }
            if (value != '\r') lock (_buf) _buf.Append(value);
        }

        public override void Write(string? value)
        {
            if (value == null) return;
            foreach (var c in value) Write(c);
        }

        public override void Flush()
        {
            string text;
            lock (_buf)
            {
                if (_buf.Length == 0) return;
                text = _buf.ToString();
                _buf.Clear();
            }
            _status.Log(text);
        }
    }

    private static int Execute(ScanPlan plan, Settings settings, FixMode fix,
                               bool autoReport, bool degraded, string limits)
    {
        Con.Banner($"{plan.Name} scan");

        var real = Console.Out;
        var status = new Status
        {
            Vps = DatabaseInfo.SignatureLine(),
            Cloud = settings.CloudScanEnabled ? "Checking..." : "Disabled",
            Memory = plan.Memory ? "Scanning memory..." : "Memory scan skipped.",
            LogCapacity = LogCapacityForWindow(),
        };
        var screen = new StatusBlock(real);
        var drawGate = new object();

        void Draw(bool force = false)
        {
            if (!Monitor.TryEnter(drawGate)) return;
            try { screen.Render(status.Lines(), force); }
            finally { Monitor.Exit(drawGate); }
        }

        if (settings.CloudScanEnabled) ProbeCloud(settings, status);

        status.Profile = $"{plan.Name} scan   repair: {fix.ToString().ToLowerInvariant()}   "
                         + $"threads: {settings.ScanMaxParallelism}";
        status.Layers = LayerSummary(plan, settings);
        status.Limits = limits;

        var excluded = ExclusionShell.Load();
        if (excluded.Count > 0) status.Log($"[i] {excluded.Count} exclusion(s) in effect");
        if (degraded) status.Log("[!] detect-only: the console is not elevated");
        Draw(true);

        using var sink = new LogSink(status);
        using var errors = new ErrorScope(sink);
        var findings = new List<Finding>();
        var findingLock = new object();
        int exit;

        using (ConsoleRouter.Scope(sink))
        {
            using var pipeline = new ScanPipeline(settings);
            sink.Flush();

            var driversDone = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (plan.Memory)
            {
                status.Stage = "Memory Scan";
                Draw(true);
                var memory = new Malward.Engine.Memory.ProcessScanner(settings);
                foreach (var r in memory.ScanRunningProcesses(pipeline))
                {
                    status.Current = r.Path;
                    status.Scanned++;
                    if (r.Verdict == Verdict.Error) { status.Errors++; Draw(); continue; }
                    if (r.Verdict != Verdict.Malware) { Draw(); continue; }

                    findings.Add(ToFinding(r));
                    status.Infections++;
                    status.Log(Describe(r), Tone.Threat);
                    Draw(true);
                }
                sink.Flush();

                status.Stage = "Registry and startup entries";
                Draw(true);
                ScanRegistry(pipeline, status, findings, findingLock, Draw);
                sink.Flush();

                status.Stage = "System drivers";
                Draw(true);
                ScanDrivers(pipeline, status, findings, findingLock, excluded, driversDone, Draw);
                sink.Flush();

                status.Memory = "Scanning memory... Done!";
                status.Current = "";
                Draw(true);
            }

            status.Stage = "Building the file list...";
            Draw(true);

            var files = new List<string>();
            var seen = new HashSet<string>(driversDone, StringComparer.OrdinalIgnoreCase);
            foreach (var folder in plan.Folders)
            {
                bool skipOwnDir = !IsUnderOwnDirectory(folder.Path);
                foreach (var file in Walk(folder.Path))
                {
                    if (!folder.Matches(file)) continue;
                    if (skipOwnDir && IsUnderOwnDirectory(file)) continue;
                    if (IsExcluded(file, excluded)) continue;
                    if (!seen.Add(file)) continue;
                    files.Add(file);
                    if ((files.Count & 1023) == 0) { status.Current = file; Draw(); }
                }
            }
            // Scanned already counts the memory stage, so the target has to include it too.
            status.Total = files.Count + status.Scanned;
            status.Counting = false;
            status.Current = "";

            status.Stage = "File Scan. Ready.";
            Draw(true);

            var options = new ParallelOptions { MaxDegreeOfParallelism = settings.ScanMaxParallelism };
            Parallel.ForEach(files, options, file =>
            {
                status.Current = file;

                DetectionResult r;
                try { r = pipeline.Scan(file); }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref status.Errors);
                    Interlocked.Increment(ref status.Scanned);
                    status.Log($"[!] {file}: {ex.Message}");
                    Draw();
                    return;
                }

                Interlocked.Increment(ref status.Scanned);

                if (r.Verdict == Verdict.Error)
                {
                    Interlocked.Increment(ref status.Errors);
                    status.Log($"[!] {file}: {(string.IsNullOrEmpty(r.Error) ? "scan error" : r.Error)}");
                    Draw();
                    return;
                }

                if (r.Verdict == Verdict.Malware)
                {
                    lock (findingLock) findings.Add(ToFinding(r));
                    Interlocked.Increment(ref status.Infections);
                    status.Log(Describe(r), Tone.Threat);
                    Draw(true);
                    return;
                }

                Draw();
            });

            sink.Flush();
            status.Current = "";
            status.Stage = findings.Count == 0 ? "Finished. Ready." : "Repair";
            Draw(true);

            exit = findings.Count == 0
                ? 0
                : ApplyRepairs(findings, settings, fix, status, screen, real, Draw);
        }

        status.Stage = "Finished. Ready.";
        status.Current = "";
        status.Finished = true;
        Draw(true);
        screen.Release();

        FinalScreen(status, findings, plan);
        Report(status, findings, settings, plan, fix, autoReport);
        return exit;
    }

    private static string LayerSummary(ScanPlan plan, Settings settings)
        => string.Join("  ", new[]
        {
            "whitelist on",
            "memory " + OnOff(plan.Memory),
            "archives " + OnOff(settings.ScanArchives),
            "heuristics " + OnOff(settings.HeuristicEnabled),
            "cloud " + OnOff(settings.CloudScanEnabled),
        });

    private static Finding ToFinding(DetectionResult r) => new(r);

    /// <summary>Autostart entries, services and the other registry load points the graphical
    /// scanner walks: the referenced file is scanned, and the entry itself is judged on its shape.
    /// </summary>
    private static void ScanRegistry(ScanPipeline pipeline, Status status, List<Finding> findings,
                                     object findingLock, Action<bool> draw)
    {
        var items = new List<RegistryScanner.Item>();
        try { items.AddRange(RegistryScanner.Collect()); }
        catch (Exception ex) { status.Log($"[!] registry: {ex.Message}"); }
        try
        {
            foreach (var lp in RegistryLoadPoints.Collect())
                items.Add(new RegistryScanner.Item(lp.Location, lp.FilePath, lp.Kind));
        }
        catch (Exception ex) { status.Log($"[!] registry load points: {ex.Message}"); }

        foreach (var item in items)
        {
            status.Current = item.Location;

            DetectionResult r;
            try { r = pipeline.Scan(item.FilePath); }
            catch (Exception ex)
            {
                status.Errors++;
                status.Log($"[!] {item.Location}: {ex.Message}");
                draw(false);
                continue;
            }

            status.Scanned++;

            var shape = r.Verdict == Verdict.Malware ? null : RegistryScanner.ClassifyPersistence(item);
            if (r.Verdict != Verdict.Malware && shape == null) { draw(false); continue; }

            var effective = r.Verdict == Verdict.Malware
                ? r
                : r with { Verdict = Verdict.Malware, Detection = shape!.Detection,
                           Source = "Registry:heuristic" };

            lock (findingLock) findings.Add(new Finding(effective) { RegistryLocation = item.Location });
            status.Infections++;
            status.Log($"[!] {effective.Detection}  {item.Location} -> {item.FilePath}", Tone.Threat);
            draw(true);
        }

        try
        {
            foreach (var indicator in RegistryScanner.CollectIndicators())
            {
                if (!indicator.Artifact) continue;
                var r = new DetectionResult(indicator.Location, "", Verdict.Malware,
                                            indicator.Detection, "Registry", 0, 0);
                lock (findingLock)
                    findings.Add(new Finding(r)
                    {
                        RegistryLocation = indicator.Location,
                        RegistryOnly = true,
                    });
                status.Infections++;
                status.Log($"[!] {indicator.Detection}  {indicator.Detail}", Tone.Threat);
                draw(true);
            }
        }
        catch (Exception ex) { status.Log($"[!] registry indicators: {ex.Message}"); }

        status.Current = "";
    }

    private static void ScanDrivers(ScanPipeline pipeline, Status status, List<Finding> findings,
                                    object findingLock, List<string> excluded,
                                    HashSet<string> done, Action<bool> draw)
    {
        var dir = ScanPlan.DriversDir;
        if (!Directory.Exists(dir)) return;

        foreach (var file in Walk(dir))
        {
            if (IsExcluded(file, excluded)) continue;
            if (!done.Add(file)) continue;

            status.Current = file;

            DetectionResult r;
            try { r = pipeline.Scan(file); }
            catch (Exception ex)
            {
                status.Errors++;
                status.Log($"[!] {file}: {ex.Message}");
                draw(false);
                continue;
            }

            status.Scanned++;

            if (r.Verdict == Verdict.Error)
            {
                status.Errors++;
                draw(false);
                continue;
            }
            if (r.Verdict != Verdict.Malware) { draw(false); continue; }

            lock (findingLock) findings.Add(ToFinding(r));
            status.Infections++;
            status.Log(Describe(r), Tone.Threat);
            draw(true);
        }

        status.Current = "";
    }

    private static void ProbeCloud(Settings settings, Status status)
    {
        Task.Run(() =>
        {
            try
            {
                using var client = new Malward.Engine.Cloud.ServerClient(settings);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
                client.GetManifestAsync(cts.Token).GetAwaiter().GetResult();
                status.Cloud = "Connected";
            }
            catch { status.Cloud = "Unavailable"; }
        });
    }

    private static int ApplyRepairs(List<Finding> findings, Settings settings, FixMode fix,
                                    Status status, StatusBlock screen, TextWriter real,
                                    Action<bool> draw)
    {
        if (fix == FixMode.Ignore)
        {
            status.Log("[i] Repair skipped - the threats above were left untouched.");
            draw(true);
            return 1;
        }

        if (fix == FixMode.Ask)
        {
            screen.Release();
            real.WriteLine();
            Con.Line("Choose an action for the threats found:", Tone.Info);
            Con.Line("  [Q] quarantine   [D] delete   [S] skip", Tone.Dim);
            real.Write("> ");
            var key = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
            if (key.StartsWith('q')) settings.RepairMode = 2;
            else if (key.StartsWith('d')) settings.RepairMode = 3;
            else
            {
                status.Log("[i] Repair skipped on request.");
                draw(true);
                return 1;
            }
        }

        var repairer = new Repairer(settings);
        int ok = 0, failed = 0;
        foreach (var f in findings)
        {
            var name = SafeName(f.Path);
            status.Log($"[i] Fixing detection - {f.Detection}. Please wait.");
            draw(true);

            if (f.RegistryOnly)
            {
                var removal = Malward.Engine.Repair.RegistryRepair.Remove(f.RegistryLocation);
                f.Action = removal.Ok ? "registry-removed" : "failed";
                f.Detail = removal.Ok ? f.RegistryLocation : (removal.Error ?? "");
                if (removal.Ok) ok++; else failed++;
                status.Log(removal.Ok
                    ? $"[+] Detection {f.Detection} was fixed successfully (registry entry removed)."
                    : $"[!] {f.Detection} on {f.RegistryLocation} was not fixed: {f.Detail}");
                draw(true);
                continue;
            }

            RepairOutcome outcome;
            try { outcome = repairer.Repair(f.Result, userInitiated: true); }
            catch (Exception ex)
            {
                failed++;
                f.Action = "failed";
                f.Detail = ex.Message;
                status.Log($"[!] {f.Detection} on file {name} was not fixed: {ex.Message}");
                draw(true);
                continue;
            }

            f.Action = outcome.Action;
            f.Detail = outcome.Detail ?? "";

            if (f.RegistryLocation.Length > 0)
            {
                var removal = Malward.Engine.Repair.RegistryRepair.Remove(f.RegistryLocation);
                if (!removal.Ok)
                    status.Log($"[!] registry entry {f.RegistryLocation} was not removed: {removal.Error}");
            }

            if (outcome.Success && outcome.Action is not ("deferred" or "noop" or "system-skip"))
            {
                ok++;
                status.Log($"[+] Detection {f.Detection} on file {name} was fixed successfully "
                           + $"({outcome.Action}).");
            }
            else
            {
                failed++;
                status.Log($"[!] {f.Detection} on file {name} was not fixed ({outcome.Action}"
                           + (string.IsNullOrEmpty(outcome.Detail) ? "" : ", " + outcome.Detail) + ").");
            }
            draw(true);
        }

        status.Log($"[i] Repaired {ok} of {findings.Count}, {failed} left.");
        draw(true);
        return failed == 0 ? 0 : 1;
    }

    /// <summary>The live block fills the window, so the results would land under the fold.
    /// On a real console the summary gets the screen to itself.</summary>
    private static void FinalScreen(Status status, List<Finding> findings, ScanPlan plan)
    {
        if (Console.IsOutputRedirected) { Console.Out.WriteLine(); return; }

        Con.Banner($"{plan.Name} scan — finished");
        Con.Line($"Started : {status.Started:yyyy-MM-dd HH:mm:ss}", Tone.Dim);
        Con.Line($"Profile : {status.Profile}", Tone.Dim);
        Con.Line($"Layers  : {status.Layers}", Tone.Dim);
        Con.Line($"Limits  : {status.Limits}", Tone.Dim);
        Con.Line($"Scanned : {status.Scanned}", Tone.Dim);
        Con.Line($"Errors  : {status.Errors}", status.Errors > 0 ? Tone.Warn : Tone.Dim);
        Con.Line();
    }

    private static void Report(Status status, List<Finding> findings, Settings settings,
                               ScanPlan plan, FixMode fix, bool autoReport)
    {
        var elapsed = DateTime.Now - status.Started;

        if (findings.Count == 0)
        {
            Con.Line("No threats detected!", Tone.Info);
        }
        else
        {
            Con.Line($"DETECTIONS ({findings.Count})", Tone.Threat);
            Con.Line();
            var rows = new List<IReadOnlyList<string>>();
            var tones = new List<Tone>();
            foreach (var f in findings)
            {
                rows.Add(new[]
                {
                    f.Detection,
                    f.Source,
                    f.Action,
                    f.Entry.Length == 0 ? f.Path : $"{f.Path} >> {f.Entry}",
                });
                tones.Add(f.Detection.StartsWith("Heur", StringComparison.OrdinalIgnoreCase)
                    ? Tone.Heuristic : Tone.Threat);
            }
            Con.Table(new[] { "DETECTION", "SOURCE", "ACTION", "FILE" }, rows, tones);
        }

        Con.Line();
        Con.Line($"Scanned {status.Scanned} file(s) in {elapsed.TotalSeconds:F1} s, "
                 + $"{findings.Count} threat(s), {status.Errors} error(s).", Tone.Dim);

        bool save = autoReport;
        if (!save && !Console.IsInputRedirected && !Console.IsOutputRedirected)
        {
            Con.Line();
            Con.Write(Console.Out, "Save a detailed report to the Desktop? [y/N] ", Tone.Info);
            var answer = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
            save = answer.StartsWith('y') || answer.StartsWith('t');
        }
        if (!save) return;

        try
        {
            var path = WriteReport(status, findings, settings, plan, fix);
            Con.Line($"Report saved: {path}", Tone.Info);
        }
        catch (Exception ex)
        {
            Con.ErrorLine($"[!] Could not write the report: {ex.Message}");
        }
    }

    private static string WriteReport(Status status, List<Finding> findings, Settings settings,
                                      ScanPlan plan, FixMode fix)
    {
        var dir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrEmpty(dir)) dir = AppContext.BaseDirectory;
        var file = Path.Combine(dir, $"malward-scan-{status.Started:yyyyMMdd-HHmmss}.txt");

        var text = new System.Text.StringBuilder();
        text.AppendLine("Malward Command Shell Manager - scan report");
        text.AppendLine($"Started : {status.Started:yyyy-MM-dd HH:mm:ss}");
        text.AppendLine($"Finished: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        text.AppendLine($"Profile : {plan.Name}");
        text.AppendLine($"Repair  : {fix.ToString().ToLowerInvariant()}");
        text.AppendLine($"Threads : {settings.ScanMaxParallelism}");
        text.AppendLine();
        text.AppendLine("Detection layers");
        text.AppendLine($"  memory scan      : {OnOff(plan.Memory)}");
        text.AppendLine($"  archives         : {OnOff(settings.ScanArchives)}");
        text.AppendLine($"  heuristics       : {OnOff(settings.HeuristicEnabled)}");
        text.AppendLine("  file whitelist   : on");
        text.AppendLine($"  cloud scan       : {OnOff(settings.CloudScanEnabled)}");
        text.AppendLine($"  cloud verify     : {OnOff(settings.CloudVerifyDetections)}");
        text.AppendLine($"  cloud cache      : {OnOff(settings.ScanOptimization)}");
        text.AppendLine($"  skip MS-signed   : {OnOff(settings.SkipMsSigned)}");
        text.AppendLine($"  limits           : {status.Limits}");
        text.AppendLine();
        text.AppendLine("Databases");
        foreach (var e in DatabaseInfo.Listed)
        {
            if (!DatabaseInfo.Installed(e)) continue;
            var build = DatabaseInfo.Version(e.VersionKey);
            text.AppendLine($"  {e.Name,-24}{(build.Length == 0 ? "unknown" : build)}");
        }
        text.AppendLine();
        text.AppendLine($"Scanned    : {status.Scanned}");
        text.AppendLine($"Infections : {findings.Count}");
        text.AppendLine($"Errors     : {status.Errors}");
        text.AppendLine();

        text.AppendLine("Detections");
        if (findings.Count == 0) text.AppendLine("  none");
        foreach (var f in findings)
        {
            text.AppendLine($"  {f.Detection}");
            text.AppendLine($"    file   : {f.Path}");
            if (f.Entry.Length > 0) text.AppendLine($"    entry  : {f.Entry}");
            text.AppendLine($"    source : {f.Source}");
            text.AppendLine($"    action : {f.Action}{(f.Detail.Length == 0 ? "" : " - " + f.Detail)}");
        }
        text.AppendLine();

        text.AppendLine("Log");
        foreach (var line in status.FullLog) text.AppendLine("  " + line);

        File.WriteAllText(file, text.ToString(), new System.Text.UTF8Encoding(false));
        return file;
    }

    private static string SafeName(string path)
    {
        try { return Path.GetFileName(path); }
        catch { return path; }
    }

    private static string Describe(DetectionResult r)
        => $"[!] {r.Detection}  {r.Path}"
           + (string.IsNullOrEmpty(r.ArchiveEntry) ? "" : $"  >> {r.ArchiveEntry}");

    private static readonly string OwnDirectory = OwnDirectoryPath();

    private static string OwnDirectoryPath()
    {
        try
        {
            var dir = Path.GetFullPath(AppContext.BaseDirectory);
            return dir.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        }
        catch { return ""; }
    }

    private static bool IsUnderOwnDirectory(string path)
    {
        if (OwnDirectory.Length == 0) return false;
        try
        {
            var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar)
                       + Path.DirectorySeparatorChar;
            return full.StartsWith(OwnDirectory, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool IsExcluded(string file, List<string> excluded)
    {
        if (excluded.Count == 0) return false;

        string full;
        try { full = Path.GetFullPath(file); }
        catch { full = file; }

        foreach (var e in excluded)
        {
            if (full.Equals(e, StringComparison.OrdinalIgnoreCase)) return true;
            var prefix = e.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string OnOff(bool v) => v ? "on" : "off";

    private static IEnumerable<string> Walk(string root)
    {
        if (File.Exists(root)) { yield return root; yield break; }
        if (!Directory.Exists(root)) yield break;

        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            string[] files;
            try { files = Directory.GetFiles(dir); }
            catch { continue; }
            foreach (var f in files) yield return f;

            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch { continue; }
            foreach (var s in subs)
            {
                try { if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) != 0) continue; }
                catch { continue; }
                stack.Push(s);
            }
        }
    }
}
