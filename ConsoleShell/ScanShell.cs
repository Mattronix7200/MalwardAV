using System.Collections.Concurrent;
using Malward.Engine.Config;
using Malward.Engine.Core;
using Malward.Engine.Repair;
using Malward.Engine.Util;

namespace Malward.ConsoleShell;

public static class ScanShell
{
    private sealed class StopFlag
    {
        private volatile bool _requested;
        private volatile bool _done;

        public bool Requested { get => _requested; set => _requested = value; }
        public bool Done { get => _done; set => _done = value; }
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

    private sealed class LogSink : TextWriter
    {
        private readonly ScanView _view;
        private readonly System.Text.StringBuilder _buffer = new();

        public LogSink(ScanView view) => _view = view;

        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;

        public override void Write(char value)
        {
            if (value == '\n') { Flush(); return; }
            if (value != '\r') lock (_buffer) _buffer.Append(value);
        }

        public override void Write(string? value)
        {
            if (value == null) return;
            foreach (var c in value) Write(c);
        }

        public override void Flush()
        {
            string text;
            lock (_buffer)
            {
                if (_buffer.Length == 0) return;
                text = _buffer.ToString().TrimEnd();
                _buffer.Clear();
            }
            if (text.Length == 0 || IsNoise(text)) return;
            _view.Note(text);
        }

        private static bool IsNoise(string line)
            => line.Contains("database loaded", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Whitelist loaded", StringComparison.OrdinalIgnoreCase)
            || line.Contains("heuristic rules loaded", StringComparison.OrdinalIgnoreCase);
    }

    public static int Run(CommandLine cl)
    {
        var options = ScanOptions.Load();
        options.ApplyCommandLine(cl);

        if (!ApplyExtensionFilter(cl, options)) return 2;
        if (!ApplyFixMode(cl, options)) return 2;

        if (cl.Has("c", "custom"))
        {
            Con.ErrorLine("[!] /c was removed. Give the path on its own:");
            Con.ErrorLine("      malcsm /scan \"D:\\data\"", Tone.Info);
            return 2;
        }

        bool quick = cl.Has("q", "quick");
        bool full = cl.Has("f", "full");
        var targets = cl.Positional();

        if (quick && full)
        {
            Con.ErrorLine("[!] Pick one mode: /q or /f.");
            return 2;
        }

        ScanPlan plan;
        if (full) plan = ScanPlan.Full();
        else if (quick) plan = ScanPlan.Quick();
        else if (targets.Count > 0)
        {
            plan = TargetPlan(targets, out var bad);
            if (bad != null) { Con.ErrorLine("[!] " + bad); return 2; }
        }
        else
        {
            Con.ErrorLine("[!] Nothing to scan. Use /q (quick), /f (full)");
            Con.ErrorLine("    or give a path:  malcsm /scan \"D:\\data\"", Tone.Info);
            return 2;
        }

        return Start(plan, options, interactive: false);
    }

    public static ScanPlan TargetPlan(IReadOnlyList<string> targets, out string? error)
    {
        error = null;
        var plan = new ScanPlan { Name = "custom" };
        foreach (var raw in targets)
        {
            var target = raw.Trim().Trim('"');
            if (target.Length == 0) continue;

            string full;
            try { full = System.IO.Path.GetFullPath(target); }
            catch (Exception ex) { error = $"{target}: {ex.Message}"; return plan; }

            if (!File.Exists(full) && !Directory.Exists(full))
            {
                error = $"{full} does not exist.";
                return plan;
            }
            plan.Folders.Add(new ScanPlan.FolderTarget(full, Array.Empty<string>()));
        }

        if (plan.Folders.Count == 0) error = "no usable path given.";
        return plan;
    }

    public static int Start(ScanPlan plan, ScanOptions options, bool interactive)
    {
        if (!DatabasesReady(interactive)) return 5;
        return Execute(plan, options, interactive);
    }

    private static bool ApplyFixMode(CommandLine cl, ScanOptions options)
    {
        if (cl.Has("fix-quar")) { options.Fix = FixMode.Quarantine; return true; }
        if (cl.Has("fix-del")) { options.Fix = FixMode.Delete; return true; }
        if (cl.Has("fix-ask")) { options.Fix = FixMode.Ask; return true; }
        if (cl.Has("fix-ignore")) { options.Fix = FixMode.Report; return true; }

        var value = cl.Value("fix");
        if (value != null)
        {
            switch (value.Trim().ToLowerInvariant())
            {
                case "1": case "quar": options.Fix = FixMode.Quarantine; return true;
                case "2": case "del": options.Fix = FixMode.Delete; return true;
                case "3": case "ask": options.Fix = FixMode.Ask; return true;
                case "4": case "ignore": options.Fix = FixMode.Report; return true;
                default:
                    Con.ErrorLine($"[!] unknown repair mode: {value} (use 1..4 or quar/del/ask/ignore)");
                    return false;
            }
        }

        if (cl.Has("auto", "autofix")) options.Fix = FixMode.Quarantine;

        if (cl.Has("archive-fix-copy")) options.ArchiveFix = ArchiveFixMode.DropEntry;
        else if (cl.Has("archive-fix-del")) options.ArchiveFix = ArchiveFixMode.DeleteArchive;
        else
        {
            var afix = cl.Value("afix");
            if (afix != null)
                options.ArchiveFix = afix.Trim().ToLowerInvariant() is "2" or "del"
                    ? ArchiveFixMode.DeleteArchive : ArchiveFixMode.DropEntry;
        }
        return true;
    }

    private static bool ApplyExtensionFilter(CommandLine cl, ScanOptions options)
    {
        var values = cl.ValuesAfter("ext", "extension-list");
        if (values.Count == 0) return true;

        if (values[0] == "0") { options.Extensions = ExtensionMode.Common; options.ExtensionList.Clear(); return true; }
        if (values[0] == "1") { options.Extensions = ExtensionMode.All; options.ExtensionList.Clear(); return true; }
        if (values[0] == "2")
        {
            var list = values.Skip(1).Select(Clean).Where(v => v.Length > 0).ToList();
            if (list.Count == 0)
            {
                Con.ErrorLine("[!] /ext 2 needs a list of extensions to exclude.");
                return false;
            }
            options.Extensions = ExtensionMode.Blacklist;
            options.ExtensionList = list;
            return true;
        }

        options.Extensions = ExtensionMode.Only;
        options.ExtensionList = values.Select(Clean).Where(v => v.Length > 0).ToList();
        return true;

        static string Clean(string v) => v.Trim().TrimStart('.', '*').ToLowerInvariant();
    }

    private static bool DatabasesReady(bool interactive)
    {
        var missing = DatabaseInfo.Required.Where(e => !DatabaseInfo.Installed(e)).ToList();
        if (missing.Count == 0) return true;

        if (interactive)
        {
            var screen = new Screen();
            screen.Clear();
            screen.Sidebar(SidebarInfo());
            int y = screen.ContentTop;
            screen.Put(screen.ContentLeft, y++, "NO DETECTION DATABASES", Tone.Warn);
            screen.Rule(screen.ContentLeft, y++, screen.ContentWidth);
            foreach (var e in missing)
                screen.Put(screen.ContentLeft, y++, "missing: " + e.Name + " (" + e.FileName + ")", Tone.Dim);
            y++;
            screen.Put(screen.ContentLeft, y, "Run \"Check for updates\" first. Press any key.", Tone.Info);
            screen.Flush(true);
            screen.WaitKey();
            return false;
        }

        Con.Banner("");
        Con.Line("No detection databases installed.", Tone.Warn);
        Con.Line();
        foreach (var e in missing) Con.Line($"  missing: {e.Name} ({e.FileName})", Tone.Dim);
        Con.Line();
        Con.Line("Run  malcsm.exe /update  first.", Tone.Info);
        return false;
    }

    public static SidebarInfo SidebarInfo()
    {
        var asm = System.Reflection.Assembly.GetExecutingAssembly();
        var version = asm.GetName().Version;
        string shown = version == null
            ? "1.0.0"
            : $"{version.Major}.{version.Minor}.{version.Build}";
        var vps = DatabaseInfo.Version("vps");
        var date = DatabaseInfo.BuildDate(DatabaseInfo.Listed[0]);
        return new SidebarInfo(shown,
                               vps.Length == 0 ? "not installed" : vps,
                               date.Length == 0 ? "never" : date);
    }

    public static IReadOnlyList<(string Text, Tone Tone)>? BuildWarning(ScanOptions options)
    {
        var lines = new List<(string, Tone)>();

        if (!options.CloudScan)
        {
            lines.Add(("!  CLOUD SCANNING IS OFF - DETECTION CONFIDENCE IS INCOMPLETE", Tone.Warn));
            lines.Add(("", Tone.Plain));
            lines.Add(("Database hits are reported without a second opinion from the cloud", Tone.Plain));
            lines.Add(("engines, so clean files can be flagged as threats. Turn it back on in", Tone.Plain));
            lines.Add(("Settings (1) or run with  /cs on", Tone.Dim));
        }
        else if (!options.CloudVerify)
        {
            lines.Add(("!  CLOUD VERIFICATION IS OFF - FALSE POSITIVES ARE LIKELY", Tone.Warn));
            lines.Add(("", Tone.Plain));
            lines.Add(("A database hit is not re-checked against the cloud engines, so a file", Tone.Plain));
            lines.Add(("the cloud already knows as clean is still reported as a threat.", Tone.Plain));
            lines.Add(("Turn it back on in Settings (2) or run with  /cv on", Tone.Dim));
        }

        if (options.Heuristics)
        {
            if (lines.Count > 0) lines.Add(("", Tone.Plain));
            lines.Add(("!  HEURISTIC ANALYSIS IS ON - EXPECT FALSE POSITIVES", Tone.Warn));
            lines.Add(("", Tone.Plain));
            lines.Add(("Generic rules judge a file by its shape, not by a known signature.", Tone.Plain));
            lines.Add(("They work best with cloud scanning left on.", Tone.Dim));
        }

        return lines.Count == 0 ? null : lines;
    }

    public static string WarningSummary(ScanOptions options)
    {
        var parts = new List<string>();
        if (!options.CloudScan) parts.Add("cloud scanning OFF");
        else if (!options.CloudVerify) parts.Add("cloud verification OFF");
        if (options.Heuristics) parts.Add("heuristics ON");
        if (parts.Count == 0) return "";
        return "!  " + string.Join(", ", parts) + " - detections may include false positives";
    }

    private static int Execute(ScanPlan plan, ScanOptions options, bool interactive)
    {
        ConsoleWindow.Enter();

        var settings = options.ToSettings();
        plan.Memory = options.MemoryScan;

        bool degraded = false;
        if (options.Fix is FixMode.Quarantine or FixMode.Delete or FixMode.Ask
            && !Elevation.IsAdministrator)
        {
            options.Fix = FixMode.Report;
            settings.RepairMode = 1;
            degraded = true;
        }

        var screen = new Screen();
        var view = new ScanView(screen, SidebarInfo())
        {
            Mode = plan.Name.ToUpperInvariant(),
            Threads = settings.ScanMaxParallelism,
            Cloud = options.CloudScan ? "connecting" : "off",
            CloudEnabled = options.CloudScan,
            Warning = BuildWarning(options),
            WarningLine = WarningSummary(options),
            Stage = "Starting",
        };

        if (degraded)
            view.AddError("ELEVATION - the console is not running as administrator, "
                          + "threats can only be reported");

        var stop = new StopFlag();
        StartAutoStop(stop);
        Thread? watcher = StartKeyWatch(stop, screen, view);
        ConsoleWindow.Busy = true;
        var painter = view.StartPainter();

        var findings = new List<Finding>();
        var findingLock = new object();
        var reported = new List<Finding>();
        int exit;

        try
        {
            view.Draw(true);

            var excluded = ExclusionShell.Load();
            if (excluded.Count > 0) view.Note($"[i] {excluded.Count} exclusion(s) in effect");

            using var sink = new LogSink(view);
            using var errors = new ErrorScope(sink);

            using (ConsoleRouter.Scope(sink))
            {
                if (options.CloudScan) ProbeCloud(settings, view);

                view.Stage = "Loading detection databases";
                var pipeline = new ScanPipeline(settings);
                bool pipelineIdle = true;
                sink.Flush();

                var done = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (plan.Memory && !stop.Requested)
                {
                    view.Stage = "Memory scan";
                    view.Draw(true);
                    ScanMemory(pipeline, settings, view, findings, findingLock, stop);
                    sink.Flush();

                    if (!stop.Requested)
                    {
                        view.Stage = "Registry and startup entries";
                        view.Draw(true);
                        ScanRegistry(pipeline, view, findings, findingLock, stop);
                        sink.Flush();
                    }

                    if (!stop.Requested)
                    {
                        view.Stage = "System drivers";
                        view.Draw(true);
                        ScanDrivers(pipeline, view, findings, findingLock, excluded, done, stop);
                        sink.Flush();
                    }
                }

                int already = view.Scanned;

                view.Stage = "Counting files";
                view.Draw(true);
                var files = CollectFiles(plan, excluded, done, stop, view, already);

                view.Total = already + files.Count;
                view.Counting = false;
                view.Current = "";
                view.Stage = "File scan";
                view.Draw(true);

                var governor = new CpuGovernor(options.CpuLimit <= 0 ? 100 : options.CpuLimit);
                if (governor.Active)
                {
                    try
                    {
                        System.Diagnostics.Process.GetCurrentProcess().PriorityClass =
                            System.Diagnostics.ProcessPriorityClass.BelowNormal;
                    }
                    catch { }
                }

                int workers = Math.Max(1, settings.ScanMaxParallelism);
                if (governor.Active) workers = Math.Min(workers, governor.SuggestedThreads);
                view.Threads = workers;

                int cursor = -1;
                var scanners = new Thread[workers];
                for (int i = 0; i < workers; i++)
                {
                    scanners[i] = new Thread(() =>
                    {
                        if (governor.Active)
                            try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }

                        try
                        {
                            while (!stop.Requested)
                            {
                                int index = Interlocked.Increment(ref cursor);
                                if (index >= files.Count) break;

                                governor.Throttle();
                                var file = files[index];
                                view.Current = file;

                                DetectionResult result;
                                try { result = pipeline.Scan(file); }
                                catch (Exception ex)
                                {
                                    Interlocked.Increment(ref view.Errors);
                                    Interlocked.Increment(ref view.Scanned);
                                    view.AddError(ErrorLine(file, ex.Message));
                                    continue;
                                }

                                Interlocked.Increment(ref view.Scanned);
                                if (result.FileSize > 0) Interlocked.Add(ref view.Bytes, result.FileSize);

                                Record(view, result, findings, findingLock);
                            }
                        }
                        catch { }
                    })
                    { IsBackground = true, Name = "malcsm-scan-" + i };
                    scanners[i].Start();
                }

                long deadline = 0;
                foreach (var scanner in scanners)
                {
                    try
                    {
                        while (!scanner.Join(200))
                        {
                            if (!stop.Requested) continue;
                            if (deadline == 0) deadline = Environment.TickCount64 + StopGraceMs;
                            if (Environment.TickCount64 < deadline) continue;
                            pipelineIdle = false;
                            break;
                        }
                    }
                    catch { pipelineIdle = false; }
                }

                files.Clear();
                files.TrimExcess();

                sink.Flush();
                view.Current = "";
                view.Stage = stop.Requested ? "Stopped by user" : "Repair";
                view.Draw(true);

                lock (findingLock) reported = new List<Finding>(findings);

                exit = reported.Count == 0
                    ? 0
                    : ApplyRepairs(reported, settings, options, view, interactive);

                if (pipelineIdle) pipeline.Dispose();
            }
        }
        finally
        {
            ConsoleWindow.Busy = false;
            stop.Done = true;
            painter.Dispose();
            try { watcher?.Join(300); } catch { }
        }

        view.Stopped = stop.Requested;
        view.Finished = true;
        view.Stage = stop.Requested ? "Stopped by user" : "Finished";
        view.Current = "";
        view.Draw(true);

        Finish(view, reported, options, plan, screen, interactive);
        return stop.Requested && exit == 0 ? 7 : exit;
    }

    private static void StartAutoStop(StopFlag stop)
    {
        var value = Environment.GetEnvironmentVariable("MALWARD_STOP_AFTER_MS");
        if (!int.TryParse(value, out int delay) || delay <= 0) return;

        new Thread(() =>
        {
            Thread.Sleep(delay);
            stop.Requested = true;
        })
        { IsBackground = true, Name = "malcsm-autostop" }.Start();
    }

    private static Thread? StartKeyWatch(StopFlag stop, Screen screen, ScanView view)
    {
        if (!screen.Live) return null;
        try { if (Console.IsInputRedirected) return null; }
        catch { return null; }

        var thread = new Thread(() =>
        {
            while (!stop.Done)
            {
                try
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key is ConsoleKey.Q or ConsoleKey.Escape) stop.Requested = true;
                    }
                    if (ConsoleWindow.ClearInterruptFlag())
                    {
                        view.Note("[i] Ctrl+C was blocked while the scan was running - press [Q] to stop it.");
                    }
                }
                catch { return; }
                Thread.Sleep(70);
            }
        })
        { IsBackground = true, Name = "malcsm-keys" };
        thread.Start();
        return thread;
    }

    private static IEnumerable<string> EnumerateFolder(ScanPlan.FolderTarget folder,
                                                       List<string> excluded,
                                                       ConcurrentDictionary<string, byte> seen,
                                                       StopFlag stop)
    {
        bool skipOwn = !IsUnderOwnDirectory(folder.Path);
        foreach (var file in Walk(folder.Path))
        {
            if (stop.Requested) yield break;
            if (!folder.Matches(file)) continue;
            if (skipOwn && IsUnderOwnDirectory(file)) continue;
            if (IsExcluded(file, excluded)) continue;
            if (!seen.TryAdd(file, 0)) continue;
            yield return file;
        }
    }

    private const int MaxListers = 4;

    private const int StopGraceMs = 2500;

    private static List<string> CollectFiles(ScanPlan plan, List<string> excluded,
                                             HashSet<string> done, StopFlag stop,
                                             ScanView view, int already)
    {
        var seen = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in done) seen.TryAdd(path, 0);

        int count = Math.Max(1, Math.Min(MaxListers, plan.Folders.Count));
        int next = -1;
        int found = 0;

        var buckets = new List<string>[count];
        var listers = new Thread[count];

        for (int i = 0; i < count; i++)
        {
            int slot = i;
            buckets[slot] = new List<string>();
            listers[slot] = new Thread(() =>
            {
                var bucket = buckets[slot];
                try
                {
                    while (!stop.Requested)
                    {
                        int index = Interlocked.Increment(ref next);
                        if (index >= plan.Folders.Count) break;

                        var folder = plan.Folders[index];
                        view.Current = folder.Path;

                        foreach (var file in EnumerateFolder(folder, excluded, seen, stop))
                        {
                            bucket.Add(file);
                            int n = Interlocked.Increment(ref found);
                            view.Total = already + n;
                            if ((n & 1023) == 0) view.Current = file;
                        }
                    }
                }
                catch { }
            })
            { IsBackground = true, Name = "malcsm-list-" + slot };
            listers[slot].Start();
        }

        long deadline = 0;
        var usable = new bool[count];
        for (int i = 0; i < count; i++)
        {
            usable[i] = true;
            try
            {
                while (!listers[i].Join(200))
                {
                    if (!stop.Requested) continue;
                    if (deadline == 0) deadline = Environment.TickCount64 + StopGraceMs;
                    if (Environment.TickCount64 < deadline) continue;
                    usable[i] = false;
                    break;
                }
            }
            catch { usable[i] = false; }
        }

        var files = new List<string>(found);
        for (int i = 0; i < count; i++)
            if (usable[i]) files.AddRange(buckets[i]);
        return files;
    }

    private static bool Record(ScanView view, DetectionResult result,
                               List<Finding> findings, object findingLock)
    {
        if (result.Verdict == Verdict.Error)
        {
            Interlocked.Increment(ref view.Errors);
            view.AddError(ErrorLine(result.Path,
                string.IsNullOrEmpty(result.Error) ? "scan error" : result.Error));
            return false;
        }

        if (result.Verdict == Verdict.Skipped && IsReportableSkip(result.Source))
        {
            Interlocked.Increment(ref view.Errors);
            view.AddError(SkipLine(result));
            return false;
        }

        if (result.Verdict != Verdict.Malware) return false;

        lock (findingLock) findings.Add(new Finding(result));
        Interlocked.Increment(ref view.Infections);
        if (result.Source == ScanPipeline.UnverifiedSource)
            Interlocked.Increment(ref view.Unverified);
        view.AddDetection(result.Detection ?? "unknown",
                          result.ArchiveEntry is { Length: > 0 } entry
                              ? result.Path + " >> " + entry
                              : result.Path,
                          Method(result.Source));
        view.Draw(true);
        return true;
    }

    private static bool IsReportableSkip(string? source)
        => source is "Skipped:blocked" or "Skipped:locked" or "Skipped:encrypted-archive";

    private static string SkipLine(DetectionResult result) => result.Source switch
    {
        "Skipped:blocked" => $"FILE - {result.Path} is PROTECTED, CANNOT BE SCANNED RIGHT NOW",
        "Skipped:locked" => $"FILE - {result.Path} is USED BY ANOTHER PROCESS, CANNOT BE SCANNED",
        _ => $"FILE - {result.Path} is PROTECTED BY AN ARCHIVE PASSWORD, SKIPPING",
    };

    private static string ErrorLine(string path, string message)
        => $"FILE - {path}: {message}";

    public static string Method(string? source)
    {
        if (string.IsNullOrEmpty(source)) return "unknown";
        if (source.StartsWith("Archive:", StringComparison.Ordinal)) return "Archive";
        if (source.StartsWith("Registry", StringComparison.Ordinal)) return "Registry";
        return source switch
        {
            "VPS" => "Database",
            "VPS+Cloud" => "Database+Cloud",
            ScanPipeline.UnverifiedSource => "Database (raw)",
            ScanPipeline.RescanMalwareSource => "Cloud engines",
            "Cloud:hash" => "Cloud",
            "Cloud:scan" => "Cloud engines",
            "Heur.Generic" => "Heuristics",
            "Heur:Script" => "Heuristics",
            "Script" => "Script",
            "Masquerade" => "Masquerade",
            "CertBlocklist" => "Certificate",
            ScanPipeline.ByodSource => "Driver list",
            _ => source,
        };
    }

    private static void ScanMemory(ScanPipeline pipeline, Settings settings, ScanView view,
                                   List<Finding> findings, object findingLock, StopFlag stop)
    {
        var memory = new Malward.Engine.Memory.ProcessScanner(settings);
        foreach (var result in memory.ScanRunningProcesses(pipeline))
        {
            if (stop.Requested) return;
            view.Current = result.Path;
            view.Scanned++;
            if (result.FileSize > 0) view.Bytes += result.FileSize;
            if (!Record(view, result, findings, findingLock)) view.Draw();
        }
        view.Current = "";
    }

    private static void ScanRegistry(ScanPipeline pipeline, ScanView view, List<Finding> findings,
                                     object findingLock, StopFlag stop)
    {
        var items = new List<RegistryScanner.Item>();
        try { items.AddRange(RegistryScanner.Collect()); }
        catch (Exception ex) { view.AddError("REGISTRY - " + ex.Message); }
        try
        {
            foreach (var point in RegistryLoadPoints.Collect())
                items.Add(new RegistryScanner.Item(point.Location, point.FilePath, point.Kind));
        }
        catch (Exception ex) { view.AddError("REGISTRY - load points: " + ex.Message); }

        foreach (var item in items)
        {
            if (stop.Requested) return;
            view.Current = item.Location;

            DetectionResult result;
            try { result = pipeline.Scan(item.FilePath); }
            catch (Exception ex)
            {
                view.Errors++;
                view.AddError(ErrorLine(item.Location, ex.Message));
                view.Draw();
                continue;
            }

            view.Scanned++;

            var shape = result.Verdict == Verdict.Malware
                ? null : RegistryScanner.ClassifyPersistence(item);
            if (result.Verdict != Verdict.Malware && shape == null) { view.Draw(); continue; }

            var effective = result.Verdict == Verdict.Malware
                ? result
                : result with
                {
                    Verdict = Verdict.Malware,
                    Detection = shape!.Detection,
                    Source = "Registry:heuristic",
                };

            lock (findingLock)
                findings.Add(new Finding(effective) { RegistryLocation = item.Location });
            view.Infections++;
            view.AddDetection(effective.Detection ?? "unknown",
                              item.Location + " -> " + item.FilePath, "Registry");
            view.Draw(true);
        }

        try
        {
            foreach (var indicator in RegistryScanner.CollectIndicators())
            {
                if (stop.Requested) return;
                if (!indicator.Artifact) continue;
                var result = new DetectionResult(indicator.Location, "", Verdict.Malware,
                                                 indicator.Detection, "Registry", 0, 0);
                lock (findingLock)
                    findings.Add(new Finding(result)
                    {
                        RegistryLocation = indicator.Location,
                        RegistryOnly = true,
                    });
                view.Infections++;
                view.AddDetection(indicator.Detection, indicator.Detail, "Registry");
                view.Draw(true);
            }
        }
        catch (Exception ex) { view.AddError("REGISTRY - indicators: " + ex.Message); }

        view.Current = "";
    }

    private static void ScanDrivers(ScanPipeline pipeline, ScanView view, List<Finding> findings,
                                    object findingLock, List<string> excluded,
                                    HashSet<string> done, StopFlag stop)
    {
        var dir = ScanPlan.DriversDir;
        if (!Directory.Exists(dir)) return;

        foreach (var file in Walk(dir))
        {
            if (stop.Requested) return;
            if (IsExcluded(file, excluded)) continue;
            if (!done.Add(file)) continue;

            view.Current = file;

            DetectionResult result;
            try { result = pipeline.Scan(file); }
            catch (Exception ex)
            {
                view.Errors++;
                view.AddError(ErrorLine(file, ex.Message));
                view.Draw();
                continue;
            }

            view.Scanned++;
            if (result.FileSize > 0) view.Bytes += result.FileSize;
            if (!Record(view, result, findings, findingLock)) view.Draw();
        }

        view.Current = "";
    }

    private static void ProbeCloud(Settings settings, ScanView view)
    {
        Task.Run(() =>
        {
            try
            {
                using var client = new Malward.Engine.Cloud.ServerClient(settings);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
                client.GetManifestAsync(cts.Token).GetAwaiter().GetResult();
                view.Cloud = "connected";
            }
            catch { view.Cloud = "unavailable"; }
        });
    }

    private static int ApplyRepairs(List<Finding> findings, Settings settings, ScanOptions options,
                                    ScanView view, bool interactive)
    {
        var fix = options.Fix;

        if (fix == FixMode.Ask)
        {
            var choice = AskRepair(view);
            if (choice == FixMode.Report) fix = FixMode.Report;
            else { fix = choice; settings.RepairMode = choice == FixMode.Delete ? 3 : 2; }
        }

        if (fix == FixMode.Report)
        {
            view.Note("[i] Repair skipped - the threats above were left untouched.");
            view.Draw(true);
            return 1;
        }

        view.Stage = "Repair";
        var repairer = new Repairer(settings);
        int ok = 0, failed = 0;

        foreach (var finding in findings)
        {
            var name = SafeName(finding.Path);
            view.Current = finding.Path;
            view.Note($"[i] Fixing detection - {finding.Detection}.");
            view.Draw(true);

            if (finding.RegistryOnly)
            {
                var removal = RegistryRepair.Remove(finding.RegistryLocation);
                finding.Action = removal.Ok ? "registry-removed" : "failed";
                finding.Detail = removal.Ok ? finding.RegistryLocation : (removal.Error ?? "");
                if (removal.Ok) ok++; else failed++;
                view.Note(removal.Ok
                    ? $"[+] {finding.Detection} fixed (registry entry removed)."
                    : $"[!] {finding.Detection} on {finding.RegistryLocation} was not fixed: {finding.Detail}");
                view.Draw(true);
                continue;
            }

            RepairOutcome outcome;
            try { outcome = repairer.Repair(finding.Result, userInitiated: true); }
            catch (Exception ex)
            {
                failed++;
                finding.Action = "failed";
                finding.Detail = ex.Message;
                view.AddError($"REPAIR - {finding.Detection} on {name}: {ex.Message}");
                view.Draw(true);
                continue;
            }

            finding.Action = outcome.Action;
            finding.Detail = outcome.Detail ?? "";

            if (finding.RegistryLocation.Length > 0)
            {
                var removal = RegistryRepair.Remove(finding.RegistryLocation);
                if (!removal.Ok)
                    view.AddError($"REPAIR - registry entry {finding.RegistryLocation} "
                                  + $"was not removed: {removal.Error}");
            }

            if (outcome.Success && outcome.Action is not ("deferred" or "noop" or "system-skip"))
            {
                ok++;
                view.Note($"[+] {finding.Detection} on {name} fixed ({outcome.Action}).");
            }
            else
            {
                failed++;
                view.AddError($"REPAIR - {finding.Detection} on {name} was not fixed "
                              + $"({outcome.Action}"
                              + (string.IsNullOrEmpty(outcome.Detail) ? "" : ", " + outcome.Detail) + ")");
            }
            view.Draw(true);
        }

        view.Current = "";
        view.Note($"[i] Repaired {ok} of {findings.Count}, {failed} left.");
        view.Draw(true);
        return failed == 0 ? 0 : 1;
    }

    private static FixMode AskRepair(ScanView view)
    {
        var screen = view.Surface;
        if (!screen.Live || Console.IsInputRedirected) return FixMode.Report;

        var box = new List<(string, Tone)>
        {
            ("THREATS FOUND - CHOOSE AN ACTION", Tone.Title),
            ("", Tone.Plain),
            ("[Q] move to quarantine    [D] delete    [S] skip, report only", Tone.Info),
        };

        while (true)
        {
            screen.Clear();
            screen.Sidebar(SidebarInfo());
            int y = screen.ContentTop;
            screen.Put(screen.ContentLeft, y++, "REPAIR", Tone.Title);
            screen.Rule(screen.ContentLeft, y++, screen.ContentWidth);
            y++;
            screen.Box(screen.ContentLeft, y, screen.ContentWidth, box, Tone.Threat);
            screen.Flush(true);

            var key = screen.WaitKey();
            switch (key.Key)
            {
                case ConsoleKey.Q: return FixMode.Quarantine;
                case ConsoleKey.D: return FixMode.Delete;
                case ConsoleKey.S:
                case ConsoleKey.Escape: return FixMode.Report;
            }
        }
    }

    private static void Finish(ScanView view, List<Finding> findings, ScanOptions options,
                               ScanPlan plan, Screen screen, bool interactive)
    {
        string? saved = null;
        if (options.AutoReport) saved = TrySaveReport(view, findings, options, plan);

        if (!screen.Live)
        {
            PlainReport(view, findings, saved);
            return;
        }

        bool inputAvailable;
        try { inputAvailable = !Console.IsInputRedirected; }
        catch { inputAvailable = false; }
        if (!inputAvailable) return;

        while (true)
        {
            view.Draw(true);
            var key = screen.WaitKey();
            if (key.Key == ConsoleKey.S)
            {
                saved = TrySaveReport(view, findings, options, plan);
                view.Note(saved == null ? "[!] Report was not written." : "[+] Report saved: " + saved);
                if (saved != null) view.AddError("REPORT - saved to " + saved);
                continue;
            }
            return;
        }
    }

    private static void PlainReport(ScanView view, List<Finding> findings, string? saved)
    {
        var output = view.Surface.Output;
        output.WriteLine();
        output.WriteLine($"Scanned {view.Scanned} file(s) in {view.Elapsed.TotalSeconds:F1} s, "
                         + $"{findings.Count} threat(s), {view.Errors} error(s).");
        foreach (var finding in findings)
            output.WriteLine($"  {finding.Detection}  {finding.Path}"
                             + (finding.Entry.Length == 0 ? "" : " >> " + finding.Entry)
                             + $"  [{Method(finding.Source)}]  {finding.Action}");
        if (saved != null) output.WriteLine("Report saved: " + saved);
    }

    private static string? TrySaveReport(ScanView view, List<Finding> findings,
                                         ScanOptions options, ScanPlan plan)
    {
        try { return WriteReport(view, findings, options, plan); }
        catch { return null; }
    }

    private static string WriteReport(ScanView view, List<Finding> findings,
                                      ScanOptions options, ScanPlan plan)
    {
        var dir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrEmpty(dir)) dir = AppContext.BaseDirectory;
        var file = System.IO.Path.Combine(dir,
            $"malward-scan-{view.Started:yyyyMMdd-HHmmss}.txt");

        var text = new System.Text.StringBuilder();
        text.AppendLine("Malward Command Tool Utility - scan report");
        text.AppendLine($"Started : {view.Started:yyyy-MM-dd HH:mm:ss}");
        text.AppendLine($"Finished: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        text.AppendLine($"Profile : {plan.Name}{(view.Stopped ? " (stopped by user)" : "")}");
        text.AppendLine($"Repair  : {options.FixLabel}");
        text.AppendLine($"Threads : {options.EffectiveThreads}");
        text.AppendLine();
        text.AppendLine("Detection layers");
        text.AppendLine($"  cloud scan       : {ScanOptions.OnOff(options.CloudScan)}");
        text.AppendLine($"  cloud verify     : {ScanOptions.OnOff(options.CloudVerify)}");
        text.AppendLine($"  cloud cache      : {ScanOptions.OnOff(options.CloudCache)}");
        text.AppendLine($"  skip MS-signed   : {ScanOptions.OnOff(options.SkipSigned)}");
        text.AppendLine("  file whitelist   : on");
        text.AppendLine($"  memory scan      : {ScanOptions.OnOff(options.MemoryScan)}");
        text.AppendLine($"  archives         : {ScanOptions.OnOff(options.Archives)}");
        text.AppendLine($"  heuristics       : {ScanOptions.OnOff(options.Heuristics)}");
        text.AppendLine($"  largest file     : {ScanOptions.Limit(options.MaxFileMb)}");
        text.AppendLine($"  largest archive  : {ScanOptions.Limit(options.ArchiveMaxMb)}");
        text.AppendLine($"  archive nesting  : {options.ArchiveDepth}");
        text.AppendLine($"  extensions       : {options.ExtensionLabel}");
        if (options.CloudWeakened)
        {
            text.AppendLine();
            text.AppendLine("WARNING: the cloud cross-check was off for this scan, so detections");
            text.AppendLine("were not confirmed and some of them may be false positives.");
        }
        if (options.Heuristics)
        {
            text.AppendLine();
            text.AppendLine("WARNING: heuristic analysis was on, which judges files by shape and");
            text.AppendLine("produces false positives more often than signature matching.");
        }
        text.AppendLine();
        text.AppendLine("Databases");
        foreach (var entry in DatabaseInfo.Listed)
        {
            if (!DatabaseInfo.Installed(entry)) continue;
            var build = DatabaseInfo.Version(entry.VersionKey);
            text.AppendLine($"  {entry.Name,-24}{(build.Length == 0 ? "unknown" : build)}");
        }
        text.AppendLine();
        text.AppendLine($"Scanned    : {view.Scanned}");
        text.AppendLine($"Data       : {ScanView.Data(view.Bytes)}");
        text.AppendLine($"Duration   : {view.Elapsed:hh\\:mm\\:ss}");
        text.AppendLine($"Infections : {findings.Count}");
        text.AppendLine($"Errors     : {view.Errors}");
        foreach (var alert in view.Alerts()) text.AppendLine("WARNING: " + alert.TrimStart('!', ' '));
        text.AppendLine();

        text.AppendLine("Detections");
        if (findings.Count == 0) text.AppendLine("  none");
        foreach (var finding in findings)
        {
            text.AppendLine($"  {finding.Detection}");
            text.AppendLine($"    file   : {finding.Path}");
            if (finding.Entry.Length > 0) text.AppendLine($"    entry  : {finding.Entry}");
            text.AppendLine($"    method : {Method(finding.Source)} ({finding.Source})");
            text.AppendLine($"    action : {finding.Action}"
                            + (finding.Detail.Length == 0 ? "" : " - " + finding.Detail));
        }
        text.AppendLine();

        text.AppendLine("Errors");
        var errorLines = view.ErrorLines;
        if (errorLines.Count == 0) text.AppendLine("  none");
        foreach (var line in errorLines) text.AppendLine("  " + line);
        text.AppendLine();

        text.AppendLine("Log");
        foreach (var line in view.Journal) text.AppendLine("  " + line);

        File.WriteAllText(file, text.ToString(), new System.Text.UTF8Encoding(false));
        return file;
    }

    private static string SafeName(string path)
    {
        try { return System.IO.Path.GetFileName(path); }
        catch { return path; }
    }

    private static readonly string OwnDirectory = OwnDirectoryPath();

    private static string OwnDirectoryPath()
    {
        try
        {
            var dir = System.IO.Path.GetFullPath(AppContext.BaseDirectory);
            return dir.TrimEnd(System.IO.Path.DirectorySeparatorChar)
                   + System.IO.Path.DirectorySeparatorChar;
        }
        catch { return ""; }
    }

    private static bool IsUnderOwnDirectory(string path)
    {
        if (OwnDirectory.Length == 0) return false;
        if (path.StartsWith(OwnDirectory, StringComparison.OrdinalIgnoreCase)) return true;
        if (path.Length == OwnDirectory.Length - 1
            && OwnDirectory.StartsWith(path, StringComparison.OrdinalIgnoreCase)) return true;
        if (System.IO.Path.IsPathFullyQualified(path)) return false;

        try
        {
            var full = System.IO.Path.GetFullPath(path)
                       .TrimEnd(System.IO.Path.DirectorySeparatorChar)
                       + System.IO.Path.DirectorySeparatorChar;
            return full.StartsWith(OwnDirectory, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool IsExcluded(string file, List<string> excluded)
    {
        if (excluded.Count == 0) return false;

        string full;
        try { full = System.IO.Path.GetFullPath(file); }
        catch { full = file; }

        foreach (var entry in excluded)
        {
            if (full.Equals(entry, StringComparison.OrdinalIgnoreCase)) return true;
            var prefix = entry.TrimEnd(System.IO.Path.DirectorySeparatorChar)
                         + System.IO.Path.DirectorySeparatorChar;
            if (full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static readonly EnumerationOptions WalkOptions = new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        ReturnSpecialDirectories = false,
        AttributesToSkip = 0,
    };

    private static IEnumerable<string> Walk(string root)
    {
        if (File.Exists(root)) { yield return root; yield break; }
        if (!Directory.Exists(root)) yield break;

        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();

            IEnumerator<FileSystemInfo>? entries;
            try
            {
                entries = new DirectoryInfo(dir)
                    .EnumerateFileSystemInfos("*", WalkOptions).GetEnumerator();
            }
            catch { continue; }

            using (entries)
            {
                while (true)
                {
                    FileSystemInfo entry;
                    try
                    {
                        if (!entries.MoveNext()) break;
                        entry = entries.Current;
                    }
                    catch { break; }

                    FileAttributes attributes;
                    try { attributes = entry.Attributes; }
                    catch { continue; }

                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        stack.Push(entry.FullName);
                        continue;
                    }
                    yield return entry.FullName;
                }
            }
        }
    }
}
