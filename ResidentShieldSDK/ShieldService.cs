using System.Threading.Channels;

namespace Malward.ResidentShield;

public sealed class ShieldService : IAsyncDisposable
{
    private readonly ShieldConfig   _config;
    private readonly ScanEngine     _scanner;
    private readonly ProcessTracker _tracker;

    private readonly ProcessBombGuard _bombGuard;
    private readonly RollbackDb     _rollback;
    private readonly Notifier       _notify;
    private readonly ThreatHandler  _handler;
    private readonly ScanQueue      _queue;
    private readonly ActivityReporter _activity = new();

    private FileWatcher?        _fileWatcher;
    private UsnJournalMonitor?  _usn;
    private UserFolderWatcher?  _userFolders;
    private EtwMonitor?         _etw;
    private WmiProcessMonitor?  _wmi;
    private HookPipe?           _pipe;
    private RemovableScanWatcher? _removable;
    private Timer?              _bootBackupTimer;
    private Hips.HipsFileWatcher?     _hipsFiles;
    private Hips.HipsRegistryWatcher? _hipsRegistry;
    private Hips.HipsWmiWatcher?      _hipsWmi;
    private Hips.HipsInjectionWatcher? _hipsInjection;
    private Timer?                    _hipsSupervisor;
    private Timer?                    _folderGuard;

    private readonly CancellationTokenSource _cts = new();

    private readonly Channel<ScanEvent> _priority;
    private readonly Channel<ScanEvent> _normal;
    private readonly Task[]             _workers;

    private static readonly HashSet<string> OwnBinaryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "malward.exe", "malscan.exe", "heurscanner.exe", "mwshield.exe",
        "rsmonitor.exe",   
        "residentshield.exe", "shieldhook.dll",
    };

    private static readonly string DotNetTempDir = Path.Combine(Path.GetTempPath(), ".net");

    public ShieldService(ShieldConfig config)
    {
        _config   = config;
        _scanner  = new ScanEngine(config);
        _tracker  = new ProcessTracker();
        _bombGuard = new ProcessBombGuard(_tracker);
        _rollback = new RollbackDb();
        _notify   = new Notifier();
        _handler  = new ThreatHandler(config, _rollback, _tracker, _notify);
        _handler.AttachBombGuard(_bombGuard);
        _queue    = new ScanQueue(config.DedupWindowMs);

        _priority = Channel.CreateUnbounded<ScanEvent>(new UnboundedChannelOptions
        {
            SingleWriter = false, SingleReader = false,
        });
        _normal   = Channel.CreateBounded<ScanEvent>(new BoundedChannelOptions(config.QueueCapacity)
        {
            FullMode     = BoundedChannelFullMode.DropOldest,
            SingleWriter = false, SingleReader = false,
        });

        _workers = new Task[Math.Max(1, config.ScanWorkers)];
    }

    public void Start()
    {
        var ct = _cts.Token;

        AutoExcludeSelfDirectory();
        _activity.Start();

        for (int i = 0; i < _workers.Length; i++)
            _workers[i] = Task.Run(() => ScanWorkerAsync(ct), ct);

        if (_config.FileMonitorEnabled)
        {
            var usnVolumes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (_config.UsnJournalEnabled)
            {
                try
                {
                    _usn = new UsnJournalMonitor(_config, OnFileEvent);
                    usnVolumes = UsnJournalMonitor.NtfsFixedVolumes();
                    _usn.Start();
                }
                catch (Exception ex)
                {
                    Log.Warn("USN", $"Failed to start — FSW takes over everything: {ex.Message}");
                    _usn = null;
                    usnVolumes.Clear();
                }
            }

            _fileWatcher = new FileWatcher(_config, OnFileEvent, usnVolumes);
            _fileWatcher.Start();

            _userFolders = new UserFolderWatcher(OnFileEvent);
            _userFolders.Start();
        }

        if (_config.ProcessMonitorEnabled)
        {
            _etw = new EtwMonitor(_config, _tracker, _rollback, OnBehaviorAlert, OnFileEvent, _bombGuard,
                                  (detector, path) => _hips.Decide(detector, path) != null);
            _etw.Start(ct);

            _wmi = new WmiProcessMonitor(_config, _tracker, OnFileEvent);
            _wmi.Start();
        }

        _pipe = new HookPipe(_scanner, _config, ct);
        _pipe.Start();

        if (_config.ScanRemovable)
        {
            _removable = new RemovableScanWatcher(_scanner.MalscanPath);
            _removable.Start();
        }

        Malward.NetworkScanner.DangerousConnectionBus.Handler = OnDangerousConnection;

        _hipsSupervisor = new Timer(_ => SyncHipsWatchers(), null, TimeSpan.Zero, TimeSpan.FromSeconds(3));

        _folderGuard = new Timer(_ => InstallFolderGuard.VerifyAll(), null,
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));

        if (_config.BootBackup)
            _bootBackupTimer = new Timer(_ => RunBootBackup(), null,
                TimeSpan.FromSeconds(20), TimeSpan.FromHours(24));

        if (_config.AutoScanOnStartup)
            EnqueueSystemScan();

        Log.Info("Shield", "Resident protection active.");
    }

    public async Task StopAsync()
    {
        Log.Info("Shield", "Stopping...");
        _cts.Cancel();
        _priority.Writer.TryComplete();
        _normal.Writer.TryComplete();
        Malward.NetworkScanner.DangerousConnectionBus.Handler = null;
        _activity.Stop();
        _usn?.Stop();
        _userFolders?.Stop();
        _fileWatcher?.Stop();
        _etw?.Stop();
        _wmi?.Dispose();
        _pipe?.Dispose();
        _removable?.Stop();
        _hipsSupervisor?.Dispose();
        _folderGuard?.Dispose();
        _hipsFiles?.Dispose();
        _hipsRegistry?.Dispose();
        _hipsWmi?.Dispose();
        _hipsInjection?.Dispose();
        _bootBackupTimer?.Dispose();

        try { await Task.WhenAll(_workers).WaitAsync(TimeSpan.FromSeconds(5)); }
        catch {  }

        Log.Info("Shield", "Stopped.");
    }

    public Task<bool> ReconfigureAsync(CancellationToken ct)
    {
        try
        {
            var fresh = ShieldConfig.Load(null);

            bool structuralChange =
                fresh.FileMonitorEnabled != _config.FileMonitorEnabled ||
                fresh.UsnJournalEnabled  != _config.UsnJournalEnabled  ||
                fresh.ActiveProcessScan  != _config.ActiveProcessScan  ||
                fresh.ScanRemovable      != _config.ScanRemovable;

            if (structuralChange)
            {
                Log.Info("Shield", "Settings change affects which monitors run — a module rebuild is needed.");
                return Task.FromResult(false);
            }

            _config.CopyFrom(fresh);
            _fileWatcher?.ApplySettings();
            SyncHipsWatchers();

            Log.Info("Shield", "Settings applied without stopping protection.");
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            Log.Warn("Shield", $"Could not apply settings in place ({ex.GetType().Name}: {ex.Message}) — falling back to a module rebuild.");
            return Task.FromResult(false);
        }
    }

    private void SyncHipsWatchers()
    {
        try
        {
            try { Hips.HipsRequests.ProcessPending(); } catch { }

            bool want = _hips.EnabledNow;

            if (want && _hipsFiles == null)
            {
                Hips.HipsFileWatcher.IsMalwareHook = p =>
                {
                    try { return _scanner.QuickVerdict(p).Verdict == ScanVerdict.Threat; }
                    catch { return false; }
                };
                _hipsFiles = new Hips.HipsFileWatcher(_hips, _activity, _notify);
                _hipsFiles.Start();
                _hipsRegistry = new Hips.HipsRegistryWatcher(_hips, _activity, _notify);
                _hipsRegistry.Start();
                _hipsWmi = new Hips.HipsWmiWatcher(_hips, _activity, _notify);
                _hipsWmi.Start();
                _hipsInjection = new Hips.HipsInjectionWatcher(_hips, _activity, _notify);
                _hipsInjection.Start();
            }
            else if (!want && _hipsFiles != null)
            {
                _hipsFiles.Dispose();   _hipsFiles = null;
                _hipsRegistry?.Dispose(); _hipsRegistry = null;
                _hipsWmi?.Dispose();      _hipsWmi = null;
                _hipsInjection?.Dispose(); _hipsInjection = null;
                Log.Info("HIPS", "System component protection disabled — watchers stopped.");
            }
        }
        catch (Exception ex) { Log.Debug("HIPS", ex.Message); }
    }

    private void OnFileEvent(ScanEvent ev)
    {
        if (OwnBinaryNames.Contains(Path.GetFileName(ev.FilePath))
            || SystemGuard.IsOwnComponent(ev.FilePath))
            return;

        var excl = _config.ExcludedPaths;
        for (int i = 0; i < excl.Count; i++)
            if (ev.FilePath.StartsWith(excl[i], StringComparison.OrdinalIgnoreCase))
                return;

        if (IsDotNetRuntimeFile(ev.FilePath))
            return;

        if (_hipsFiles != null && ev.Kind != ScanEventKind.ProcessStarted)
            _hipsFiles.Inspect(ev.FilePath);

        if (ev.Kind == ScanEventKind.ProcessStarted && ev.Pid is int pid && pid > 0
            && (!SystemGuard.IsProtectedPath(ev.FilePath) || IsInterpreter(ev.FilePath))
            && File.Exists(ev.FilePath))
        {
            if (!_procGateSeen.TryAdd(pid + "|" + ev.FilePath, Environment.TickCount64))
                return;
            if (_procGateSeen.Count > 512) PruneProcGate();

            NativeProcess.Suspend(pid);
            _ = Task.Run(() => QuickGateAsync(pid, ev));
            return;
        }

        Enqueue(ev);
    }

    private static HashSet<string>? _interpreterNames;
    private static HashSet<string> InterpreterNames =>
        _interpreterNames ??= new HashSet<string>(
            Malward.Engine.Data.SignatureStore.List("interpreter_images"), StringComparer.OrdinalIgnoreCase);

    private static bool IsInterpreter(string path)
    {
        try { return InterpreterNames.Contains(Path.GetFileName(path)); }
        catch { return false; }
    }

    internal static string? ScriptTargetFromCommandLine(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;

        string[] exts =
        {
            ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".hta", ".jar", ".py", ".scr", ".exe", ".dll", ".com", ".msi", ".lnk", ".sct", ".xsl",
        };
        foreach (var raw in SplitArgs(commandLine).Skip(1))
        {
            var arg = raw.Trim().Trim('"');
            if (arg.Length < 4 || arg.StartsWith('-') || arg.StartsWith('/')) continue;

            int comma = arg.IndexOf(',');
            if (comma > 0 && arg.IndexOf('\\') >= 0) arg = arg[..comma];
            if (!exts.Any(e => arg.EndsWith(e, StringComparison.OrdinalIgnoreCase))) continue;
            try { if (File.Exists(arg)) return Path.GetFullPath(arg); } catch { }
        }
        return null;
    }

    private static IEnumerable<string> SplitArgs(string cmd)
    {
        var sb = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (char c in cmd)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (c == ' ' && !inQuotes)
            {
                if (sb.Length > 0) { yield return sb.ToString(); sb.Clear(); }
                continue;
            }
            sb.Append(c);
        }
        if (sb.Length > 0) yield return sb.ToString();
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _procGateSeen = new();
    private const long ProcGateWindowMs = 15_000;

    private void PruneProcGate()
    {
        long now = Environment.TickCount64;
        foreach (var kv in _procGateSeen)
            if (now - kv.Value > ProcGateWindowMs) _procGateSeen.TryRemove(kv.Key, out _);
    }

    private static bool IsHardRansomSignal(string? category) => category switch
    {
        "Ransomware" or "RansomNote" or "EncryptionEntropy" or "RansomExtension"
            or "ShadowCopyDeletion" or "RawDiskWrite" => true,
        _ => false,
    };

    private void Enqueue(ScanEvent ev)
    {
        if (!_queue.TryEnqueue(ev)) return;
        if (ev.Kind == ScanEventKind.FileModified)
            _normal.Writer.TryWrite(ev);
        else
            _priority.Writer.TryWrite(ev);
    }

    private async Task QuickGateAsync(int pid, ScanEvent ev)
    {
        try
        {
            string subject = ev.FilePath;
            if (IsInterpreter(ev.FilePath))
            {
                string cmd = "";
                try { cmd = _tracker.GetProcess(pid)?.CommandLine ?? ""; } catch { }
                var target = ScriptTargetFromCommandLine(cmd);
                if (target != null && !SystemGuard.IsOwnComponent(target))
                {
                    subject = target;
                    Log.Info("Gate", $"{Path.GetFileName(ev.FilePath)} launches: {target}");
                }
                else
                {
                    NativeProcess.Resume(pid);
                    return;
                }
            }

            var r = _scanner.QuickVerdict(subject, out var rep);

            try
            {
                var fi = new FileInfo(subject);
                _tracker.SetReputation(pid, new RepRecord(rep, subject,
                    fi.Exists ? fi.Length : 0, fi.Exists ? fi.LastWriteTimeUtc : default));
            }
            catch { }

            if (r.Verdict == ScanVerdict.Threat)
            {
                Log.Alert("Gate", $"BLOCKED before execution: {Path.GetFileName(subject)} → {r.ThreatName}");
                await _handler.HandleAsync(r, pid, _cts.Token);
                return;
            }

            if (_config.PreLaunchAnalysis && ShouldDeepGate(subject))
            {
                if (_config.Notifications)
                    _notify.Info("Analyzing launched file",
                        $"Scanning: {Path.GetFileName(subject)} — please wait…");

                ScanResult? full = null;
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                    cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(2, _config.PreLaunchTimeoutSec)));
                    full = await _scanner.ScanAsync(subject, cts.Token);
                }
                catch (OperationCanceledException) {  }
                catch (Exception ex) { Log.Error("Gate", $"deep {subject}: {ex.Message}"); }

                if (full != null && full.Verdict is ScanVerdict.Threat or ScanVerdict.Suspicious)
                {
                    Log.Alert("Gate", $"BLOCKED after full scan: {Path.GetFileName(subject)} → {full.ThreatName}");
                    await _handler.HandleAsync(full, pid, _cts.Token);
                    return;
                }
                NativeProcess.Resume(pid);

                if (full == null) Enqueue(ev);
                return;
            }
        }
        catch (Exception ex) { Log.Error("Gate", $"{ev.FilePath}: {ex.Message}"); }

        NativeProcess.Resume(pid);
        Enqueue(ev);
    }

    private static bool ShouldDeepGate(string path)
    {
        try
        {
            if (SystemGuard.IsProtectedPath(path) || SystemGuard.IsOwnComponent(path)) return false;
            if (SystemGuard.IsTrustedImage(path)) return false;
            if (SystemGuard.HasValidSignature(path)) return false;
            return true;
        }
        catch { return false; }
    }

    private void RunBootBackup()
    {
        try
        {
            Malward.BackupEngine.BootSectorGuard.Backup();
            Log.Info("Boot", "Boot sector backup completed.");
        }
        catch (Exception ex)
        {
            Log.Warn("Boot", $"Boot sector backup failed: {ex.Message}");
        }
    }

    private static bool IsDotNetRuntimeFile(string path)
    {
        if (path.StartsWith(DotNetTempDir, StringComparison.OrdinalIgnoreCase))
            return true;
        var name = Path.GetFileName(path);
        return name.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase);
    }

    private readonly Hips.HipsConfig _hips = new();

    private bool IsExcludedImage(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        var excl = _config.ExcludedPaths;
        for (int i = 0; i < excl.Count; i++)
            if (imagePath.StartsWith(excl[i], StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private bool StrictProfile => _hips.Tier is "high" or "paranoic";

    private void OnDangerousConnection(Malward.NetworkScanner.DangerousConnection c)
    {
        if (string.IsNullOrEmpty(c.ImagePath) || !File.Exists(c.ImagePath)) return;
        if (c.Pid <= 4 || c.Pid == Environment.ProcessId) return;
        if (Hips.HipsSelfGuard.IsOwnProcessTree(c.Pid)) return;

        var proc = new ProcessInfo(c.Pid, 0, c.ProcessName, c.ImagePath, "", DateTimeOffset.UtcNow);
        var alert = new BehaviorAlert(c.Pid, c.ProcessName, BehaviorSeverity.High, c.Detection,
            $"Connection to a known malicious address {c.RemoteIp}:{c.RemotePort} "
            + "from the malicious-address database");

        OnBehaviorAlert(alert, proc);
    }

    private void OnBehaviorAlert(BehaviorAlert alert, ProcessInfo proc)
    {
        if (IsExcludedImage(proc.ImagePath) && (!IsHardRansomSignal(alert.Category) || !StrictProfile))
        {
            Log.Info("Behavior", $"Excluded by the user, alert ignored: {alert.Category} PID {proc.Pid} ({proc.ImagePath})");
            return;
        }

        Log.Alert("Behavior", $"[{alert.Severity}] {alert.Category} | PID {proc.Pid} " +
            $"{proc.Name}: {alert.Description}");

        var decision = _hips.Decide(alert.Category, proc.ImagePath);
        if (decision is { } d)
        {
            if (d.Mode == Hips.HipsRules.Mode.Log)
            {
                Log.Info("HIPS", $"[{d.Rule.Name}] log only: PID {proc.Pid} ({proc.Name}) — {alert.Description}");
                _activity.ReportHips(d.Rule.Id, d.Rule.Name, proc.Name, proc.ImagePath, alert.Description, "log");
                return;
            }
            _activity.ReportHips(d.Rule.Id, d.Rule.Name, proc.Name, proc.ImagePath, alert.Description,
                                 d.Mode == Hips.HipsRules.Mode.Block ? "block" : "ask");

            if (d.Mode == Hips.HipsRules.Mode.Ask)
            {
                Log.Alert("HIPS", $"[{d.Rule.Name}] PID {proc.Pid} ({proc.Name}) — " +
                    "reported (mode: ask, no automatic reaction)");
                _notify.Threat("Suspicious behavior detected", proc.ImagePath, d.Rule.Name, AlertSeverity.Medium);
                return;
            }
        }
        else if (_hips.Enabled && Hips.HipsRules.ForDetector(alert.Category).Any())
        {
            Log.Debug("HIPS", $"Rule disabled by the user — skipping {alert.Category} for PID {proc.Pid}.");
            return;
        }

        try { NativeProcess.Suspend(proc.Pid); } catch { }

        Task.Run(async () =>
        {
            try
            {
                var rep = _tracker.GetReputation(proc.Pid, proc.ImagePath);
                if (rep == ProcRep.Unknown)
                {
                    try { if (_scanner.IsBehaviorTrusted(proc.ImagePath)) rep = ProcRep.Whitelisted; }
                    catch { }
                }

                if (rep is ProcRep.Whitelisted or ProcRep.SystemTrusted)
                {
                    if (!IsHardRansomSignal(alert.Category))
                    {
                        Log.Info("Behavior", $"Alert {alert.Category} for PID {proc.Pid} ({proc.Name}) " +
                                             $"— trusted program ({rep}); NO automatic rollback of changes.");
                        try { NativeProcess.Resume(proc.Pid); } catch { }
                        return;
                    }

                    if (!StrictProfile)
                    {
                        Log.Info("Behavior", $"Alert {alert.Category} for PID {proc.Pid} ({proc.Name}) — " +
                                             $"trusted program ({rep}); profile \"{_hips.Tier}\" lets it continue " +
                                             "and waits for the scan verdict instead of reacting.");
                        try { NativeProcess.Resume(proc.Pid); } catch { }
                        return;
                    }

                    Log.Alert("Behavior", $"Alert {alert.Category} for PID {proc.Pid} ({proc.Name}) — " +
                                          $"trusted program ({rep}), but the signal is hard → full reaction.");
                }

                await _handler.HandleBehaviorAsync(alert, proc, _cts.Token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Log.Error("Shield", $"Alert handling error: {ex.Message}"); }
        });
    }

    private async Task ScanWorkerAsync(CancellationToken ct)
    {
        var pr = _priority.Reader;
        var nr = _normal.Reader;
        Task<bool>? pWait = null;
        Task<bool>? nWait = null;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (pr.TryRead(out var ev) || nr.TryRead(out ev))
                {
                    await ProcessEventAsync(ev, ct);
                    continue;
                }

                pWait ??= pr.WaitToReadAsync(ct).AsTask();
                nWait ??= nr.WaitToReadAsync(ct).AsTask();

                var done = await Task.WhenAny(pWait, nWait);
                if (done == pWait) pWait = null; else nWait = null;

                if (pr.Completion.IsCompleted && nr.Completion.IsCompleted)
                    break;
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task ProcessEventAsync(ScanEvent ev, CancellationToken ct)
    {
        try
        {
            _activity.SetCurrentFile(ev.FilePath);
            var result = await _scanner.ScanAsync(ev.FilePath, ct);

            _activity.ReportScanned(ev.FilePath, result.Verdict.ToString(), result.ThreatName,
                                    result.CloudChecked,
                                    showInFeed: ev.Kind != ScanEventKind.ProcessStarted);

            if (result.Verdict == ScanVerdict.Threat)
                Log.Alert("Scan", $"THREAT {Path.GetFileName(ev.FilePath)} | {result.ThreatName}");
            else
                Log.Debug("Scan", $"{result.Verdict,-9} {Path.GetFileName(ev.FilePath)}");

            if (result.Verdict is ScanVerdict.Threat or ScanVerdict.Suspicious)
                _ = Task.Run(() => _handler.HandleAsync(result, ev.Pid, ct), ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Error("Worker", $"Scan error {ev.FilePath}: {ex.Message}");
        }
    }

    private void EnqueueSystemScan()
    {
        Task.Run(() =>
        {
            Log.Info("Shield", "Startup auto-scan...");

            var dirs = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            string[] ext = { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js" };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (!ext.Contains(Path.GetExtension(file).ToLowerInvariant())) continue;
                        OnFileEvent(new ScanEvent(ScanEventKind.ManualScan, file, 0, "", DateTimeOffset.UtcNow));
                    }
                }
                catch {  }
            }
        }, _cts.Token);
    }

    private void AutoExcludeSelfDirectory()
    {
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var selfPath = Environment.ProcessPath ?? "";
        if (!string.IsNullOrEmpty(selfPath))
            dirs.Add(Path.GetDirectoryName(selfPath) ?? "");

        if (!string.IsNullOrEmpty(_scanner.MalscanPath))
            dirs.Add(Path.GetDirectoryName(_scanner.MalscanPath) ?? "");

        dirs.Add(DotNetTempDir);

        foreach (var dir in dirs)
        {
            if (string.IsNullOrEmpty(dir)) continue;
            var key = dir.TrimEnd('\\') + "\\";

            if (!_config.ExcludedPaths.Any(p => p.Equals(key, StringComparison.OrdinalIgnoreCase)))
            {
                _config.Exclusions.Add(new ExclusionEntry { Path = key, Scope = "shield" });
                Log.Info("Shield", $"Auto-excluded: {key}");
            }
        }
    }

    public void TriggerSignatureUpdateScan()
    {
        if (!_config.AutoScanOnSigUpdate) return;
        Log.Info("Shield", "Scan after signature update.");
        EnqueueSystemScan();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _usn?.Dispose();
        _userFolders?.Dispose();
        _fileWatcher?.Dispose();
        _scanner.Dispose();
        _rollback.Dispose();
        _cts.Dispose();
    }
}
