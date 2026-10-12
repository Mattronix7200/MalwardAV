namespace Malward.ResidentShield;

public sealed class ThreatHandler
{
    private readonly ShieldConfig   _config;
    private readonly RollbackDb     _rollback;
    private readonly ProcessTracker _tracker;
    private readonly Notifier       _notify;
    private readonly NotifyBus      _bus = new();
    private readonly BackupEngineIpcClient _backupIpc;

    private static readonly string QuarantineDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "quarantine");

    private ProcessBombGuard? _bombGuard;

    private static readonly AsyncLocal<List<(string Stored, string Original)>?> _quarantineLog = new();

    private static readonly AsyncLocal<List<string>?> _pendingReboot = new();

    public void AttachBombGuard(ProcessBombGuard guard) => _bombGuard = guard;

    public ThreatHandler(ShieldConfig config, RollbackDb rollback,
        ProcessTracker tracker, Notifier notify)
    {
        _config   = config;
        _rollback = rollback;
        _tracker  = tracker;
        _notify   = notify;
        _backupIpc = new BackupEngineIpcClient(
            string.IsNullOrEmpty(config.BackupEnginePipe) ? "malward-backup" : config.BackupEnginePipe);
    }

    public async Task HandleAsync(ScanResult result, int? pid = null, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(result.ThreatName))
        {
            Log.Debug("Threat", $"Neutralisation skipped — no detection name ({result.Detail ?? "none"}): {result.FilePath}");
            return;
        }

        string threat = result.ThreatName;

        if (IsExcludedFile(result.FilePath))
        {
            Log.Info("Threat", $"Excluded by the user — no action and no alert: {result.FilePath}");
            return;
        }

        int effectivePid = pid ?? 0;
        bool behavioral = false;
        if (effectivePid <= 0 && _config.ActiveProcessScan
            && !string.IsNullOrEmpty(result.FilePath))
        {
            foreach (var candidate in _tracker.FindProcessesTouchingFile(result.FilePath))
            {
                if (candidate <= 4 || candidate == Environment.ProcessId || IsCriticalPid(candidate)) continue;
                var img = NativeProcess.GetImagePath(candidate);

                if (SystemGuard.IsUntouchable(img) && !SystemGuard.IsInQuarantine(img)) continue;

                if (!string.IsNullOrEmpty(img) && _config.ExcludedPaths.Any(p => img.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
                effectivePid = candidate;
                behavioral = true;
                break;
            }
        }

        if (behavioral)
        {
            var info = _tracker.GetProcess(effectivePid);
            string name = $"Behaviour.Suspicious ({threat})";
            Log.Warn("Behavior", $"Process PID {effectivePid} ({info?.Name}) dropped/modified " +
                                 $"known malware: {result.FilePath} -> {name}");
            _notify.Threat("Suspicious process behaviour",
                info?.ImagePath ?? result.FilePath, "Behaviour.Suspicious", AlertSeverity.High);

            await NeutralizeAsync(effectivePid, result.FilePath, name, ct, rollbackFiles: true,
                                  source: "Behaviour");
            return;
        }

        _notify.Threat("Threat detected", result.FilePath, threat,
            result.Verdict == ScanVerdict.Threat ? AlertSeverity.High : AlertSeverity.Medium);
        await NeutralizeAsync(pid, result.FilePath, threat, ct, rollbackFiles: false,
                              source: result.Detail ?? "");
    }

    private bool IsExcludedFile(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var excl = _config.ExcludedPaths;
        for (int i = 0; i < excl.Count; i++)
            if (path.StartsWith(excl[i], StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    public async Task HandleBehaviorAsync(BehaviorAlert alert, ProcessInfo proc,
        CancellationToken ct = default)
    {
        string name = BehaviorThreatName(alert.Category);
        _notify.Threat("Behavioural threat", proc.ImagePath, name, AlertSeverity.High);

        await NeutralizeAsync(proc.Pid, proc.ImagePath, name, ct, rollbackFiles: true,
                              source: "Behaviour");

        TrySubmitBehavioral(proc.ImagePath, name);
    }

    private void TrySubmitBehavioral(string? filePath, string threat)
    {
        try
        {
            if (!_config.CloudEnabled) return;
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;
            if (SystemGuard.IsUntouchableForRepair(filePath)) return;

            var path = filePath;
            _ = Task.Run(() =>
            {
                try
                {
                    using var sink = new StringWriter();
                    Malward.Engine.EngineHost.RunSubmitDetection(
                        new[] { "submit-detection", path!, "--name", threat }, sink);
                }
                catch (Exception ex) { Log.Debug("Submit", ex.Message); }
            });
        }
        catch {  }
    }

    private static string? _malscanPath;
    private static bool _malscanResolved;
    private static string? MalscanPathLazy
    {
        get
        {
            if (_malscanResolved) return _malscanPath;
            _malscanResolved = true;
            try
            {
                var p = Path.Combine(AppContext.BaseDirectory, "malscan.exe");
                _malscanPath = File.Exists(p) ? p : null;
            }
            catch { _malscanPath = null; }
            return _malscanPath;
        }
    }

    private static string BehaviorThreatName(string category)
    {
        var c = (category ?? "").Trim();
        if (c.Length == 0) return "Behaviour.Suspicious";
        if (c.Contains('.') || c.Contains('@')) return c;   
        return "Behaviour." + c;
    }

    private async Task NeutralizeAsync(int? pid, string filePath, string threat,
        CancellationToken ct, bool rollbackFiles = false, string source = "")
    {
        bool inQuar = SystemGuard.IsInQuarantine(filePath);
        bool fileUntouchable = SystemGuard.IsUntouchableForRepair(filePath) && !inQuar;

        int targetPid = pid ?? FindPidByImage(filePath);
        if (targetPid > 0 && IsCriticalPid(targetPid)) targetPid = 0;

        string offenderImg = (pid.HasValue && pid.Value > 4 && !IsCriticalPid(pid.Value))
            ? NativeProcess.GetImagePath(pid.Value) : "";
        if (string.IsNullOrEmpty(offenderImg))
        {
            try
            {
                foreach (var cand in _tracker.FindProcessesTouchingFile(filePath))
                {
                    if (cand <= 4 || cand == Environment.ProcessId) continue;
                    var img = NativeProcess.GetImagePath(cand);
                    if (!string.IsNullOrEmpty(img)
                        && !string.Equals(img, filePath, StringComparison.OrdinalIgnoreCase))
                    { offenderImg = img; break; }
                }
            }
            catch { }
        }
        if (string.IsNullOrEmpty(offenderImg) && targetPid > 0)
        {
            try
            {
                foreach (var anc in NativeProcess.GetAncestors(targetPid))
                {
                    if (anc <= 4) continue;
                    var img = NativeProcess.GetImagePath(anc);
                    if (!string.IsNullOrEmpty(img)) { offenderImg = img; break; }
                }
            }
            catch { }
        }
        if (string.IsNullOrEmpty(offenderImg))
            offenderImg = targetPid > 0 ? NativeProcess.GetImagePath(targetPid) : "";

        if (fileUntouchable && targetPid <= 0)
        {
            Log.Warn("Threat", $"Skipped (system/own file — possible false positive): {filePath}");
            return;
        }

        var malwarePaths = fileUntouchable ? new List<string>() : CollectMalwarePaths(filePath, targetPid);

        var killSet = BuildKillSet(targetPid, malwarePaths, filePath);

        foreach (var p in killSet) NativeProcess.Suspend(p);

        bool delete;
        if (_config.RepairMode == RepairMode.Ask)
        {
            var dec = await Task.Run(() => _bus.AskDecision(filePath, threat, ct, process: offenderImg), ct);
            delete = dec == NotifyBus.Decision.Delete;
        }
        else
        {
            delete = _config.RepairMode == RepairMode.Delete;
        }

        int killed = 0;
        foreach (var p in killSet) if (KillWithRetry(p)) killed++;

        int persist = 0;
        if (malwarePaths.Count > 0)
        {
            bool deep = TreeTouchedPersistence(targetPid, killSet);
            var cleaner = new PersistenceCleaner(malwarePaths);
            persist = cleaner.CleanAll(deep);

            if (targetPid > 0)
                persist += cleaner.CleanAttributedRegistry(CollectTreeRegistryChanges(targetPid));
        }

        await Task.Delay(150, ct);

        var quarantined = new List<(string Stored, string Original)>();
        _quarantineLog.Value = quarantined;
        var pending = new List<string>();
        _pendingReboot.Value = pending;
        int handled = 0;

        var unresolved = new List<string>();
        foreach (var mp in malwarePaths)
        {
            if (delete ? DeleteFile(mp) : QuarantineFile(mp, threat)) handled++;
            else if (File.Exists(mp)) unresolved.Add(mp);
        }

        int rolledBack = 0;
        RollbackResult? backupResult = null;
        var restoredPaths = new List<string>();
        if (rollbackFiles && targetPid > 0)
        {
            rolledBack = RollbackProcessFileChanges(targetPid, threat, delete);

            if (_config.AutoRestoreRansomware)
                backupResult = await RestoreFromBackupEngineAsync(targetPid, ct, restoredPaths);
        }
        int restoredFromBackup = backupResult?.Restored ?? 0;

        _rollback.AuditNeutralize(targetPid, filePath, killed, handled + rolledBack, persist);

        if (unresolved.Count > 0)
        {
            string list = string.Join(", ", unresolved.Select(Path.GetFileName).Take(5));
            _notify.Threat($"Failed to resolve {unresolved.Count} detected threat(s)",
                           unresolved[0], threat, AlertSeverity.High);
            Log.Error("Threat", $"Failed to resolve {unresolved.Count} detected threat(s): {list}");
        }

        try { _bombGuard?.MarkThreat(targetPid, filePath, threat); } catch { }

        string actionWord = delete ? "Threat deleted" : "Neutralised";
        string rb = rolledBack > 0 ? $", changes reverted: {rolledBack}" : "";

        string pend = pending.Count > 0 ? $", awaiting restart: {pending.Count}" : "";
        _notify.Action(actionWord, filePath,
            $"{threat} — processes: {killed}, files: {handled - pending.Count}, " +
            $"persistence: {persist}{rb}{pend}");

        if (rollbackFiles)
        {
            var title = restoredFromBackup > 0
                ? "Zatrzymano atak ransomware — przywrócono pliki"
                : "Zatrzymano atak behawioralny";
            var body = $"Wykryto i zatrzymano zagrożenie ({threat}) — {Path.GetFileName(filePath)} (PID {targetPid}). " +
                       $"Zakończono procesów: {killed}; pliki (usunięte/kwarantanna): {handled + rolledBack - pending.Count}; " +
                       (pending.Count > 0
                          ? $"do usunięcia po ponownym uruchomieniu: {pending.Count}; "
                          : "") +
                       $"mechanizmy trwałości usunięte: {persist}; " +
                       (restoredFromBackup > 0
                          ? $"przywrócono z kopii: {restoredFromBackup}."
                          : "brak plików do przywrócenia z kopii (lub kopia niedostępna).");
            _notify.Info(
                restoredFromBackup > 0
                    ? "Ransomware attack stopped — files restored"
                    : "Behavioural attack stopped",
                $"Threat detected and stopped ({threat}) — {Path.GetFileName(filePath)} (PID {targetPid}). " +
                $"Processes terminated: {killed}; files (deleted/quarantined): {handled + rolledBack - pending.Count}; " +
                (pending.Count > 0 ? $"awaiting restart: {pending.Count}; " : "") +
                $"persistence mechanisms removed: {persist}; " +
                (restoredFromBackup > 0
                    ? $"restored from backup: {restoredFromBackup}."
                    : "no files to restore from backup (or backup unavailable)."));
            _bus.NotifyRestored(title, body, restoredFromBackup,
                                fromBkf: backupResult?.FromBkf ?? 0,
                                fromVss: backupResult?.FromVss ?? 0,
                                pid: targetPid, threat: threat, paths: restoredPaths,
                                filePath: filePath, quarantined: quarantined, deleted: delete);
        }
        _quarantineLog.Value = null;
        _pendingReboot.Value = null;

        if (_config.RepairMode != RepairMode.Ask && !rollbackFiles)
            _bus.NotifyAuto(filePath, threat, delete ? "delete" : "quarantine",
                            process: offenderImg, source: source);
    }

    private List<int> BuildKillSet(int targetPid, List<string> malwarePaths, string filePath)
    {
        var kill = new HashSet<int>();

        if (targetPid > 0)
        {
            kill.Add(targetPid);
            foreach (var d in NativeProcess.GetDescendantsLeafFirst(targetPid)) kill.Add(d);

            foreach (var anc in NativeProcess.GetAncestors(targetPid))
            {
                var img = NativeProcess.GetImagePath(anc);
                if (IsCriticalPid(anc)) break;
                if (SystemGuard.IsUntouchable(img) && !SystemGuard.IsInQuarantine(img)) break;
                kill.Add(anc);
            }
        }

        var imgPaths = new List<string>(malwarePaths);
        if (!string.IsNullOrEmpty(filePath)) imgPaths.Add(filePath);
        foreach (var p in NativeProcess.FindPidsByImagePaths(imgPaths)) kill.Add(p);

        foreach (var p in NativeProcess.FindPidsUnderDirectory(SystemGuard.QuarantineDir)) kill.Add(p);

        kill.RemoveWhere(p => p == Environment.ProcessId || IsCriticalPid(p));
        return kill.ToList();
    }

    private List<string> CollectMalwarePaths(string filePath, int targetPid)
    {
        var paths = new List<string>();
        if (!string.IsNullOrEmpty(filePath) && !SystemGuard.IsUntouchable(filePath))
            paths.Add(filePath);

        var script = ScriptBehindProcess(targetPid, filePath);
        if (script != null && !paths.Contains(script, StringComparer.OrdinalIgnoreCase))
            paths.Add(script);

        return paths;
    }

    /// <summary>The file an interpreter was told to run, when the interpreter itself cannot be touched.</summary>
    /// <remarks>
    /// A behavioural alert names the running process, and for wscript, powershell or node that
    /// process is a signed Windows component - untouchable, so the old collector returned nothing
    /// and the log said "files: 0". Killing the interpreter leaves the script on disk, ready for
    /// the next double click. The malicious artefact is the argument, so it is what gets
    /// quarantined (and stays restorable from quarantine).
    /// </remarks>
    private string? ScriptBehindProcess(int pid, string imagePath)
    {
        if (pid <= 4) return null;

        try
        {
            string cmd = _tracker.GetProcess(pid)?.CommandLine ?? "";
            if (string.IsNullOrWhiteSpace(cmd)) return null;

            var target = ShieldService.ScriptTargetFromCommandLine(cmd);
            if (string.IsNullOrEmpty(target)) return null;
            if (string.Equals(target, imagePath, StringComparison.OrdinalIgnoreCase)) return null;
            if (SystemGuard.IsUntouchable(target) || SystemGuard.IsOwnComponent(target)) return null;
            if (SystemGuard.IsInQuarantine(target)) return null;
            if (!File.Exists(target)) return null;

            Log.Info("Threat", $"Behavioural alert on {Path.GetFileName(imagePath)} — "
                               + $"the artefact is its argument: {target}");
            return target;
        }
        catch { return null; }
    }

    private int RollbackProcessFileChanges(int targetPid, string threat, bool delete)
    {
        var pids = new HashSet<int> { targetPid };
        foreach (var d in NativeProcess.GetDescendantsLeafFirst(targetPid)) pids.Add(d);

        var created = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in pids)
            foreach (var ch in _tracker.GetChanges(p))
                if (ch.Kind == ChangeKind.FileCreate && !string.IsNullOrEmpty(ch.Location))
                    created.Add(ch.Location);

        int n = 0;
        foreach (var path in created)
        {
            if (SystemGuard.IsUntouchable(path) || SystemGuard.IsInQuarantine(path)) continue;
            if (!File.Exists(path)) continue;
            if (delete ? DeleteFile(path) : QuarantineFile(path, threat)) n++;
        }

        var touchedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset attackStart = DateTimeOffset.UtcNow;
        foreach (var p in pids)
            foreach (var ch in _tracker.GetChanges(p))
            {
                if ((ch.Kind == ChangeKind.FileCreate || ch.Kind == ChangeKind.FileModify || ch.Kind == ChangeKind.FileDelete)
                    && !string.IsNullOrEmpty(ch.Location))
                {
                    var d = Path.GetDirectoryName(ch.Location);
                    if (!string.IsNullOrEmpty(d)) touchedDirs.Add(d);
                    if (ch.Timestamp < attackStart) attackStart = ch.Timestamp;
                }
            }
        var noteCutoff = attackStart.AddMinutes(-2).UtcDateTime;
        foreach (var dir in touchedDirs)
        {
            if (SystemGuard.IsUntouchable(dir)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); } catch { continue; }
            foreach (var f in files)
            {
                var fn = Path.GetFileName(f).ToLowerInvariant();
                if (!BehaviorAnalyzer.IsRansomNoteName(fn)) continue;
                if (SystemGuard.IsUntouchable(f) || SystemGuard.IsInQuarantine(f)) continue;
                try { if (File.GetLastWriteTimeUtc(f) < noteCutoff) continue; } catch { continue; }
                if (delete ? DeleteFile(f) : QuarantineFile(f, threat)) n++;
            }
        }

        if (n > 0)
            Log.Info("Rollback", $"Reverted {n} file(s)/note(s) created by PID {targetPid} ({threat})");
        return n;
    }

    private IEnumerable<ProcessChange> CollectTreeRegistryChanges(int targetPid)
    {
        var pids = new HashSet<int> { targetPid };
        foreach (var d in NativeProcess.GetDescendantsLeafFirst(targetPid)) pids.Add(d);
        var list = new List<ProcessChange>();
        foreach (var p in pids)
            foreach (var ch in _tracker.GetChanges(p))
                if (ch.Kind is ChangeKind.RegSet or ChangeKind.RegCreate or ChangeKind.RegAutostart)
                    list.Add(ch);
        return list;
    }

    private async Task<RollbackResult?> RestoreFromBackupEngineAsync(int targetPid, CancellationToken ct,
        List<string> restoredPathsOut)
    {
        var pids = new HashSet<int> { targetPid };
        foreach (var d in NativeProcess.GetDescendantsLeafFirst(targetPid)) pids.Add(d);

        var modified = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        DateTimeOffset earliestChange = DateTimeOffset.UtcNow;
        foreach (var p in pids)
        {
            foreach (var ch in _tracker.GetChanges(p))
            {
                if (ch.Kind != ChangeKind.FileModify && ch.Kind != ChangeKind.FileDelete) continue;
                if (string.IsNullOrEmpty(ch.Location)) continue;
                if (SystemGuard.IsUntouchable(ch.Location)) continue;
                modified.Add(ch.Location);
                if (ch.Timestamp < earliestChange) earliestChange = ch.Timestamp;
            }
        }

        if (modified.Count == 0)
        {
            Log.Debug("Backup", $"PID {targetPid}: no files modified in place — skipping BackupEngine");
            return null;
        }

        var bk = FindBkmonitor();
        if (bk == null)
        {
            Log.Warn("Backup", $"bkmonitor.exe not found — {modified.Count} file(s) modified " +
                               $"by PID {targetPid} will remain encrypted");
            return null;
        }

        try
        {
            var since = earliestChange.AddMinutes(-2);
            var result = await RunBkmonitorRollbackAsync(bk, modified, since.ToUnixTimeSeconds(), ct);
            if (result == null)
            {
                Log.Warn("Backup", $"bkmonitor rollback failed — PID {targetPid}");
                return null;
            }
            Log.Info("Backup",
                $"bkmonitor rollback PID {targetPid}: restored={result.Restored} " +
                $"(from_bkf={result.FromBkf} + from_vss={result.FromVss}), failed={result.Failed}");
            if (result.Restored > 0) restoredPathsOut.AddRange(modified);
            return result;
        }
        catch (Exception ex)
        {
            Log.Warn("Backup", $"bkmonitor rollback threw: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    private string? FindBkmonitor()
    {
        var cands = new List<string?>();
        var mp = _config.MalscanPath;
        if (!string.IsNullOrEmpty(mp))
        {
            var d = Path.GetDirectoryName(mp);
            if (!string.IsNullOrEmpty(d)) cands.Add(Path.Combine(d, "bkmonitor.exe"));
        }
        cands.Add(Path.Combine(AppContext.BaseDirectory, "bkmonitor.exe"));
        try
        {
            var main = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            var d = string.IsNullOrEmpty(main) ? null : Path.GetDirectoryName(main);
            if (!string.IsNullOrEmpty(d)) cands.Add(Path.Combine(d, "bkmonitor.exe"));
        }
        catch { }
        foreach (var c in cands)
            if (!string.IsNullOrEmpty(c) && File.Exists(c)) return c;
        return null;
    }

    private async Task<RollbackResult?> RunBkmonitorRollbackAsync(string bkExe, IEnumerable<string> paths,
        long sinceUnix, CancellationToken ct)
    {
        string tmp = Path.Combine(Path.GetTempPath(), $"malward-rollback-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllLinesAsync(tmp, paths, ct);
            var psi = new System.Diagnostics.ProcessStartInfo(bkExe)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding  = System.Text.Encoding.UTF8,
            };
            psi.ArgumentList.Add("rollback");
            psi.ArgumentList.Add("--since");      psi.ArgumentList.Add(sinceUnix.ToString());
            psi.ArgumentList.Add("--paths-file"); psi.ArgumentList.Add(tmp);
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return null;
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            string stdout = await stdoutTask;
            _ = await stderrTask;
            using var doc = System.Text.Json.JsonDocument.Parse(stdout);
            var root = doc.RootElement;
            if (!root.TryGetProperty("ok", out var okEl) || !okEl.GetBoolean()) return null;
            if (!root.TryGetProperty("result", out var res)) return null;
            return new RollbackResult
            {
                Restored = res.TryGetProperty("restored", out var r) ? r.GetInt32() : 0,
                Failed   = res.TryGetProperty("failed",   out var f) ? f.GetInt32() : 0,
                FromBkf  = res.TryGetProperty("from_bkf", out var b) ? b.GetInt32() : 0,
                FromVss  = res.TryGetProperty("from_vss", out var v) ? v.GetInt32() : 0,
            };
        }
        catch (Exception ex) { Log.Warn("Backup", $"bkmonitor spawn/parse: {ex.Message}"); return null; }
        finally { try { File.Delete(tmp); } catch { } }
    }

    private bool TreeTouchedPersistence(int targetPid, List<int> tree)
    {
        var pids = new List<int>(tree);
        if (targetPid > 0 && !pids.Contains(targetPid)) pids.Add(targetPid);

        foreach (var p in pids)
            foreach (var ch in _tracker.GetChanges(p))
                if (ch.Kind is ChangeKind.ServiceCreate or ChangeKind.ScheduledTask
                            or ChangeKind.RegAutostart)
                    return true;
        return false;
    }

    private static bool IsCriticalPid(int pid)
    {
        if (pid <= 4) return true;
        string img  = NativeProcess.GetImagePath(pid);
        string name = string.IsNullOrEmpty(img) ? "" : Path.GetFileName(img);
        return SystemGuard.IsCriticalProcess(pid, name, img);
    }

    private static bool KillWithRetry(int pid)
    {
        for (int i = 0; i < 3; i++)
        {
            if (NativeProcess.Terminate(pid)) return true;
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                p.Kill(entireProcessTree: true);
                return true;
            }
            catch (ArgumentException) { return true; }
            catch { Thread.Sleep(120); }
        }
        Log.Warn("Threat", $"Failed to terminate PID {pid}");
        return false;
    }

    private int FindPidByImage(string filePath)
        => _tracker.AllProcesses.FirstOrDefault(p =>
            string.Equals(p.ImagePath, filePath, StringComparison.OrdinalIgnoreCase))?.Pid ?? 0;

    public static bool QuarantineForHips(string path, string ruleName)
    {
        if (SystemGuard.IsOwnComponent(path)) return false;

        if (SystemGuard.IsProtectedPath(path) && Hips.HipsTrust.IsTrustedProgram(path))
            return false;

        var detection = SystemGuard.IsProtectedPath(path)
            ? "Behaviour.SystemFilesInjection"
            : $"Behaviour.HIPS.{ruleName.Replace(' ', '_')}";
        return QuarantineFile(path, detection, allowProtectedPath: true);
    }

    private static bool QuarantineFile(string path, string detection, bool allowProtectedPath = false)
    {
        if (!allowProtectedPath && SystemGuard.IsUntouchableForRepair(path)) return false;
        if (allowProtectedPath && SystemGuard.IsOwnComponent(path)) return false;
        if (!File.Exists(path)) return false;

        foreach (var p in NativeProcess.FindPidsByImagePaths(new[] { path }))
        {
            NativeProcess.Suspend(p);
            NativeProcess.Terminate(p);
        }

        string dest = Path.Combine(QuarantineDir, $"{Guid.NewGuid()}.quarantine");

        bool TryOnce(string label)
        {
            bool copied = false;
            try
            {
                Directory.CreateDirectory(QuarantineDir);
                UnlockFile(path);
                QuarantineCrypto.EncryptFile(path, dest);
                copied = true;
                File.Delete(path);
                QuarantineStore.Record(dest, path, detection);
                _quarantineLog.Value?.Add((Path.GetFileName(dest), path));
                Log.Info("Threat", $"Quarantined{label}: {Path.GetFileName(path)}");
                return true;
            }
            catch (Exception ex)
            {
                if (copied) { try { File.Delete(dest); } catch { } }
                Log.Debug("Threat", $"Quarantine{label} failed ({ex.GetType().Name}): {ex.Message}");
                return false;
            }
        }

        if (TryOnce("")) return true;

        foreach (var p in NativeProcess.FindPidsByImagePaths(new[] { path }))
        {
            try { NativeProcess.Suspend(p); NativeProcess.Terminate(p); } catch { }
        }
        StopScriptHostsRunning(path);
        TryResetAcl(path);
        if (TryOnce(" (after releasing the file)")) return true;

        if (NativeProcess.ScheduleDeleteOnReboot(path))
        {
            Log.Warn("Threat", $"File locked — deletion scheduled after reboot: {path}");
            _pendingReboot.Value?.Add(path);
            return true;
        }

        Log.Error("Threat", $"Failed to move to quarantine (file in use or protected): {path}");
        return false;
    }

    private static bool DeleteFile(string path)
    {
        if (SystemGuard.IsUntouchableForRepair(path)) return false;
        if (!File.Exists(path)) return false;
        try
        {
            UnlockFile(path);
            File.Delete(path);
            Log.Info("Threat", $"Deleted: {path}");
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            if (TryResetAcl(path)) { try { File.Delete(path); return true; } catch { } }
            Log.Error("Threat", $"Access denied to file (delete): {path}");
            return false;
        }
        catch (Exception ex) { Log.Error("Threat", $"Delete error {path}: {ex.Message}"); return false; }
    }

    private static void StopScriptHostsRunning(string path)
    {
        string[] hosts;
        try { hosts = Malward.Engine.Data.SignatureStore.List("interpreter_images"); }
        catch { return; }
        if (hosts.Length == 0) return;

        var name = Path.GetFileName(path);
        if (string.IsNullOrEmpty(name)) return;

        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process");
            using var results = searcher.Get();
            foreach (System.Management.ManagementBaseObject o in results)
            {
                using (o)
                {
                    var procName = o["Name"]?.ToString() ?? "";
                    if (!hosts.Contains(procName, StringComparer.OrdinalIgnoreCase)) continue;

                    var cmd = o["CommandLine"]?.ToString() ?? "";
                    if (cmd.IndexOf(path, StringComparison.OrdinalIgnoreCase) < 0 &&
                        cmd.IndexOf(name, StringComparison.OrdinalIgnoreCase) < 0) continue;

                    int pid;
                    try { pid = Convert.ToInt32(o["ProcessId"]); } catch { continue; }
                    if (pid <= 4 || pid == Environment.ProcessId) continue;

                    var image = o["ExecutablePath"]?.ToString() ?? "";
                    if (SystemGuard.IsCriticalProcess(pid, procName, image)) continue;
                    if (SystemGuard.IsOwnComponent(image)) continue;
                    if (Hips.HipsSelfGuard.IsOwnProcessTree(pid)) continue;

                    Log.Info("Threat", $"Stopping {procName} (PID {pid}) — it is running the detected file {name}.");
                    try { NativeProcess.Suspend(pid); NativeProcess.Terminate(pid); } catch { }
                }
            }
        }
        catch (Exception ex) { Log.Debug("Threat", $"Holder lookup failed: {ex.Message}"); }
    }

    private static void UnlockFile(string path)
    {
        try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
    }

    private static bool TryResetAcl(string path)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("icacls.exe",
                $"\"{path}\" /reset /Q /C")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(4000);
            UnlockFile(path);
            return p != null && p.HasExited && p.ExitCode == 0;
        }
        catch { return false; }
    }
}
