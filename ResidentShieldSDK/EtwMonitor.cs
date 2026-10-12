using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Malward.ResidentShield;

public sealed class EtwMonitor : IDisposable
{
    private readonly ShieldConfig                        _config;
    private readonly ProcessTracker                      _tracker;
    private readonly RollbackDb                          _rollback;
    private readonly Action<BehaviorAlert, ProcessInfo>? _alertCallback;

    private readonly Func<string, string?, bool>? _hipsCovers;
    private readonly Action<ScanEvent>?                  _scanCallback;

    private TraceEventSession? _session;
    private Thread?            _thread;
    private CancellationToken  _ct;

    private const string SessionName = "MalwardResidentShield";

    private static string[] AutostartKeys =>
        Malward.Engine.Data.SignatureStore.List("autostart_reg_keys");

    private readonly Dictionary<string, string> _deviceMap = BuildDeviceMap();
    private readonly ConcurrentDictionary<int, DateTime> _lastAlerted = new();

    public EtwMonitor(
        ShieldConfig                        config,
        ProcessTracker                      tracker,
        RollbackDb                          rollback,
        Action<BehaviorAlert, ProcessInfo>? alertCallback = null,
        Action<ScanEvent>?                  scanCallback  = null,
        ProcessBombGuard?                   bombGuard     = null,
        Func<string, string?, bool>?        hipsCovers    = null)
    {
        _bombGuard = bombGuard;
        _hipsCovers = hipsCovers;
        _config        = config;
        _tracker       = tracker;
        _rollback      = rollback;
        _alertCallback = alertCallback;
        _scanCallback  = scanCallback;
    }

    public void Start(CancellationToken ct = default)
    {
        _ct = ct;

        try { TraceEventSession.GetActiveSession(SessionName)?.Dispose(); } catch { }

        _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create)
        {
            StopOnDispose = true,
        };

        var keywords =
            KernelTraceEventParser.Keywords.Process   |
            KernelTraceEventParser.Keywords.Registry  |
            KernelTraceEventParser.Keywords.ImageLoad |
            KernelTraceEventParser.Keywords.FileIOInit;

        bool fileTracking = _config.BehaviorMonitorEnabled && _config.BehaviorFileTrackingEnabled;
        if (fileTracking)
            keywords |= KernelTraceEventParser.Keywords.FileIO;

        _session.EnableKernelProvider(keywords,
            stackCapture: KernelTraceEventParser.Keywords.None);

        _session.Source.Kernel.ProcessStart += OnProcessStart;

        _session.Source.Kernel.ImageLoad += OnImageLoad;
        _session.Source.Kernel.ProcessStop  += OnProcessStop;

        _session.Source.Kernel.RegistrySetValue    += OnRegistrySet;
        _session.Source.Kernel.RegistryCreate      += OnRegistryCreate;
        _session.Source.Kernel.RegistryDelete      += OnRegistryDelete;
        _session.Source.Kernel.RegistryDeleteValue += OnRegistryDelete;

        _session.Source.Kernel.FileIOCreate += OnFileCreate;

        if (fileTracking)
        {
            _session.Source.Kernel.FileIOWrite  += OnFileWrite;
            _session.Source.Kernel.FileIODelete += OnFileDelete;
        }

        _thread = new Thread(() =>
        {
            try   { _session.Source.Process(); }
            catch (Exception ex) when (ex is not ThreadInterruptedException)
            { Log.Error("ETW", $"Session error: {ex.Message}"); }
        })
        {
            Name = "ETW-Processing", IsBackground = true,
        };
        _thread.Start();

        Log.Info("ETW", "Session started (Process + Registry"
                        + (fileTracking ? " + FileIO)" : ", file tracking OFF)"));

        if (fileTracking)
            _statsTimer = new System.Threading.Timer(_ => LogThroughput(), null,
                                                     TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public void Stop()
    {
        try { _statsTimer?.Dispose(); } catch { }
        _statsTimer = null;
        try { _session?.Dispose(); } catch { }
        _session = null;
    }

    private System.Threading.Timer? _statsTimer;
    private long _fileSeen;
    private long _fileKept;

    private void LogThroughput()
    {
        long seen = System.Threading.Interlocked.Exchange(ref _fileSeen, 0);
        long kept = System.Threading.Interlocked.Exchange(ref _fileKept, 0);
        int lost = 0;
        try { lost = _session?.EventsLost ?? 0; } catch { }
        if (seen == 0 && lost == 0) return;
        long pct = seen == 0 ? 0 : kept * 100 / seen;
        Log.Info("ETW", $"file events/s: {seen / 60} received, {kept / 60} kept ({pct}%); "
                        + $"session lost {lost} events since start");
    }

    private readonly ProcessBombGuard? _bombGuard;

    private void OnProcessStart(ProcessTraceData data)
    {
        if (!_config.ProcessMonitorEnabled) return;

        string image   = ResolveDevicePath(data.ImageFileName ?? "");
        string cmdLine = data.CommandLine ?? "";
        _tracker.Register(data.ProcessID, data.ParentID, data.ProcessName, image, cmdLine);

        CheckProcessBomb(data.ProcessID);

        if (_scanCallback != null && !string.IsNullOrEmpty(image) && File.Exists(image))
        {
            _scanCallback(new ScanEvent(ScanEventKind.ProcessStarted,
                image, data.ProcessID, data.ProcessName, DateTimeOffset.UtcNow));
        }

        if (_scanCallback != null)
        {
            foreach (var target in LolBin.ExtractTargets(data.ProcessName, cmdLine))
                _scanCallback(new ScanEvent(ScanEventKind.FileCreated,
                    target, data.ProcessID, data.ProcessName, DateTimeOffset.UtcNow));
        }

        CheckSabotageLaunch(data.ProcessID, cmdLine);

        CheckCommandLineAbuse(data.ProcessID);

        AnalyzeIfRelevant(data.ProcessID);
    }

    private void CheckProcessBomb(int pid)
    {
        if (_bombGuard == null || _alertCallback == null) return;
        try
        {
            var proc = _tracker.GetProcess(pid);
            if (proc == null) return;

            var v = _bombGuard.Inspect(proc);
            if (!v.Block)
            {
                v = _bombGuard.InspectCompiler(proc);
                if (!v.Block) return;
            }

            if (v.KillLineage && _bombGuard.AlreadyReported(proc.ParentPid)) return;

            _alertCallback(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High,
                v.Detection ?? "Behaviour.ProcessBomb", v.Reason ?? "Bombardowanie procesami"), proc);
        }
        catch {  }
    }

    private void OnProcessStop(ProcessTraceData data)
    {
        if (!_config.ProcessMonitorEnabled) return;
        _tracker.Unregister(data.ProcessID);

        _worthFollowing.TryRemove(data.ProcessID, out _);
        _lastAnalyzeMs.TryRemove(data.ProcessID, out _);
    }

    private void OnRegistrySet(RegistryTraceData data)
    {
        if (!_config.RegistryMonitorEnabled) return;

        string key = data.KeyName ?? "";
        bool autostart = IsAutostartKey(key);

        _tracker.RecordRegistryOp(data.ProcessID,
            autostart ? ChangeKind.RegAutostart : ChangeKind.RegSet,
            key, data.ValueName, autostart);
        NoteRegistryAuthor(key, data.ProcessID);

        AnalyzeIfRelevant(data.ProcessID);
    }

    private void OnRegistryCreate(RegistryTraceData data)
    {
        if (!_config.RegistryMonitorEnabled) return;

        string key = data.KeyName ?? "";
        _tracker.RecordRegistryOp(data.ProcessID, ChangeKind.RegCreate, key, null, IsAutostartKey(key));
        NoteRegistryAuthor(key, data.ProcessID);

        string? svc = ExtractServiceName(key);
        if (svc != null)
        {
            _tracker.RecordServiceOp(data.ProcessID, svc);
            AnalyzeIfRelevant(data.ProcessID);
        }
    }

    private void OnRegistryDelete(RegistryTraceData data)
    {
        if (!_config.RegistryMonitorEnabled) return;
        _tracker.RecordRegistryOp(data.ProcessID, ChangeKind.RegDelete,
            data.KeyName ?? "", data.ValueName, false);
        NoteRegistryAuthor(data.KeyName ?? "", data.ProcessID);
    }

    private void NoteRegistryAuthor(string key, int pid)
    {
        if (!RegistryWriters.Matches(key, out var area)) return;
        var image = _tracker.GetProcess(pid)?.ImagePath;
        if (string.IsNullOrEmpty(image))
        {
            try { image = NativeProcess.GetImagePath(pid); } catch { image = null; }
        }
        RegistryWriters.Note(area, pid, image);
    }

    private void OnFileCreate(FileIOCreateTraceData data)
    {
        if (!_config.ProcessMonitorEnabled) return;

        string raw = data.FileName ?? "";

        if (DefenseTamper.IsRawDiskPath(raw))
            CheckRawDiskAccess(data.ProcessID, raw);

        string path = ResolveDevicePath(raw);
        if (string.IsNullOrEmpty(path)) return;

        _tracker.RecordFileOp(data.ProcessID, ChangeKind.FileCreate, path);

        if (path.Contains(@"\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
        {
            _tracker.RecordScheduledTask(data.ProcessID, path);
            AnalyzeIfRelevant(data.ProcessID);
        }
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, bool> _worthFollowing = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, long> _lastAnalyzeMs = new();

    private bool WorthFollowing(int pid)
    {
        if (pid <= 4 || pid == Environment.ProcessId) return false;
        return _worthFollowing.GetOrAdd(pid, p =>
        {
            string? img = null;
            try { img = _tracker.GetProcess(p)?.ImagePath ?? NativeProcess.GetImagePath(p); } catch { }
            if (string.IsNullOrEmpty(img)) return true;
            if (SystemGuard.IsOwnComponent(img)) return false;
            return !(Hips.HipsTrust.IsTrustedProgram(img) && !Hips.HipsTrust.InUserWritableArea(img));
        });
    }

    private void OnFileWrite(FileIOReadWriteTraceData data)
    {
        if (!_config.BehaviorFileTrackingEnabled) return;
        if (!_config.BehaviorMonitorEnabled) return;
        System.Threading.Interlocked.Increment(ref _fileSeen);
        if (!WorthFollowing(data.ProcessID)) return;
        System.Threading.Interlocked.Increment(ref _fileKept);
        string path = ResolveDevicePath(data.FileName ?? "");
        if (string.IsNullOrEmpty(path)) return;
        if (SystemGuard.IsProtectedPath(path)) return;
        _tracker.RecordFileOp(data.ProcessID, ChangeKind.FileModify, path);
        AnalyzeIfRelevant(data.ProcessID);
    }

    private void OnFileDelete(FileIOInfoTraceData data)
    {
        if (!_config.BehaviorFileTrackingEnabled) return;
        if (!_config.BehaviorMonitorEnabled) return;
        System.Threading.Interlocked.Increment(ref _fileSeen);
        if (!WorthFollowing(data.ProcessID)) return;
        System.Threading.Interlocked.Increment(ref _fileKept);
        string path = ResolveDevicePath(data.FileName ?? "");
        if (string.IsNullOrEmpty(path)) return;
        if (SystemGuard.IsProtectedPath(path)) return;

        _tracker.RecordFileOp(data.ProcessID, ChangeKind.FileDelete, path);
    }

    private void AnalyzeIfRelevant(int pid)
    {
        if (_alertCallback == null || !_config.BehaviorMonitorEnabled) return;

        long teraz = Environment.TickCount64;
        long ostatnio = _lastAnalyzeMs.GetOrAdd(pid, 0);
        if (teraz - ostatnio < 500) return;
        _lastAnalyzeMs[pid] = teraz;

        var proc = _tracker.GetProcess(pid);
        if (proc == null) return;
        if (pid == Environment.ProcessId) return;

        var blame = proc;
        bool viaTrustedTool = false;
        if (SystemGuard.IsTrustedImage(proc.ImagePath) && !RunsUntrustedScript(proc))
        {
            int offender = ResolveOffenderPid(pid);
            if (offender <= 0 || offender == pid) return;
            var owner = _tracker.GetProcess(offender);
            if (owner == null) return;
            blame = owner;
            viaTrustedTool = true;
        }

        if (SystemGuard.IsOwnComponent(proc.ImagePath) && !SystemGuard.IsInQuarantine(proc.ImagePath))
            return;
        if (SystemGuard.IsOwnComponent(blame.ImagePath) && !SystemGuard.IsInQuarantine(blame.ImagePath))
            return;

        if (Hips.HipsSelfGuard.IsOwnProcessTree(blame.Pid)) return;

        var now = DateTime.UtcNow;
        if (_lastAlerted.TryGetValue(pid, out var last) && (now - last).TotalSeconds < 3)
            return;

        var alerts = BehaviorAnalyzer.Analyze(_tracker, pid, _config, viaTrustedTool);

        var worst = alerts.FirstOrDefault(a => a.Severity == BehaviorSeverity.High)
                 ?? alerts.FirstOrDefault(a => _hipsCovers?.Invoke(a.Category, blame.ImagePath) == true);
        if (worst == null) return;

        if (viaTrustedTool)
            worst = worst with
            {
                Pid = blame.Pid,
                ProcessName = blame.Name,
                Description = $"{worst.Description} (przez {proc.Name})",
            };

        if (!SurvivesSignature(worst.Category)
            && (SystemGuard.HasValidSignature(blame.ImagePath) || UnpackedBySignedInstaller(blame)))
        {
            Log.Info("Behavior", $"Skipped alert {worst.Category} for PID {blame.Pid} " +
                                 $"({blame.Name}) — the program carries a valid digital signature.");
            return;
        }

        _lastAlerted[pid] = now;
        try { _alertCallback(worst, blame); }
        catch (Exception ex) { Log.Error("ETW", $"Alert callback error: {ex.Message}"); }
    }

    private bool UnpackedBySignedInstaller(ProcessInfo proc)
    {
        if (!Hips.HipsTrust.TrustSignedInUserArea) return false;
        if (string.IsNullOrEmpty(proc.ImagePath)) return false;
        if (!proc.ImagePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)) return false;

        int pid = proc.ParentPid;
        for (int i = 0; i < 4 && pid > 4; i++)
        {
            var parent = _tracker.GetProcess(pid);
            if (parent == null) return false;
            if (SystemGuard.HasValidSignature(parent.ImagePath)) return true;
            pid = parent.ParentPid;
        }
        return false;
    }

    private static bool SurvivesSignature(string? category) => category switch
    {
        "LolBinAbuse" or "SuspiciousChain" or "Persistence" or "DefenseImpairment"
            or "ShadowCopyDeletion" or "Ransomware" or "RansomNote" or "EncryptionEntropy"
            or "RansomExtension" or "RawDiskWrite" or "ProcessSpoofing"

            or "LolBinHiddenScript" or "LolBinDownload" or "LolBinRemoteScript" or "LolBinWmic"
            or "AccountChange" or "CriticalProcessKill" or "ExplorerTamper"
            or "CryptoMiner" or "ReconBurst" or "AnonymisedC2"

            or "UnsignedModuleLoad" => true,
        _ => false,
    };

    private readonly Dictionary<string, bool> _moduleTrust = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _moduleReported = new(StringComparer.OrdinalIgnoreCase);

    private void OnImageLoad(ImageLoadTraceData data)
    {
        if (_alertCallback == null || !_config.BehaviorMonitorEnabled) return;

        try
        {
            var file = data.FileName;
            if (string.IsNullOrEmpty(file)) return;
            if (data.ProcessID <= 4 || data.ProcessID == Environment.ProcessId) return;

            if (!file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                !file.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase)) return;

            if (!Hips.HipsTrust.InUserWritableArea(file)) return;
            if (SystemGuard.IsOwnComponent(file)) return;

            var proc = _tracker.GetProcess(data.ProcessID);
            if (proc == null) return;

            if (!SystemGuard.IsTrustedImage(proc.ImagePath)) return;

            if (Hips.HipsTrust.TrustSignedInUserArea && WRozpakowniInstalatora(file)) return;

            if (!ModuleUntrusted(file)) return;
            if (!_moduleReported.Add(proc.ImagePath + "|" + file)) return;

            var alert = new BehaviorAlert(data.ProcessID, proc.Name, BehaviorSeverity.High,
                "UnsignedModuleLoad",
                $"Niepodpisana biblioteka {file} załadowana do zaufanego procesu {proc.Name} " +
                $"({proc.ImagePath}) — podszycie się pod jego reputację (DLL side-loading).");
            _alertCallback(alert, proc);
        }
        catch (Exception ex) { Log.Debug("ETW", $"ImageLoad: {ex.Message}"); }
    }

    private static bool WRozpakowniInstalatora(string dll)
    {
        var dir = Path.GetDirectoryName(dll);
        if (string.IsNullOrEmpty(dir)) return false;
        return dir.Contains(BACKSLASH_TEMP, StringComparison.OrdinalIgnoreCase)
            && dir.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
    }

    private const string BACKSLASH_TEMP = @"\Temp\";

    private bool ModuleUntrusted(string path)
    {
        string key;
        try { key = path + "|" + File.GetLastWriteTimeUtc(path).Ticks; }
        catch { return false; }
        lock (_moduleTrust)
        {
            if (_moduleTrust.TryGetValue(key, out var cached)) return cached;

            if (_moduleTrust.Count > 4096) _moduleTrust.Clear();
        }

        bool untrusted;
        try { untrusted = !Hips.HipsTrust.IsTrustedProgram(path); }
        catch { untrusted = false; }

        lock (_moduleTrust) _moduleTrust[key] = untrusted;
        return untrusted;
    }

    private void CheckCommandLineAbuse(int pid)
    {
        if (_alertCallback == null || !_config.BehaviorMonitorEnabled) return;
        try
        {
            var proc = _tracker.GetProcess(pid);
            if (proc == null || pid == Environment.ProcessId) return;
            if (SystemGuard.IsOwnComponent(proc.ImagePath)) return;

            if (Hips.HipsSelfGuard.IsOwnCommand(proc.CommandLine)) return;
            if (Hips.HipsSelfGuard.IsOwnProcessTree(pid)) return;

            foreach (var alert in BehaviorAnalyzer.AnalyzeCommandLine(proc))
                _alertCallback(alert, proc);
        }
        catch (Exception ex) { Log.Debug("ETW", ex.Message); }
    }

    private void CheckSabotageLaunch(int pid, string cmdLine)
    {
        if (_alertCallback == null || !_config.BehaviorMonitorEnabled) return;
        if (!_config.RansomwareDetect.DefenseTamper) return;

        var hit = DefenseTamper.Match(cmdLine);
        if (hit == null) return;

        int target = ResolveOffenderPid(pid);
        if (target <= 0) return;
        var proc = _tracker.GetProcess(target);
        if (proc == null) return;

        var alert = new BehaviorAlert(target, proc.Name, BehaviorSeverity.High,
            hit.Value.Category, $"{hit.Value.Description}: {Trunc(cmdLine, 160)}");
        RaiseSpecial(target, proc, alert);
    }

    private void CheckRawDiskAccess(int pid, string rawPath)
    {
        if (_alertCallback == null || !_config.BehaviorMonitorEnabled) return;
        if (!_config.RansomwareDetect.RawDiskGuard) return;

        int target = ResolveOffenderPid(pid);
        if (target <= 0) return;
        var proc = _tracker.GetProcess(target);
        if (proc == null) return;

        var alert = new BehaviorAlert(target, proc.Name, BehaviorSeverity.High, "RawDiskWrite",
            $"Bezposredni dostep do surowego dysku (mozliwy wiper/bootkit — nadpisanie MBR/GPT): {rawPath}");
        RaiseSpecial(target, proc, alert);
    }

    private static bool RunsUntrustedScript(ProcessInfo proc)
    {
        try
        {
            if (string.IsNullOrEmpty(proc.CommandLine)) return false;
            var host = Path.GetFileName(proc.ImagePath ?? "");
            if (host.Length == 0 || !LolBin.IsInterpreter(host)) return false;
            foreach (var target in LolBin.ExtractTargets(host, proc.CommandLine))
                if (!SystemGuard.IsTrustedImage(target)) return true;
            return false;
        }
        catch { return false; }
    }

    private int ResolveOffenderPid(int pid)
    {
        var selfImg = _tracker.GetProcess(pid)?.ImagePath;
        if (string.IsNullOrEmpty(selfImg)) selfImg = NativeProcess.GetImagePath(pid);
        if (!string.IsNullOrEmpty(selfImg) && !SystemGuard.IsTrustedImage(selfImg))
            return pid;

        foreach (var anc in NativeProcess.GetAncestors(pid))
        {
            if (anc <= 4) break;
            var img = NativeProcess.GetImagePath(anc);
            string name = string.IsNullOrEmpty(img) ? "" : Path.GetFileName(img);
            if (SystemGuard.IsCriticalProcess(anc, name, img)) break;
            if (!string.IsNullOrEmpty(img) && !SystemGuard.IsTrustedImage(img)) return anc;
        }
        return 0;
    }

    private void RaiseSpecial(int pid, ProcessInfo proc, BehaviorAlert alert)
    {
        if (SystemGuard.IsOwnComponent(proc.ImagePath) && !SystemGuard.IsInQuarantine(proc.ImagePath))
            return;
        var now = DateTime.UtcNow;
        if (_lastAlerted.TryGetValue(pid, out var last) && (now - last).TotalSeconds < 3) return;
        _lastAlerted[pid] = now;
        Log.Alert("Precursor", $"[{alert.Category}] PID {pid} {proc.Name}: {alert.Description}");
        try { _alertCallback!(alert, proc); }
        catch (Exception ex) { Log.Error("ETW", $"Alert callback error: {ex.Message}"); }
    }

    private static string Trunc(string s, int max)
        => string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max] + "…");

    private static bool IsAutostartKey(string keyName)
        => !string.IsNullOrEmpty(keyName)
        && AutostartKeys.Any(a => keyName.Contains(a, StringComparison.OrdinalIgnoreCase));

    private static string? ExtractServiceName(string keyName)
    {
        if (string.IsNullOrEmpty(keyName)) return null;
        const string marker = @"\Services\";
        int idx = keyName.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        string rest = keyName[(idx + marker.Length)..];
        if (rest.Length == 0) return null;

        int slash = rest.IndexOf('\\');
        string name = slash < 0 ? rest : rest[..slash];

        return slash < 0 && name.Length > 0 ? name : null;
    }

    private string ResolveDevicePath(string devicePath)
    {
        if (string.IsNullOrEmpty(devicePath)) return devicePath;
        foreach (var (device, letter) in _deviceMap)
            if (devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return letter + devicePath[device.Length..];
        return devicePath;
    }

    private static Dictionary<string, string> BuildDeviceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                var letter = drive.Name.TrimEnd('\\');
                var sb     = new StringBuilder(512);
                if (QueryDosDevice(letter, sb, sb.Capacity) > 0)
                    map[sb.ToString()] = letter;
            }
            catch { }
        }
        return map;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int maxLength);

    public void Dispose() => Stop();
}
