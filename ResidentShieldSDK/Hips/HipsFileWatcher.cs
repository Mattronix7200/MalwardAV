using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Malward.Engine.Util;

namespace Malward.ResidentShield.Hips;

public sealed class HipsFileWatcher : IDisposable
{
    private readonly HipsConfig _hips;
    private readonly ActivityReporter _activity;
    private readonly Notifier _notify;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _ruleOf = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private DateTime _lastRescan = DateTime.MinValue;

    private static string BaselineDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "hips-baseline");

    public static IEnumerable<string> Detectors => new[]
    {
        "FileWatcher:startup", "FileWatcher:startup-all", "FileWatcher:tasks", "FileWatcher:hosts",
        "FileWatcher:system32", "FileWatcher:autorun", "FileWatcher:ads", "FileWatcher:shortcuts",
        "FileWatcher:psprofile", "FileWatcher:gposcripts", "FileWatcher:office",
        "FileWatcher:sysdirs", "FileWatcher:systemp", "FileWatcher:accessibility",
        "FileWatcher:badip",
    };

    public HipsFileWatcher(HipsConfig hips, ActivityReporter activity, Notifier notify)
    { _hips = hips; _activity = activity; _notify = notify; }

    public static Func<string, bool>? IsMalwareHook { get; set; }

    private static bool ConfirmedMalware(string path)
    {
        try { return IsMalwareHook?.Invoke(path) == true; }
        catch { return false; }
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        try { Directory.CreateDirectory(BaselineDir); } catch { }
        Attach();

        _loop = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try { Drain(); } catch (Exception ex) { Log.Debug("HIPS-Plik", ex.Message); }

                if ((DateTime.UtcNow - _lastRescan).TotalSeconds > 30)
                {
                    try { Attach(); } catch { }
                    _lastRescan = DateTime.UtcNow;
                }
                try { await Task.Delay(1000, ct); } catch { break; }
            }
        }, ct);

        Log.Info("HIPS", $"File watching started ({_watchers.Count} locations).");
    }

    private void Attach()
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string sys32 = Path.Combine(win, "System32");
        string syswow = Path.Combine(win, "SysWOW64");

        Watch("file.startup", Environment.GetFolderPath(Environment.SpecialFolder.Startup), "*", false);
        Watch("file.startup_ext", Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "*", false);
        Watch("file.startup_ext", Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows\Start Menu\Programs\StartUp"), "*", false);

        Watch("file.tasks", Path.Combine(sys32, "Tasks"), "*", true);
        Watch("file.tasks", Path.Combine(win, "Tasks"), "*", false);
        Watch("file.tasks", Path.Combine(sys32, "Tasks_Migrated"), "*", true);

        Watch("file.hosts", Path.Combine(sys32, @"drivers\etc"), "*", false);
        foreach (var n in HostsFiles)
            SaveBaselineIfMissing(Path.Combine(sys32, @"drivers\etc", n));

        Watch("file.system", sys32, "*", false);
        Watch("file.system", syswow, "*", false);
        Watch("file.system", Path.Combine(sys32, "drivers"), "*", false);
        Watch("file.system", Path.Combine(sys32, @"drivers\UMDF"), "*", false);

        Watch("file.sys_subdirs", Path.Combine(sys32, "wbem"), "*", false);
        Watch("file.sys_subdirs", Path.Combine(sys32, @"wbem\mof"), "*", false);
        Watch("file.sys_subdirs", Path.Combine(sys32, @"spool\drivers"), "*", true);
        Watch("file.sys_subdirs", Path.Combine(sys32, @"spool\prtprocs"), "*", true);
        Watch("file.sys_subdirs", Path.Combine(sys32, @"WindowsPowerShell\v1.0\Modules"), "*", true);

        Watch("file.psprofile", Path.Combine(sys32, @"WindowsPowerShell\v1.0"), "*.ps1", false);
        Watch("file.psprofile", Path.Combine(syswow, @"WindowsPowerShell\v1.0"), "*.ps1", false);

        Watch("file.gpo_scripts", Path.Combine(sys32, @"GroupPolicy\Machine\Scripts"), "*", true);
        Watch("file.gpo_scripts", Path.Combine(sys32, @"GroupPolicy\User\Scripts"), "*", true);

        Watch("file.systemp", Path.Combine(win, "Temp"), "*", false);
        Watch("file.systemp", Path.Combine(sys32, @"config\systemprofile\AppData\Local\Temp"), "*", false);
        Watch("file.systemp", Path.Combine(syswow, @"config\systemprofile\AppData\Local\Temp"), "*", false);

        foreach (var p in UserProfiles())
        {
            Watch("file.startup", Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), "*", false);
            Watch("file.psprofile", Path.Combine(p, @"Documents\WindowsPowerShell"), "*.ps1", false);
            Watch("file.psprofile", Path.Combine(p, @"Documents\PowerShell"), "*.ps1", false);
            Watch("file.psprofile", Path.Combine(p, @"OneDrive\Documents\WindowsPowerShell"), "*.ps1", false);
            Watch("file.psprofile", Path.Combine(p, @"OneDrive\Documents\PowerShell"), "*.ps1", false);

            var roaming = Path.Combine(p, @"AppData\Roaming\Microsoft");
            Watch("file.office", Path.Combine(roaming, @"Word\STARTUP"), "*", false);
            Watch("file.office", Path.Combine(roaming, @"Excel\XLSTART"), "*", false);
            Watch("file.office", Path.Combine(roaming, "Templates"), "*", false);
            Watch("file.office", Path.Combine(roaming, "AddIns"), "*", false);
        }

        foreach (var pf in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                   Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            if (string.IsNullOrEmpty(pf)) continue;
            var office = Path.Combine(pf, @"Microsoft Office\root");
            if (!Directory.Exists(office)) continue;
            foreach (var dir in SafeDirs(office, "Office*"))
            {
                Watch("file.office", Path.Combine(dir, "STARTUP"), "*", false);
                Watch("file.office", Path.Combine(dir, "XLSTART"), "*", false);
            }
        }

        var seenShortcutDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in ShortcutDirs())
        {
            if (!seenShortcutDirs.Add(dir.Path + "|" + dir.Recursive)) continue;
            foreach (var filter in ShortcutFilters)
            {
                Watch("file.shortcuts", dir.Path, filter, dir.Recursive);
                if (filter == "*.lnk") SaveBaselineDirIfMissing(dir.Path, filter, dir.Recursive);
            }
        }

        AttachRemovable();
    }

    private static readonly string[] HostsFiles = { "hosts", "hosts.ics", "lmhosts", "lmhosts.sam", "services" };
    private static readonly string[] ShortcutFilters = { "*.lnk", "*.url", "*.scf", "*.pif", "*.website" };

    private static readonly string[] AccessibilityTools =
        { "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe" };

    private static IEnumerable<string> SafeDirs(string root, string pattern)
    {
        try { return Directory.EnumerateDirectories(root, pattern).ToList(); }
        catch { return Array.Empty<string>(); }
    }

    private static IEnumerable<string> UserProfiles()
    {
        string[] skip = { "Public", "Default", "Default User", "All Users" };
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in ProfilesFromRegistry().Concat(ProfilesFromUsersFolder()))
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var dir = raw.TrimEnd('\\');
            var name = Path.GetFileName(dir);
            if (name.Length == 0 || skip.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;

            if (win.Length > 0 && dir.StartsWith(win + "\\", StringComparison.OrdinalIgnoreCase)) continue;
            if (!seen.Add(dir)) continue;
            bool exists;
            try { exists = Directory.Exists(dir); } catch { exists = false; }
            if (exists) yield return dir;
        }
    }

    private static IEnumerable<string> ProfilesFromRegistry()
    {
        var result = new List<string>();
        try
        {
            using var list = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (list == null) return result;
            foreach (var sid in list.GetSubKeyNames())
            {
                try
                {
                    using var k = list.OpenSubKey(sid);

                    if (k?.GetValue("ProfileImagePath") is not string p || p.Length == 0) continue;
                    result.Add(Environment.ExpandEnvironmentVariables(p));
                }
                catch { }
            }
        }
        catch (Exception ex) { Log.Debug("HIPS-Plik", $"ProfileList: {ex.Message}"); }
        return result;
    }

    private static IEnumerable<string> ProfilesFromUsersFolder()
    {
        try
        {
            var drive = Environment.GetEnvironmentVariable("SystemDrive");
            if (string.IsNullOrEmpty(drive)) drive = "C:";
            var root = Path.Combine(drive + "\\", "Users");
            return Directory.Exists(root) ? Directory.GetDirectories(root) : Array.Empty<string>();
        }
        catch { return Array.Empty<string>(); }
    }

    private static IEnumerable<(string Path, bool Recursive)> ShortcutDirs()
    {
        yield return (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), false);
        yield return (Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), false);
        yield return (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                   @"Microsoft\Windows\Start Menu\Programs"), true);
        foreach (var p in UserProfiles())
        {
            yield return (Path.Combine(p, "Desktop"), false);
            var quick = Path.Combine(p, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch");
            yield return (Path.Combine(quick, @"User Pinned\TaskBar"), false);
            yield return (Path.Combine(quick, @"User Pinned\StartMenu"), false);
            yield return (Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"), true);
        }
    }

    private void Watch(string ruleId, string dir, string filter, bool recursive)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) return;
            if (_watchers.Any(w => string.Equals(w.Path, dir, StringComparison.OrdinalIgnoreCase)
                                   && w.Filter == filter)) return;

            var fsw = new FileSystemWatcher(dir, filter)
            {
                IncludeSubdirectories = recursive,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            fsw.Created += (_, e) => Queue(ruleId, e.FullPath);
            fsw.Changed += (_, e) => Queue(ruleId, e.FullPath);
            fsw.Renamed += (_, e) => Queue(ruleId, e.FullPath);
            fsw.Error += (_, e) => Log.Debug("HIPS-Plik", $"{dir}: {e.GetException().Message}");
            fsw.EnableRaisingEvents = true;
            _watchers.Add(fsw);
        }
        catch (Exception ex) { Log.Debug("HIPS-Plik", $"{dir}: {ex.Message}"); }
    }

    private void AttachRemovable()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType != DriveType.Removable || !d.IsReady) continue;
                Watch("file.autorun_usb", d.RootDirectory.FullName, "autorun.inf", false);
            }
            catch { }
        }
    }

    private void Queue(string ruleId, string path)
    {
        if (string.IsNullOrEmpty(path)) return;
        if (path.StartsWith(BaselineDir, StringComparison.OrdinalIgnoreCase)) return;
        _ruleOf[path] = ruleId;
        _pending[path] = DateTime.UtcNow;
    }

    private void Drain()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _pending.ToArray())
        {
            if ((now - kv.Value).TotalMilliseconds < 1500) continue;
            _pending.TryRemove(kv.Key, out _);

            if (_recent.TryGetValue(kv.Key, out var last) && (now - last).TotalSeconds < 60) continue;
            _recent[kv.Key] = now;

            if (!_ruleOf.TryGetValue(kv.Key, out var ruleId)) continue;
            try { Handle(ruleId, kv.Key); } catch (Exception ex) { Log.Debug("HIPS-Plik", ex.Message); }
        }
        foreach (var kv in _recent.ToArray())
            if ((now - kv.Value).TotalMinutes > 10) _recent.TryRemove(kv.Key, out _);

        if (_ruleOf.Count > 20000)
            foreach (var k in _ruleOf.Keys.ToArray())
                if (!_pending.ContainsKey(k) && !_recent.ContainsKey(k)) _ruleOf.TryRemove(k, out _);
    }

    private void Handle(string ruleId, string path)
    {
        if (ruleId == "file.system" && IsAccessibilityTool(path)) ruleId = "file.accessibility";

        var rule = HipsRules.ById(ruleId);
        if (rule == null) return;
        var (on, mode) = _hips.StateOf(ruleId);
        if (!_hips.Enabled || !on) return;

        if (SystemGuard.IsOwnComponent(path)) return;

        if (HipsSelfGuard.IsOwnTaskFile(path)) return;

        if (_hips.IsExcepted(ruleId, path))
        {
            Log.Debug("HIPS-Plik", $"User exception for {ruleId}: {path}");
            return;
        }
        if (!File.Exists(path)) return;

        string? extra;
        bool canJudge = true;
        switch (ruleId)
        {
            case "file.system":
            case "file.sys_subdirs":

                if (!IsExecutableFile(path) && ruleId == "file.system") return;
                if (HipsTrust.IsTrustedProgram(path)) return;

                if (ConfirmedMalware(path))
                {
                    extra = Loc.T("silnik potwierdza zagrożenie w pliku systemowym");
                }
                else
                {
                    extra = Loc.T("brak zaufanego podpisu — plik nie został rozpoznany jako zagrożenie");
                    canJudge = false;
                }
                break;

            case "file.accessibility":
                extra = AccessibilityHijack(path);
                if (extra == null) return;
                break;

            case "file.hosts":
                if (!IsHostsFile(path)) return;
                if (!TextFileChanged(path, out extra)) return;
                break;

            case "file.shortcuts":
                if (!ShortcutChanged(path)) return;
                extra = JudgeTarget(TargetOfShortcut(path), out canJudge);
                if (extra == null && canJudge) return;
                break;

            case "file.tasks":
                if (path.EndsWith(".job", StringComparison.OrdinalIgnoreCase)) { extra = "zadanie w starym formacie"; break; }

                if (TaskRunsNoProgram(path)) return;
                extra = JudgeTarget(TargetOfTask(path), out canJudge);

                if (!canJudge && IsSystemOwnedTask(path)) return;
                if (extra == null && canJudge) return;
                break;

            case "file.startup":
            case "file.startup_ext":
                extra = JudgeTarget(StartupTarget(path), out canJudge);
                if (extra == null && canJudge) return;
                break;

            case "file.psprofile":
                if (!IsPowerShellProfile(path)) return;
                extra = Loc.T("skrypt wykonywany przy każdym starcie programu PowerShell");
                break;

            case "file.gpo_scripts":
            case "file.office":
            case "file.autorun_usb":
                extra = null;
                break;

            case "file.systemp":
                if (!IsExecutableFile(path)) return;
                if (HipsTrust.IsTrustedProgram(path)) return;
                extra = "program bez zaufanego podpisu w katalogu tymczasowym systemu";
                break;

            default:
                return;
        }

        var effective = mode;
        if (!canJudge && mode == HipsRules.Mode.Block)
        {
            effective = HipsRules.Mode.Ask;
            extra = (extra == null ? "" : extra + "; ") + Loc.T("nie ustalono celu, więc nie cofnięto automatycznie");
        }

        string detail = $"{rule.Name}: {path}" + (extra != null ? $" ({extra})" : "");
        string action = effective == HipsRules.Mode.Block ? "block" : effective == HipsRules.Mode.Log ? "log" : "ask";
        _activity.ReportHips(ruleId, rule.Name, "plik", path, detail, action,
                             fix: effective == HipsRules.Mode.Ask
                                 ? new System.Text.Json.Nodes.JsonObject
                                   {
                                       ["kind"] = "file",
                                       ["rule"] = ruleId,
                                       ["path"] = path,
                                       ["where"] = path,
                                   }
                                 : null);

        bool undone = false;
        if (effective == HipsRules.Mode.Block)
        {
            undone = Revert(ruleId, path);
            Log.Alert("HIPS", $"[{rule.Name}] {path} — {(undone ? "reverted" : "FAILED to revert")}");
            _notify.Threat(undone ? "File change reverted" : "Failed to revert file change",
                           path, rule.Name, AlertSeverity.High);
        }
        else if (effective == HipsRules.Mode.Ask)
        {
            Log.Alert("HIPS", $"[{rule.Name}] {path} — reported (mode: ask, awaiting user decision)");
            _notify.Threat("File change detected", path, rule.Name, AlertSeverity.Medium);
        }
        else Log.Info("HIPS", detail);

        if (ruleId is "file.hosts" or "file.shortcuts" && !undone && effective != HipsRules.Mode.Block)
            SaveBaseline(path);
    }

    private static string? JudgeTarget(string? target, out bool canJudge)
    {
        canJudge = target != null;
        return target == null ? null : HipsTrust.SuspectReason(target);
    }

    private static bool IsSystemOwnedTask(string path)
    {
        try
        {
            var tasksRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!path.StartsWith(tasksRoot, StringComparison.OrdinalIgnoreCase)) return false;

            return Malward.Engine.Util.SystemFileCheck.IsOwnedBySystemAuthority(path);
        }
        catch
        {
            return true;
        }
    }

    private static bool TaskRunsNoProgram(string path)
    {
        try
        {
            if (path.EndsWith(".job", StringComparison.OrdinalIgnoreCase)) return false;
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length > 512 * 1024) return false;
            var xml = File.ReadAllText(path);
            if (xml.IndexOf("<Exec", StringComparison.OrdinalIgnoreCase) >= 0) return false;

            return xml.IndexOf("<ComHandler", StringComparison.OrdinalIgnoreCase) >= 0
                || xml.IndexOf("<Actions", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        catch { return false; }
    }

    private static bool IsExecutableFile(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".exe" or ".dll" or ".sys" or ".ocx" or ".scr" or ".cpl" or ".drv" or ".mof";
    }

    private static bool IsHostsFile(string path) =>
        HostsFiles.Contains(Path.GetFileName(path), StringComparer.OrdinalIgnoreCase);

    private static bool IsAccessibilityTool(string path) =>
        AccessibilityTools.Contains(Path.GetFileName(path), StringComparer.OrdinalIgnoreCase);

    private static bool IsPowerShellProfile(string path)
    {
        var n = Path.GetFileName(path);
        return n.EndsWith("profile.ps1", StringComparison.OrdinalIgnoreCase);
    }

    private static string? AccessibilityHijack(string path)
    {
        try
        {
            var onDisk = Path.GetFileName(path);
            var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            var original = info.OriginalFilename;

            if (string.IsNullOrWhiteSpace(original))
            {
                return Malward.Engine.Util.SystemFileCheck.IsSignedByMicrosoft(path)
                    ? null
                    : Loc.T("plik nie podaje własnej nazwy i nie ma podpisu Microsoftu — możliwa podmiana");
            }

            if (string.Equals(Stem(original), Stem(onDisk), StringComparison.OrdinalIgnoreCase))
                return null;

            var udaje = Stem(original) + ".exe";
            var powloki = Malward.Engine.Data.SignatureStore.List("shell_impersonation_names");
            foreach (var shell in powloki)
                if (string.Equals(udaje, shell, StringComparison.OrdinalIgnoreCase))
                    return Loc.F("narzędzie dostępności {0} jest w rzeczywistości programem {1}", onDisk, original);

            var para = onDisk.ToLowerInvariant() + "|" + udaje.ToLowerInvariant();
            foreach (var alias in Malward.Engine.Data.SignatureStore.List("accessibility_legit_aliases"))
                if (string.Equals(para, alias, StringComparison.OrdinalIgnoreCase))
                    return null;

            if (powloki.Length == 0)
                return Loc.F("plik podaje się za {0}, a nosi nazwę {1}", original, onDisk);

            return Malward.Engine.Util.SystemFileCheck.IsSignedByMicrosoft(path)
                ? null
                : Loc.F("plik podaje się za {0}, a nosi nazwę {1}", original, onDisk);
        }
        catch { return null; }
    }

    private static string Stem(string name)
    {
        var n = name.Trim();
        if (n.EndsWith(".mui", StringComparison.OrdinalIgnoreCase)) n = n[..^4];
        return Path.GetFileNameWithoutExtension(n);
    }

    private static string? TargetOfTask(string path)
    {
        try
        {
            var xml = File.ReadAllText(path);
            var m = Regex.Match(xml, @"<Command>\s*(.+?)\s*</Command>",
                                RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (!m.Success) return null;
            var cmd = Environment.ExpandEnvironmentVariables(m.Groups[1].Value.Trim().Trim('"'));
            return File.Exists(cmd) ? cmd : ResolveOnPath(cmd);
        }
        catch { return null; }
    }

    private static string? StartupTarget(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext is ".lnk" or ".url") return TargetOfShortcut(path);
        return path;
    }

    private static string? TargetOfShortcut(string path)
    {
        try
        {
            if (path.EndsWith(".url", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var line in File.ReadAllLines(path))
                    if (line.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
                    {
                        var v = line[4..].Trim();
                        if (v.StartsWith("file:///", StringComparison.OrdinalIgnoreCase))
                            v = Uri.UnescapeDataString(v[8..]).Replace('/', '\\');
                        return File.Exists(v) ? v : null;
                    }
                return null;
            }

            var bytes = File.ReadAllBytes(path);
            if (bytes.Length > 4 * 1024 * 1024) return null;
            foreach (var text in new[] { System.Text.Encoding.Latin1.GetString(bytes),
                                         System.Text.Encoding.Unicode.GetString(bytes) })
            {
                foreach (Match m in Regex.Matches(text,
                             @"[A-Za-z]:\\[^\x00-\x1F""<>|?*]{2,240}?\.(?:exe|com|bat|cmd|scr|ps1|vbs|js|dll)",
                             RegexOptions.IgnoreCase))
                {
                    var cand = Environment.ExpandEnvironmentVariables(m.Value);
                    if (File.Exists(cand)) return cand;
                }
            }
            return null;
        }
        catch { return null; }
    }

    private static string? ResolveOnPath(string command)
    {
        try
        {
            if (command.Contains('\\')) return null;
            var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';');
            foreach (var d in dirs)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                var p = Path.Combine(d.Trim(), command);
                if (File.Exists(p)) return p;
                if (!Path.HasExtension(p) && File.Exists(p + ".exe")) return p + ".exe";
            }
            return null;
        }
        catch { return null; }
    }

    private static bool TextFileChanged(string path, out string? extra)
    {
        extra = null;
        try
        {
            var baseline = BaselinePath(path);
            if (!File.Exists(baseline)) { SaveBaseline(path); return false; }
            var now = ReadLinesSafe(path);
            var was = ReadLinesSafe(baseline);
            if (now.SequenceEqual(was)) return false;

            var added = now.Except(was)
                           .Select(l => l.Trim())
                           .Where(l => l.Length > 0 && !l.StartsWith("#"))
                           .ToList();
            if (added.Count == 0) return false;
            extra = "dodano: " + string.Join(", ", added.Take(3)) + (added.Count > 3 ? $" (+{added.Count - 3})" : "");
            return true;
        }
        catch { return false; }
    }

    private static bool ShortcutChanged(string path)
    {
        try
        {
            var baseline = BaselinePath(path);
            if (!File.Exists(baseline)) { SaveBaseline(path); return true; }
            return !File.ReadAllBytes(path).SequenceEqual(File.ReadAllBytes(baseline));
        }
        catch { return false; }
    }

    private static string[] ReadLinesSafe(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            return sr.ReadToEnd().Replace("\r\n", "\n").Split('\n');
        }
        catch { return Array.Empty<string>(); }
    }

    private static string BaselinePath(string path)
    {
        var bytes = System.Text.Encoding.Unicode.GetBytes(path.ToLowerInvariant());
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16];
        return Path.Combine(BaselineDir, $"{hash}_{Path.GetFileName(path)}");
    }

    private static void SaveBaseline(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            Directory.CreateDirectory(BaselineDir);
            File.Copy(path, BaselinePath(path), overwrite: true);
        }
        catch { }
    }

    private static void SaveBaselineIfMissing(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            if (File.Exists(BaselinePath(path))) return;
            Directory.CreateDirectory(BaselineDir);
            File.Copy(path, BaselinePath(path), overwrite: false);
        }
        catch { }
    }

    private static void SaveBaselineDirIfMissing(string dir, string filter, bool recursive)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            var opt = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            foreach (var f in Directory.EnumerateFiles(dir, filter, opt)) SaveBaselineIfMissing(f);
        }
        catch { }
    }

    internal static bool Revert(string ruleId, string path)
    {
        try
        {
            switch (ruleId)
            {
                case "file.hosts":
                case "file.shortcuts":
                {
                    var baseline = BaselinePath(path);
                    if (!File.Exists(baseline))
                    {
                        return ThreatHandler.QuarantineForHips(path, HipsRules.ById(ruleId)?.Name ?? ruleId);
                    }
                    File.Copy(baseline, path, overwrite: true);
                    return true;
                }

                case "file.tasks":
                {
                    var name = TaskNameOf(path);
                    if (name != null)
                    {
                        var outcome = Malward.Engine.Repair.TaskRepair.Remove(
                            Malward.Engine.Repair.TaskRepair.ModernPrefix + name);
                        if (outcome.Ok) return true;
                        Log.Warn("HIPS-Plik", $"Task removal failed: {outcome.Error}");
                    }
                    return ThreatHandler.QuarantineForHips(path, "Folder zadań harmonogramu");
                }

                case "file.ads":
                    return DeleteStream(path);

                default:

                    return ThreatHandler.QuarantineForHips(path, HipsRules.ById(ruleId)?.Name ?? ruleId);
            }
        }
        catch (Exception ex) { Log.Warn("HIPS-Plik", $"Revert failed: {ex.Message}"); return false; }
    }

    private static string? TaskNameOf(string path)
    {
        try
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return null;
            var rel = path[root.Length..].TrimStart('\\');
            return rel.Length == 0 ? null : "\\" + rel;
        }
        catch { return null; }
    }

    public void Inspect(string path)
    {
        InspectDownloadSource(path);
        try
        {
            var (on, mode) = _hips.StateOf("file.ads");
            if (!_hips.Enabled || !on) return;
            if (!File.Exists(path)) return;
            if (SystemGuard.IsOwnComponent(path)) return;
            if (_hips.IsExcepted("file.ads", path)) return;

            var now = DateTime.UtcNow;
            if (_recent.TryGetValue("ads:" + path, out var last) && (now - last).TotalSeconds < 60) return;

            foreach (var (name, size) in Streams(path))
            {
                if (BenignStreams.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
                if (size < 512) continue;
                _recent["ads:" + path] = now;
                var rule = HipsRules.ById("file.ads")!;
                string target = $"{path}:{name}";
                string detail = Loc.F("Ukryty strumień danych {0} ({1} B) w pliku {2}", name, size, path);
                string action = mode == HipsRules.Mode.Block ? "block" : mode == HipsRules.Mode.Log ? "log" : "ask";
                _activity.ReportHips("file.ads", rule.Name, "plik", target, detail, action);

                if (mode == HipsRules.Mode.Block)
                {
                    bool undone = DeleteStream(target);
                    Log.Alert("HIPS", $"[{rule.Name}] {detail} — {(undone ? "stream removed" : "FAILED to remove")}");
                    _notify.Threat(undone ? "Hidden data stream removed" : "Failed to remove data stream",
                                   target, rule.Name, AlertSeverity.High);
                }
                else if (mode == HipsRules.Mode.Ask)
                {
                    Log.Alert("HIPS", $"[{rule.Name}] {detail} — reported (mode: ask)");
                    _notify.Threat("Hidden data stream detected", target, rule.Name, AlertSeverity.Medium);
                }
                else Log.Info("HIPS", detail);
                return;
            }
        }
        catch { }
    }

    private static readonly Malward.NetworkScanner.BotIpBlocklist BadIps =
        new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                         "Malward", "data", "vps-ex01.vdeb"));

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime When, bool Bad)>
        HostVerdicts = new(StringComparer.OrdinalIgnoreCase);

    private void InspectDownloadSource(string path)
    {
        try
        {
            var (on, mode) = _hips.StateOf("file.badip_source");
            if (!_hips.Enabled || !on) return;
            if (BadIps.IsEmpty) return;
            if (!File.Exists(path)) return;
            if (SystemGuard.IsOwnComponent(path)) return;
            if (_hips.IsExcepted("file.badip_source", path)) return;

            var now = DateTime.UtcNow;
            if (_recent.TryGetValue("badip:" + path, out var last) && (now - last).TotalSeconds < 300) return;

            var host = OriginHost(path);
            if (host == null) return;
            _recent["badip:" + path] = now;

            Task.Run(() =>
            {
                try
                {
                    if (!HostIsBad(host, out var ip)) return;
                    ReportBadIpSource(path, host, ip, mode);
                }
                catch (Exception ex) { Log.Debug("HIPS-Plik", $"badip: {ex.Message}"); }
            });
        }
        catch (Exception ex) { Log.Debug("HIPS-Plik", $"badip: {ex.Message}"); }
    }

    private void ReportBadIpSource(string path, string host, string ip, HipsRules.Mode mode)
    {
        var rule = HipsRules.ById("file.badip_source")!;
        string detail = Loc.F("Plik pobrany z adresu z bazy złośliwych IP: {0} ({1}) -> {2}", host, ip, path);
        string action = mode == HipsRules.Mode.Block ? "block" : mode == HipsRules.Mode.Log ? "log" : "ask";

        _activity.ReportHips("file.badip_source", rule.Name, "plik", path, detail, action,
            fix: mode == HipsRules.Mode.Ask
                ? new System.Text.Json.Nodes.JsonObject
                  {
                      ["kind"] = "file",
                      ["rule"] = "file.badip_source",
                      ["path"] = path,
                      ["where"] = path,
                  }
                : null);

        if (mode == HipsRules.Mode.Block)
        {
            bool undone = ThreatHandler.QuarantineForHips(path, rule.Name);
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — {(undone ? "moved to quarantine" : "FAILED to quarantine")}");
            _notify.Threat(undone ? "Blocked file from malicious address" : "Failed to block file",
                           path, rule.Name, AlertSeverity.High);
        }
        else if (mode == HipsRules.Mode.Ask)
        {
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — reported (mode: ask, awaiting user decision)");
            _notify.Threat("File downloaded from malicious address", path, rule.Name, AlertSeverity.Medium);
        }
        else Log.Info("HIPS", detail);
    }

    internal static string? OriginHost(string path)
    {
        try
        {
            string text;
            try { text = File.ReadAllText(path + ":Zone.Identifier"); }
            catch { return null; }
            string? url = Field(text, "HostUrl=") ?? Field(text, "ReferrerUrl=");
            if (string.IsNullOrWhiteSpace(url)) return null;
            if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return null;

            if (uri.HostNameType == UriHostNameType.Unknown || uri.Host.Length == 0) return null;
            if (uri.IsLoopback) return null;
            return uri.Host;
        }
        catch { return null; }

        static string? Field(string text, string key)
        {
            foreach (var line in text.Split('\n'))
            {
                var t = line.Trim();
                if (t.StartsWith(key, StringComparison.OrdinalIgnoreCase))
                    return t[key.Length..].Trim();
            }
            return null;
        }
    }

    internal static bool HostIsBad(string host, out string ip)
    {
        ip = "";

        if (System.Net.IPAddress.TryParse(host, out var literal))
        {
            ip = literal.ToString();
            return BadIps.Contains(ip);
        }

        if (HostVerdicts.TryGetValue(host, out var cached)
            && (DateTime.UtcNow - cached.When) < TimeSpan.FromMinutes(30))
        {
            ip = host;
            return cached.Bad;
        }

        try
        {
            foreach (var a in System.Net.Dns.GetHostAddresses(host))
            {
                var t = a.ToString();
                if (BadIps.Contains(t))
                {
                    ip = t;
                    HostVerdicts[host] = (DateTime.UtcNow, true);
                    return true;
                }
            }
            HostVerdicts[host] = (DateTime.UtcNow, false);
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static readonly string[] BenignStreams =
    {
        "Zone.Identifier", "SmartScreen", "favicon", "OECustomProperty", "Afp_AfpInfo",
        "com.dropbox.attrs", "ms-properties", "Outlook.MAPI", "encryptable",
    };

    private static IEnumerable<(string Name, long Size)> Streams(string path)
    {
        var handle = FindFirstStreamW(path, 0, out var data, 0);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) yield break;
        try
        {
            do
            {
                var raw = data.cStreamName ?? "";
                var parts = raw.Split(':');
                if (parts.Length < 2) continue;
                var name = parts[1];
                if (name.Length == 0) continue;
                yield return (name, data.StreamSize);
            } while (FindNextStreamW(handle, out data));
        }
        finally { FindClose(handle); }
    }

    private static bool DeleteStream(string streamPath)
    {
        int start = streamPath.Length > 1 && streamPath[1] == ':' ? 2 : 0;
        int sep = streamPath.IndexOf(':', start);
        if (sep <= start) return false;
        var file = streamPath[..sep];
        var stream = streamPath[(sep + 1)..];
        if (stream.Length == 0 || !File.Exists(file)) return false;
        return DeleteFileW(@"\\?\" + streamPath);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel,
                                                  out WIN32_FIND_STREAM_DATA data, int flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(IntPtr handle, out WIN32_FIND_STREAM_DATA data);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteFileW(string lpFileName);

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
        try { _loop?.Wait(2000); } catch { }
        _cts?.Dispose();
    }
}
