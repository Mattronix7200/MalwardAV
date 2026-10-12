using Malward.Engine.Util;
namespace Malward.ResidentShield;

public enum BehaviorSeverity { Low = 1, Medium = 2, High = 3 }

public sealed record BehaviorAlert(
    int              Pid,
    string           ProcessName,
    BehaviorSeverity Severity,
    string           Category,
    string           Description);

public static class BehaviorAnalyzer
{
    private static readonly string[] SuspiciousWriteDirs =
    [
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\Tasks",
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ];

    private static string[] SecurityKeys => Sig("security_reg_keys");

    private static string IfeoPathFragment
    {
        get
        {
            var v = Sig("autostart_reg_keys");
            var f = v.FirstOrDefault(x => x.Contains("Execution Options", StringComparison.OrdinalIgnoreCase));
            return string.IsNullOrEmpty(f) ? "\u0000brak" : f;
        }
    }

    private static string[]? _defenseEvasionValues;
    private static string[] DefenseEvasionValues =>
        _defenseEvasionValues ??= Malward.Engine.Data.SignatureStore.List("defense_evasion_values");

    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "csrss", "winlogon", "services",
        "explorer", "dwm", "wininit", "smss", "spoolsv", "taskhost", "taskhostw",
    };

    private static HashSet<string>? _lolBinNames;
    private static HashSet<string> LolBinNames =>
        _lolBinNames ??= new HashSet<string>(
            Malward.Engine.Data.SignatureStore.List("lolbin_names"), StringComparer.OrdinalIgnoreCase);

    private static string[]? _ransomNotes, _ransomExts;

    private static string[] RansomNoteNames =>
        _ransomNotes ??= Malward.Engine.Data.SignatureStore.List("ransom_notes");

    private static string[] RansomEncryptedExtensions =>
        _ransomExts ??= Malward.Engine.Data.SignatureStore.List("ransom_extensions");

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1",
        ".bat", ".cmd", ".lnk", ".jar", ".msi",
    };

    public static IReadOnlyList<BehaviorAlert> Analyze(ProcessTracker tracker, int pid, ShieldConfig cfg,
        bool viaTrustedTool = false)
    {
        var alerts = new List<BehaviorAlert>();
        var proc   = tracker.GetProcess(pid);
        if (proc == null) return alerts;

        var changes = tracker.GetChanges(pid);

        CheckAutostartModification(proc, changes, alerts);
        CheckServiceCreation(proc, changes, alerts);
        CheckScheduledTask(proc, changes, alerts);
        CheckSuspiciousFileWrite(proc, changes, alerts);
        CheckSecurityKeyModification(proc, changes, alerts, viaTrustedTool);
        CheckDefenseEvasionValues(proc, changes, alerts, viaTrustedTool);
        CheckProcessSpoofing(proc, alerts);
        CheckSuspiciousLolBinChain(tracker, proc, alerts);
        CheckChildProcessSpawning(tracker, proc, alerts);
        if (cfg.RansomwareDetect.VssDeleteHook)
            CheckShadowCopyActivity(proc, alerts);
        CheckRansomware(tracker, proc, cfg, alerts);
        CheckRansomNoteSignatures(tracker, proc, cfg, alerts);
        CheckEncryptionEntropy(tracker, proc, cfg, alerts);
        CheckRansomEncryptedExtension(tracker, proc, cfg, alerts);

        CheckDiscoveryBurst(tracker, proc, alerts);
        CheckAnonymisedC2(tracker, proc, alerts);

        CheckReplication(proc, changes, cfg, alerts);

        ComputeBehaviorScore(proc, cfg, alerts);

        return alerts;
    }

    private static void CheckAutostartModification(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, List<BehaviorAlert> alerts)
    {
        var autostarts = changes.Where(c => c.IsAutostart).ToList();
        if (autostarts.Count == 0) return;

        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "Persistence",
            Loc.F("Dodano {0} wpis(ów) autostartu: ", autostarts.Count) +
            string.Join(", ", autostarts.Select(c => c.Location).Distinct().Take(3))));
    }

    private static void CheckServiceCreation(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, List<BehaviorAlert> alerts)
    {
        var svcs = changes.Where(c => c.Kind == ChangeKind.ServiceCreate)
                          .Select(c => c.Location).Distinct().ToList();
        if (svcs.Count == 0) return;

        if (!IsTrustedProcess(proc))
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "Persistence",
                Loc.F("Utworzono usługę systemową: {0}", string.Join(", ", svcs.Take(3)))));
    }

    private static void CheckScheduledTask(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, List<BehaviorAlert> alerts)
    {
        var tasks = changes.Where(c => c.Kind == ChangeKind.ScheduledTask)
                           .Select(c => c.Location).Distinct().ToList();
        if (tasks.Count == 0) return;

        if (!IsTrustedProcess(proc))
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "Persistence",
                $"Utworzono zadanie harmonogramu: {string.Join(", ", tasks.Take(3))}"));
    }

    private static readonly Dictionary<string, string[]> SigCache = new();
    private static string[] Sig(string key)
    {
        lock (SigCache)
        {
            if (!SigCache.TryGetValue(key, out var v))
            { v = Malward.Engine.Data.SignatureStore.List(key); SigCache[key] = v; }
            return v;
        }
    }

    private static readonly string[] RequiredSignatureKeys =
    {
        "shadow_tools", "shadow_phrases", "boot_tamper", "usn_tamper", "security_binaries",
        "defender_cmdlets", "defender_disable_switches", "defender_exclusion_switches",
        "defense_evasion_values", "lolbin_names", "lolbin_abuse_pairs", "script_hosts",
        "interpreter_images", "download_tool_switches",
        "lolbin_download_tools", "lolbin_remote_tools",
        "miner_pool_markers", "miner_flags", "miner_wallet_flags", "anon_c2_tools",
        "hips_rule_text", "hips_registry_watches",
        "security_reg_keys", "autostart_reg_keys", "tamper_restore",
        "ifeo_debug_values", "ifeo_path_fragment",
        "shell_impersonation_names", "accessibility_legit_aliases",
        "onhost_compilers",
    };

    public static IReadOnlyList<string> MissingSignatureKeys()
    {
        var missing = new List<string>();
        foreach (var key in RequiredSignatureKeys)
            if (Sig(key).Length == 0) missing.Add(key);
        return missing;
    }

    private static void CheckSuspiciousFileWrite(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, List<BehaviorAlert> alerts)
    {
        if (IsTrustedProcess(proc)) return;
        var writes = changes
            .Where(c => c.Kind is ChangeKind.FileCreate or ChangeKind.FileModify)
            .Select(c => c.Location)
            .Where(p => SuspiciousWriteDirs.Any(d => p.StartsWith(d, StringComparison.OrdinalIgnoreCase)))
            .Distinct().ToList();

        if (writes.Count == 0) return;

        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.Medium, "SuspiciousWrite",
            $"Zapis do chronionego katalogu: {writes[0]}"));
    }

    private static void CheckSecurityKeyModification(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, List<BehaviorAlert> alerts,
        bool viaTrustedTool = false)
    {
        if (!viaTrustedTool && IsTrustedProcess(proc)) return;

        var sec = changes
            .Where(c => c.Kind is ChangeKind.RegSet or ChangeKind.RegCreate
                     && SecurityKeys.Any(k => c.Location.Contains(k, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (sec.Count == 0) return;

        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "DefenseImpairment",
            Loc.F("Modyfikacja klucza bezpieczeństwa: {0}", sec[0].Location)));
    }

    private static void CheckDefenseEvasionValues(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, List<BehaviorAlert> alerts,
        bool viaTrustedTool = false)
    {
        if (!viaTrustedTool && IsTrustedProcess(proc)) return;

        var hits = changes
            .Where(c => c.Kind is ChangeKind.RegSet or ChangeKind.RegCreate
                     && c.Extra != null
                     && DefenseEvasionValues.Any(v => string.Equals(v, c.Extra, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (hits.Count == 0) return;

        bool ifeoDebugger = hits.Any(h =>
            string.Equals(h.Extra, "Debugger", StringComparison.OrdinalIgnoreCase) &&
            h.Location.Contains(IfeoPathFragment, StringComparison.OrdinalIgnoreCase));

        string cat = ifeoDebugger ? "AntiDebug" : "DefenseImpairment";
        string desc = ifeoDebugger
            ? $"IFEO Debugger hijack (omijanie AV): {hits[0].Location}"
            : Loc.F("Wyłączanie zabezpieczeń ({0}): {1}", hits[0].Extra, hits[0].Location);

        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, cat, desc));
    }

    private static void CheckProcessSpoofing(ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        if (!ProtectedProcessNames.Contains(proc.Name)) return;
        if (string.IsNullOrEmpty(proc.ImagePath) || !proc.ImagePath.Contains('\\')) return;

        string l = proc.ImagePath.ToLowerInvariant();
        bool isSystem = l.Contains(@"windows\system32") || l.Contains(@"windows\syswow64")
                     || l.Contains(@"windows\winsxs");

        if (!isSystem)
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "ProcessSpoofing",
                $"Proces \"{proc.Name}\" uruchomiony spoza System32: {proc.ImagePath}"));
    }

    private static void CheckSuspiciousLolBinChain(
        ProcessTracker tracker, ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        var parent = tracker.GetProcess(proc.ParentPid);
        if (parent == null) return;

        string childBase = StripExe(proc.Name);
        if (!LolBinNames.Contains(childBase)) return;

        bool parentSuspicious = !IsTrustedPath(parent.ImagePath) || IsUserDocApp(parent.Name);
        if (parentSuspicious)
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.Medium, "SuspiciousChain",
                Loc.F("{0} → {1} (możliwe wykonanie/wstrzyknięcie kodu)", parent.Name, proc.Name)));
    }

    private static void CheckChildProcessSpawning(
        ProcessTracker tracker, ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        var children = tracker.GetChildren(proc.Pid).ToList();
        if (children.Count < 3) return;

        var ownCore = NameCore(proc.Name);
        int sameName = children.Count(c =>
            NameCore(c.Name).Equals(ownCore, StringComparison.OrdinalIgnoreCase));

        if (sameName >= 3)
        {
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "SelfReplication",
                $"Proces spawnuje {sameName} kopii samego siebie ({proc.Name})"));
            return;
        }

        if (children.Count >= 5 && !IsTrustedProcess(proc))
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.Medium, "ExcessiveChildSpawning",
                Loc.F("Proces z niezaufanej lokalizacji tworzy {0} procesów potomnych", children.Count)));
    }

    private static void CheckRansomware(
        ProcessTracker tracker, ProcessInfo proc, ShieldConfig cfg, List<BehaviorAlert> alerts)
    {
        if (!cfg.RansomwareDetect.MassRename) return;
        if (IsTrustedProcess(proc)) return;

        int score = tracker.RansomwareScore(proc.Pid, cfg.RansomwareWindowMs);
        if (score >= cfg.RansomwareFileThreshold)
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "Ransomware",
                Loc.F("Masowa modyfikacja plików: {0} plików w {1} ms", score, cfg.RansomwareWindowMs)));
    }

    private static void CheckRansomNoteSignatures(
        ProcessTracker tracker, ProcessInfo proc, ShieldConfig cfg, List<BehaviorAlert> alerts)
    {
        if (!cfg.RansomwareDetect.RansomNoteSignatures) return;
        if (IsTrustedProcess(proc)) return;

        var changes = tracker.GetChanges(proc.Pid);
        foreach (var ch in changes)
        {
            if (ch.Kind != ChangeKind.FileCreate) continue;
            var fname = Path.GetFileName(ch.Location).ToLowerInvariant();
            if (string.IsNullOrEmpty(fname)) continue;
            foreach (var sig in RansomNoteNames)
            {
                if (fname.StartsWith(sig, StringComparison.Ordinal) ||
                    fname.Contains(sig, StringComparison.Ordinal))
                {
                    alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High,
                        "RansomNote",
                        Loc.F("Utworzono notkę szantażową: {0}", Path.GetFileName(ch.Location))));
                    return;
                }
            }
        }
    }

    public static bool IsRansomNoteName(string fileNameLower)
    {
        if (string.IsNullOrEmpty(fileNameLower)) return false;
        foreach (var sig in RansomNoteNames)
            if (fileNameLower.StartsWith(sig, StringComparison.Ordinal) ||
                fileNameLower.Contains(sig, StringComparison.Ordinal))
                return true;
        return false;
    }

    private static void CheckEncryptionEntropy(
        ProcessTracker tracker, ProcessInfo proc, ShieldConfig cfg, List<BehaviorAlert> alerts)
    {
        if (!cfg.RansomwareDetect.EntropyCheck) return;
        if (IsTrustedProcess(proc)) return;

        var changes = tracker.GetChanges(proc.Pid);
        int highEntropyCount = 0;
        double maxEntropy = 0;
        foreach (var ch in changes)
        {
            if (ch.Kind != ChangeKind.FileModify && ch.Kind != ChangeKind.FileCreate) continue;
            if (string.IsNullOrEmpty(ch.Location)) continue;

            FileInfo fi;
            try { fi = new FileInfo(ch.Location); if (!fi.Exists) continue; }
            catch { continue; }
            if (fi.Length < 1024 || fi.Length > 4 * 1024 * 1024) continue;
            try
            {
                using var fs = fi.OpenRead();
                var buf = new byte[Math.Min(4096, fi.Length)];
                int n = fs.Read(buf, 0, buf.Length);
                double e = ShannonEntropy(buf.AsSpan(0, n));
                if (e > maxEntropy) maxEntropy = e;
                if (e >= cfg.RansomwareDetect.EntropyThreshold) highEntropyCount++;
                if (highEntropyCount >= cfg.RansomwareDetect.EntropyMinFiles)
                {
                    alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High,
                        "EncryptionEntropy",
                        Loc.F("{0} plików zaszyfrowanych (entropia ≥ {1:F1}, maks. {2:F2})", highEntropyCount, cfg.RansomwareDetect.EntropyThreshold, maxEntropy)));
                    return;
                }
            }
            catch {  }
        }
    }

    private static void CheckRansomEncryptedExtension(
        ProcessTracker tracker, ProcessInfo proc, ShieldConfig cfg, List<BehaviorAlert> alerts)
    {
        if (!cfg.RansomwareDetect.MassRename) return;
        if (IsTrustedProcess(proc)) return;

        var changes = tracker.GetChanges(proc.Pid);
        int hits = 0;
        string? sampleExt = null;
        foreach (var ch in changes)
        {
            if (ch.Kind != ChangeKind.FileCreate) continue;
            var ext = Path.GetExtension(ch.Location).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext)) continue;
            foreach (var sig in RansomEncryptedExtensions)
            {
                if (ext == sig || ext.StartsWith(sig, StringComparison.Ordinal))
                {
                    hits++;
                    sampleExt ??= ext;
                    break;
                }
            }
            if (hits >= 3)
            {
                alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High,
                    "RansomExtension",
                    Loc.F("{0} plików dostało rozszerzenie ransomware '{1}'", hits, sampleExt)));
                return;
            }
        }
    }

    private static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> hist = stackalloc int[256];
        foreach (var b in data) hist[b]++;
        double e = 0;
        double inv = 1.0 / data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (hist[i] == 0) continue;
            double p = hist[i] * inv;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    private static void CheckShadowCopyActivity(ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        string cmd  = proc.CommandLine.ToLowerInvariant();
        string name = StripExe(proc.Name);

        bool vssDelete = Sig("shadow_tools").Contains(name) &&
            cmd.Contains("delete") && (cmd.Contains("shadow") || cmd.Contains("catalog"));

        bool bcdTamper = name == "bcdedit" && Sig("boot_tamper").Any(t => cmd.Contains(t));

        if (vssDelete || bcdTamper)
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "ShadowCopyDeletion",
                Loc.F("Sabotaż kopii zapasowych / odzyskiwania: {0}", proc.CommandLine)));
    }

    public static List<BehaviorAlert> AnalyzeCommandLine(ProcessInfo proc)
    {
        var alerts = new List<BehaviorAlert>();
        if (string.IsNullOrEmpty(proc.CommandLine)) return alerts;
        try
        {
            CheckLolBinCommandLine(proc, alerts);
            CheckAccountChange(proc, alerts);
            CheckProtectedProcessKill(proc, alerts);
            CheckCryptoMiner(proc, alerts);
        }
        catch { }
        return alerts;
    }

    private static void CheckLolBinCommandLine(ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        string cmd = proc.CommandLine.ToLowerInvariant();
        if (string.IsNullOrEmpty(cmd)) return;

        string? cat = null;

        if ((cmd.Contains("powershell") || cmd.Contains("pwsh")) &&
                (cmd.Contains(" -enc") || cmd.Contains("-encodedcommand") ||
                 cmd.Contains("frombase64string") || cmd.Contains("downloadstring") ||
                 cmd.Contains("-w hidden") || cmd.Contains("-windowstyle hidden") ||
                 cmd.Contains("bypass") && cmd.Contains("-nop")))
            cat = "LolBinHiddenScript";

        bool susp = cat != null

            || Sig("lolbin_abuse_pairs").Any(pair =>
               {
                   var i = pair.IndexOf('|');
                   if (i <= 0 || !cmd.Contains(pair[..i]) || !cmd.Contains(pair[(i + 1)..])) return false;
                   cat ??= ToolCategory(pair[..i]);
                   return true;
               })
            || (cmd.Contains("rundll32") && cmd.Contains("javascript:") && Mark(ref cat, "LolBinRemoteScript"))

            || (cmd.Contains("schtasks") && cmd.Contains("/create")
                && (cmd.Contains("onlogon") || cmd.Contains("onstart") || cmd.Contains("/sc minute"))
                && Mark(ref cat, "Persistence"))

            || (cmd.Contains("reg") && cmd.Contains(" add ")
                && (cmd.Contains(@"currentversion
un") || cmd.Contains("userinit")
                    || cmd.Contains("appinit_dlls") || cmd.Contains(@"\windows|load")))

            || (cmd.Contains("curl") && (cmd.Contains("-o ") || cmd.Contains("--output"))
                && (cmd.Contains(".exe") || cmd.Contains(".dll") || cmd.Contains(".scr"))
                && Mark(ref cat, "LolBinDownload"))

            || (Sig("defender_cmdlets").Any(x => cmd.Contains(x))
                && (Sig("defender_disable_switches").Any(x => cmd.Contains(x))
                        && Mark(ref cat, "DefenderDisable")
                    || Sig("defender_exclusion_switches").Any(x => cmd.Contains(x))
                        && Mark(ref cat, "DefenderExclusion")))
            || (cmd.Contains("wmic") && Sig("shadow_phrases").Length > 0
                && cmd.Contains(Sig("shadow_phrases")[0].Replace("win32_", "")) && cmd.Contains("delete")
                && Mark(ref cat, "ShadowCopyDeletion"));

        if (susp)
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, cat ?? "LolBinAbuse",
                Loc.F("Podejrzana linia poleceń: {0}", Trunc(proc.CommandLine, 160))));
    }

    private static bool Mark(ref string? cat, string value) { cat ??= value; return true; }

    private static string? ToolCategory(string tool)
    {
        if (Sig("lolbin_download_tools").Contains(tool, StringComparer.OrdinalIgnoreCase))
            return "LolBinDownload";
        if (Sig("lolbin_remote_tools").Contains(tool, StringComparer.OrdinalIgnoreCase))
            return "LolBinRemoteScript";
        if (tool.Equals("wmic", StringComparison.OrdinalIgnoreCase))
            return "LolBinWmic";
        return null;
    }

    private static void CheckAccountChange(ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        string cmd = proc.CommandLine.ToLowerInvariant();
        if (string.IsNullOrEmpty(cmd)) return;

        bool netUser = cmd.Contains("net") && cmd.Contains(" user ")
                       && (cmd.Contains("/add") || cmd.Contains("/delete") || cmd.Contains("/active:yes"));
        bool netGroup = cmd.Contains("localgroup") && cmd.Contains("/add");
        bool wmicUser = cmd.Contains("wmic") && cmd.Contains("useraccount");
        bool psUser = cmd.Contains("new-localuser") || cmd.Contains("add-localgroupmember");
        if (!netUser && !netGroup && !wmicUser && !psUser) return;

        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "AccountChange",
            Loc.F("Zmiana kont użytkowników: {0}", Trunc(proc.CommandLine, 160))));
    }

    private static void CheckProtectedProcessKill(ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        string cmd = proc.CommandLine.ToLowerInvariant();
        if (string.IsNullOrEmpty(cmd)) return;

        bool killing = cmd.Contains("taskkill") || cmd.Contains("stop-process")
                    || (cmd.Contains("wmic") && cmd.Contains("process") && cmd.Contains("call terminate"))
                    || (cmd.Contains("pskill"));

        bool stoppingService =
            (cmd.Contains("sc ") || cmd.Contains("sc.exe") || cmd.Contains("net ") ||
             cmd.Contains("stop-service") || cmd.Contains("set-service") || cmd.Contains("disable-service")) &&
            (cmd.Contains(" stop") || cmd.Contains(" delete") || cmd.Contains("start= disabled") ||
             cmd.Contains("start=disabled") || cmd.Contains("-startuptype disabled"));

        if (!killing && !stoppingService) return;

        if (OwnProcessNames.Any(n => cmd.Contains(n)) || Hips.HipsSelfGuard.TargetsOwnService(cmd))
            return;
        if (cmd.Contains("explorer.exe"))
        {
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.Medium, "ExplorerTamper",
                Loc.F("Próba zakończenia powłoki systemu: {0}", Trunc(proc.CommandLine, 160))));
            return;
        }

        if (Hips.HipsSelfGuard.IsOwnProcessTree(proc.Pid)) return;

        var cel = StopTarget(cmd);
        if (cel == null) return;
        if (Sig("security_binaries").Any(b => TargetMatches(cel, b)))
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "CriticalProcessKill",
                Loc.F("Próba zakończenia procesu ochronnego: {0}", Trunc(proc.CommandLine, 160))));
    }

    private static string? StopTarget(string cmd)
    {
        string[] markers = { " stop ", " delete ", "/im ", "-name ", "/f /im ", "stop-service ",
                             "stop-process ", "set-service ", "call terminate" };
        foreach (var m in markers)
        {
            int i = cmd.IndexOf(m, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            var reszta = cmd[(i + m.Length)..].TrimStart();
            var token = new string(reszta.TakeWhile(c => c is not (' ' or '"' or '\'' or ';' or ',')).ToArray());
            token = token.Trim('"', '\'');
            if (token.Length > 0) return token.ToLowerInvariant();
        }
        return null;
    }

    private static bool TargetMatches(string cel, string binary)
    {
        var b = binary.ToLowerInvariant();
        if (b.EndsWith(".exe", StringComparison.Ordinal)) b = b[..^4];
        var c = cel.EndsWith(".exe", StringComparison.Ordinal) ? cel[..^4] : cel;
        return b.Length >= 4 && string.Equals(b, c, StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] OwnProcessNames =
        { "malward.exe", "malscan.exe", "mwshield.exe", "heurscanner.exe" };

    private static void CheckCryptoMiner(ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        string cmd = proc.CommandLine.ToLowerInvariant();
        if (string.IsNullOrEmpty(cmd)) return;

        bool pool   = Sig("miner_pool_markers").Any(m => cmd.Contains(m));
        bool flags  = Sig("miner_flags").Any(m => cmd.Contains(m));
        bool wallet = Sig("miner_wallet_flags").Any(m => cmd.Contains(m));
        if (!pool || !(flags || wallet)) return;

        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "CryptoMiner",
            $"Parametry koparki kryptowalut: {Trunc(proc.CommandLine, 160)}"));
    }

    private static readonly HashSet<string> DiscoveryTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "whoami", "tasklist", "systeminfo", "ipconfig", "nslookup",
        "net", "net1", "query", "wmic", "hostname", "arp", "route",
    };

    private static void CheckDiscoveryBurst(ProcessTracker tracker, ProcessInfo proc,
                                            List<BehaviorAlert> alerts)
    {
        try
        {
            var children = tracker.GetChildren(proc.Pid).ToList();
            if (children.Count < 4) return;

            var recon = children
                .Where(c => DiscoveryTools.Contains(NameCore(c.Name)))
                .Select(c => NameCore(c.Name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (recon.Count < 4) return;

            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "ReconBurst",
                Loc.F("Seria poleceń rozpoznawczych ({0}): {1} ", recon.Count, string.Join(", ", recon.Take(6))) +
                "— typowe profilowanie maszyny przed atakiem"));
        }
        catch { }
    }

    private static void CheckAnonymisedC2(ProcessTracker tracker, ProcessInfo proc, List<BehaviorAlert> alerts)
    {
        try
        {
            var tools = Sig("anon_c2_tools");
            if (tools.Length == 0) return;

            bool byName = MatchesTool(tools, proc.Name);

            string? disguisedAs = null;
            if (!byName && !SystemGuard.IsProtectedPath(proc.ImagePath))
            {
                var built = OriginalFileName(proc.ImagePath);
                if (built != null && MatchesTool(tools, built)) disguisedAs = built;
            }
            if (!byName && disguisedAs == null) return;

            if (disguisedAs == null && StartedDeliberately(tracker, proc)) return;

            string detail = disguisedAs != null
                ? Loc.F("Narzędzie anonimizujące podszywa się pod inną nazwę: {0} to w rzeczywistości {1} ({2})", proc.Name, disguisedAs, proc.ImagePath)
                : Loc.F("Klient anonimizujący uruchomiony bez udziału użytkownika: {0}", proc.ImagePath);
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "AnonymisedC2", detail));
        }
        catch { }
    }

    private static bool StartedDeliberately(ProcessTracker tracker, ProcessInfo proc)
    {
        var parent = tracker.GetProcess(proc.ParentPid);
        if (parent == null) return false;
        if (ShellNames.Contains(StripExe(parent.Name))) return true;

        if (!SameInstallTree(parent.ImagePath, proc.ImagePath)) return false;
        var rep = tracker.GetReputation(parent.Pid, parent.ImagePath);
        return rep is ProcRep.Whitelisted or ProcRep.SystemTrusted;
    }

    private static bool MatchesTool(string[] tools, string? name)
    {
        var core = NameCore(name ?? "");
        if (core.Length == 0) return false;
        foreach (var t in tools)
            if (NameCore(t).Equals(core, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static readonly HashSet<string> ShellNames =
        new(StringComparer.OrdinalIgnoreCase) { "explorer", "searchhost", "searchapp", "startmenuexperiencehost" };

    private static bool SameInstallTree(string? parentPath, string? childPath)
    {
        try
        {
            if (string.IsNullOrEmpty(parentPath) || string.IsNullOrEmpty(childPath)) return false;
            var a = Path.GetDirectoryName(parentPath);
            var b = Path.GetDirectoryName(childPath);
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
            if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
            var prefix = a.EndsWith(Path.DirectorySeparatorChar) ? a : a + Path.DirectorySeparatorChar;
            return b.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static readonly Dictionary<string, string?> OriginalNameCache =
        new(StringComparer.OrdinalIgnoreCase);

    private static string NameCore(string name)
    {
        var n = (name ?? "").Trim();
        if (n.EndsWith(".mui", StringComparison.OrdinalIgnoreCase)) n = n[..^4];
        return StripExe(n);
    }

    private static string? OriginalFileName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        lock (OriginalNameCache)
        {
            if (OriginalNameCache.TryGetValue(path, out var hit)) return hit;
            string? built = null;
            try
            {
                var raw = System.Diagnostics.FileVersionInfo.GetVersionInfo(path).OriginalFilename;
                if (!string.IsNullOrWhiteSpace(raw)) built = raw.Trim();
            }
            catch { }

            if (OriginalNameCache.Count > 2000) OriginalNameCache.Clear();
            OriginalNameCache[path] = built;
            return built;
        }
    }

    private static void CheckReplication(
        ProcessInfo proc, IReadOnlyList<ProcessChange> changes, ShieldConfig cfg, List<BehaviorAlert> alerts)
    {
        var sc = cfg.BehaviorScoring;
        if (!sc.Enabled) return;
        if (IsTrustedProcess(proc)) return;
        if (string.IsNullOrEmpty(proc.ImagePath)) return;

        var createdPe = changes
            .Where(c => c.Kind == ChangeKind.FileCreate && IsExecutableFile(c.Location)
                        && !PathEq(c.Location, proc.ImagePath))
            .Select(c => c.Location)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (sc.SelfCopy && createdPe.Count > 0)
        {
            long imgSize = TryFileSize(proc.ImagePath);
            byte[]? imgHash = null;
            int copies = 0; string? sample = null;
            foreach (var f in createdPe)
            {
                if (imgSize <= 0 || TryFileSize(f) != imgSize) continue;
                imgHash ??= TryHash(proc.ImagePath);
                var fh = TryHash(f);
                if (imgHash != null && fh != null && imgHash.AsSpan().SequenceEqual(fh))
                { copies++; sample ??= f; }
            }
            if (copies >= 1)
                alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "Replicator",
                    Loc.F("Proces kopiuje własny plik wykonywalny ({0}×), np. {1} — cecha robaka/replikatora", copies, sample)));
        }

        if (sc.FileInfector)
        {
            string ownDir = SafeDir(proc.ImagePath);
            var infected = changes
                .Where(c => c.Kind == ChangeKind.FileModify && IsExecutableFile(c.Location)
                            && !PathEq(c.Location, proc.ImagePath)
                            && !PathEq(SafeDir(c.Location), ownDir))
                .Select(c => c.Location)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (infected.Count >= 2)
                alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "FileInfector",
                    Loc.F("Proces zapisuje kod do {0} cudzych plików wykonywalnych (infekcja PE): {1}", infected.Count, infected[0])));
            else if (infected.Count == 1)
                alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.Medium, "FileInfector",
                    Loc.F("Proces zmodyfikował cudzy plik wykonywalny: {0}", infected[0])));
        }

        if (sc.MassPeCreation && createdPe.Count >= 3 && !HasTrustedPublisher(proc.ImagePath))
        {
            var sev = createdPe.Count >= 8 ? BehaviorSeverity.High : BehaviorSeverity.Medium;
            alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, sev, "MassPeCreation",
                Loc.F("Proces utworzył {0} nowych plików wykonywalnych", createdPe.Count)));
        }
    }

    private static void ComputeBehaviorScore(ProcessInfo proc, ShieldConfig cfg, List<BehaviorAlert> alerts)
    {
        var sc = cfg.BehaviorScoring;
        if (!sc.Enabled) return;
        if (IsTrustedProcess(proc)) return;
        if (alerts.Count == 0) return;

        int score = alerts.Sum(a => a.Severity switch
        {
            BehaviorSeverity.High   => 6,
            BehaviorSeverity.Medium => 3,
            _                       => 1,
        });
        if (score < sc.Threshold) return;

        var cats = alerts.Select(a => a.Category).Distinct().Take(5);
        alerts.Add(new BehaviorAlert(proc.Pid, proc.Name, BehaviorSeverity.High, "Malicious",
            Loc.F("Proaktywna ocena zachowania: wynik {0} (próg {1}); ", score, sc.Threshold) +
            Loc.F("sygnały: {0}", string.Join(", ", cats))));
    }

    private static bool IsExecutableFile(string path)
    {
        var ext = Path.GetExtension(path);
        return !string.IsNullOrEmpty(ext) && ExecutableExtensions.Contains(ext);
    }

    private static bool PathEq(string a, string b)
        => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static string SafeDir(string path)
    {
        try { return Path.GetDirectoryName(path) ?? ""; } catch { return ""; }
    }

    private static long TryFileSize(string path)
    {
        try { var fi = new FileInfo(path); return fi.Exists ? fi.Length : -1; } catch { return -1; }
    }

    private static byte[]? TryHash(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length <= 0 || fi.Length > 96L * 1024 * 1024) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var sha = System.Security.Cryptography.SHA256.Create();
            return sha.ComputeHash(fs);
        }
        catch { return null; }
    }

    private static bool HasTrustedPublisher(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        try { return Malward.Engine.Util.SystemFileCheck.HasValidTrustedSignature(imagePath); }
        catch { return false; }
    }

    private static bool IsTrustedProcess(ProcessInfo proc)
    {
        if (!IsTrustedPath(proc.ImagePath)) return false;
        if (string.IsNullOrEmpty(proc.CommandLine)) return true;

        string host;
        try { host = Path.GetFileName(proc.ImagePath ?? ""); } catch { return true; }
        if (host.Length == 0 || !LolBin.IsInterpreter(host)) return true;

        foreach (var target in LolBin.ExtractTargets(host, proc.CommandLine))
            if (!IsTrustedPath(target)) return false;
        return true;
    }

    private static bool IsTrustedPath(string imagePath)
    {
        if (string.IsNullOrEmpty(imagePath) || !imagePath.Contains('\\')) return false;
        string l = imagePath.ToLowerInvariant();
        return l.Contains(@"\windows\system32\")
            || l.Contains(@"\windows\syswow64\")
            || l.Contains(@"\windows\winsxs\")
            || l.Contains(@"\program files\")
            || l.Contains(@"\program files (x86)\")

            || l.Contains(@"\windows defender\");
    }

    private static bool IsUserDocApp(string name)
    {
        string n = StripExe(name);
        return n is "winword" or "excel" or "powerpnt" or "outlook"
                 or "acrord32" or "acrobat" or "wmplayer";
    }

    private static string StripExe(string name)
        => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;

    private static string Trunc(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";
}
