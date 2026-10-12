using Microsoft.Win32;

namespace Malward.ResidentShield.Hips;

public sealed class HipsRegistryWatcher : IDisposable
{
    private readonly HipsConfig _hips;
    private readonly ActivityReporter _activity;
    private readonly Notifier _notify;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    private sealed record Watch(
        string RuleId, RegistryHive Hive, string Path,
        string[]? Values = null, bool Subkeys = false, string[]? SubValues = null,
        string? SubKeyPath = null, bool Recurse = false, bool Wow32 = false,
        bool ReportRemoval = false);

    private static readonly Watch[] Watches = LoadWatches();

    private static Watch[] LoadWatches()
    {
        var wynik = new List<Watch>();
        string[] linie;
        try { linie = Malward.Engine.Data.SignatureStore.List("hips_registry_watches"); }
        catch (Exception ex)
        {
            Log.Error("HIPS", "Cannot read registry watch areas from the signature store: " +
                              ex.Message + ". Registry monitoring is NOT RUNNING. " +
                              "Regenerate sigdata.vdeb (malscan make-sigdata).");
            return Array.Empty<Watch>();
        }

        if (linie.Length == 0)
        {
            Log.Error("HIPS", "Signature store contains no registry watch areas (hips_registry_watches). " +
                              "Registry monitoring is NOT RUNNING. Regenerate sigdata.vdeb.");
            return Array.Empty<Watch>();
        }

        int zle = 0;
        foreach (var linia in linie)
        {
            var p = linia.Split('\u001F');
            if (p.Length != 7 || p[0].Length == 0 || p[2].Length == 0) { zle++; continue; }
            if (!Enum.TryParse<RegistryHive>(p[1], out var hive)) { zle++; continue; }

            var flagi = p[6];
            wynik.Add(new Watch(
                RuleId:        p[0],
                Hive:          hive,
                Path:          p[2],
                Values:        p[3] == "*" ? null : p[3].Split('|', StringSplitOptions.RemoveEmptyEntries),
                Subkeys:       flagi.Contains('s'),
                SubValues:     p[4] == "*" ? null : p[4].Split('|', StringSplitOptions.RemoveEmptyEntries),
                SubKeyPath:    p[5].Length == 0 ? null : p[5],
                Recurse:       flagi.Contains('r'),
                Wow32:         flagi.Contains('w'),
                ReportRemoval: flagi.Contains('d')));
        }

        if (zle > 0)
            Log.Warn("HIPS", $"Skipped {zle} unreadable registry watch areas in the signature store.");
        return wynik.ToArray();
    }

    public static IEnumerable<string> Detectors =>
        Watches.Select(w => HipsRules.ById(w.RuleId)?.Detector ?? "")
               .Where(d => d.Length > 0)
               .Distinct(StringComparer.OrdinalIgnoreCase);

    private sealed record Snap(string Value, RegistryValueKind Kind, string Prefix);

    private readonly Dictionary<string, Snap> _snapshot = new(StringComparer.OrdinalIgnoreCase);
    private bool _primed;

    private const int MaxReportsPerPass = 25;
    private int _reportsThisPass;
    private int _deferredThisPass;

    private const string MultiSep = "";

    public HipsRegistryWatcher(HipsConfig hips, ActivityReporter activity, Notifier notify)
    { _hips = hips; _activity = activity; _notify = notify; }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loop = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try { Scan(); }
                catch (Exception ex) { Log.Debug("HIPS-Reg", ex.Message); }
                try { await Task.Delay(TimeSpan.FromSeconds(6), ct); } catch { break; }
            }
        }, ct);
        Log.Info("HIPS", $"Registry monitoring started ({Watches.Length} areas).");
    }

    public void Scan()
    {
        var current = new Dictionary<string, Snap>(StringComparer.OrdinalIgnoreCase);
        var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _reportsThisPass = 0;
        _deferredThisPass = 0;

        foreach (var w in Watches)
        {
            foreach (var (token, root) in Roots(w))
            {
                using (root)
                {
                    string prefix = $"{w.RuleId}|{token}|{(w.Wow32 ? "32" : "64")}|{w.Path}";

                    if (Collect(w, prefix, root, current)) covered.Add(prefix);
                }
            }
        }

        if (!_primed)
        {
            foreach (var kv in current) _snapshot[kv.Key] = kv.Value;
            _primed = true;
            Log.Info("HIPS", $"Registry: baseline snapshot recorded ({_snapshot.Count} items).");
            return;
        }

        foreach (var kv in current)
        {
            bool known = _snapshot.TryGetValue(kv.Key, out var old);
            if (known && old!.Value == kv.Value.Value && old.Kind == kv.Value.Kind) continue;
            var after = Report(kv.Key, kv.Value, known ? old : null,
                               known ? Change.Modified : Change.Added);

            if (after.Defer) continue;

            if (after.State == null) _snapshot.Remove(kv.Key);
            else _snapshot[kv.Key] = after.State;
        }

        foreach (var key in _snapshot.Keys.Where(k => !current.ContainsKey(k)).ToList())
        {
            var old = _snapshot[key];
            if (!covered.Contains(old.Prefix)) continue;
            if (old.Kind != RegistryValueKind.Unknown && !WantsRemovalReport(key))
            {
                _snapshot.Remove(key);
                continue;
            }
            var after = Report(key, null, old, Change.Removed);
            if (after.Defer) continue;
            if (after.State != null) _snapshot[key] = after.State;
            else _snapshot.Remove(key);
        }

        if (_deferredThisPass > 0)
            Log.Alert("HIPS", $"Deferred {_deferredThisPass} registry changes to the next pass "
                            + "— none of them was accepted as the new baseline.");
    }

    private enum Change { Added, Modified, Removed }

    private readonly record struct Handled(bool Defer, Snap? State)
    {
        public static Handled Later() => new(true, null);
        public static Handled With(Snap? state) => new(false, state);
    }

    private static bool WantsRemovalReport(string snapKey)
    {
        var ruleId = snapKey.Split('|')[0];
        foreach (var w in Watches)
            if (w.ReportRemoval && w.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static IEnumerable<(string Token, RegistryKey Root)> Roots(Watch w)
    {
        var view = w.Wow32 ? RegistryView.Registry32
                 : (Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);

        if (w.Hive == RegistryHive.LocalMachine)
        {
            RegistryKey? k = null;
            try { k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view); } catch { }
            if (k != null) yield return ("HKLM", k);
            yield break;
        }

        RegistryKey? own = null;
        try { own = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view); } catch { }
        if (own != null) yield return ("HKCU", own);

        string ownSid = OwnSid();

        RegistryKey? users = null;
        try { users = RegistryKey.OpenBaseKey(RegistryHive.Users, view); } catch { }
        if (users == null) yield break;
        string[] sids;
        try { sids = users.GetSubKeyNames(); } catch { users.Dispose(); yield break; }
        foreach (var sid in sids)
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(sid, ownSid, StringComparison.OrdinalIgnoreCase)) continue;
            RegistryKey? uk = null;
            try { uk = users.OpenSubKey(sid); } catch { }
            if (uk != null) yield return ($"HKU:{sid}", uk);
        }
        users.Dispose();
    }

    private static string OwnSid()
    {
        try { return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? ""; }
        catch { return ""; }
    }

    private static bool Collect(Watch w, string prefix, RegistryKey root, Dictionary<string, Snap> into)
    {
        RegistryKey? key;
        try { key = root.OpenSubKey(w.Path); }
        catch { return false; }

        if (key == null) return true;

        using (key)
        {
            try
            {
                if (w.Recurse) { WalkValues(key, prefix, w.Path, into, prefix, 0); return true; }

                if (w.Subkeys)
                {
                    foreach (var sub in key.GetSubKeyNames())
                    {
                        into[$"{prefix}\\{sub}"] = new Snap("<subkey>", RegistryValueKind.Unknown, prefix);
                        if (w.SubValues == null) continue;

                        var innerPath = w.SubKeyPath == null ? sub : $@"{sub}\{w.SubKeyPath}";
                        RegistryKey? inner = null;
                        try { inner = key.OpenSubKey(innerPath); } catch { }
                        if (inner == null) continue;
                        using (inner)
                            foreach (var n in w.SubValues)
                                Store(inner, n, $"{prefix}\\{innerPath}", prefix, into);
                    }
                    return true;
                }

                var names = w.Values ?? key.GetValueNames();
                foreach (var n in names) Store(key, n, prefix, prefix, into);
                return true;
            }
            catch { return false; }
        }
    }

    private static void Store(RegistryKey key, string name, string pathPart, string prefix,
                              Dictionary<string, Snap> into)
    {
        object? v;
        RegistryValueKind kind;
        try
        {
            v = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (v == null) return;
            kind = key.GetValueKind(name);
        }
        catch { return; }
        into[$"{pathPart}|{name}"] = new Snap(Serialize(v), kind, prefix);
    }

    private static void WalkValues(RegistryKey key, string prefix, string path,
                                   Dictionary<string, Snap> into, string owner, int depth)
    {
        if (depth > 3 || into.Count > 20000) return;
        foreach (var n in key.GetValueNames()) Store(key, n, prefix, owner, into);
        foreach (var sub in key.GetSubKeyNames())
        {
            RegistryKey? k = null;
            try { k = key.OpenSubKey(sub); } catch { }
            if (k == null) continue;
            using (k) WalkValues(k, $"{prefix}\\{sub}", $@"{path}\{sub}", into, owner, depth + 1);
        }
    }

    private static string Serialize(object v) => v switch
    {
        string[] arr => string.Join(MultiSep, arr),
        byte[] bin   => Convert.ToHexString(bin),
        _            => v.ToString() ?? "",
    };

    private static object? Deserialize(Snap snap) => snap.Kind switch
    {
        RegistryValueKind.DWord        => int.TryParse(snap.Value, out var i) ? i
                                          : (uint.TryParse(snap.Value, out var u) ? unchecked((int)u) : null),
        RegistryValueKind.QWord        => long.TryParse(snap.Value, out var l) ? l : null,
        RegistryValueKind.MultiString  => snap.Value.Split(MultiSep, StringSplitOptions.None),
        RegistryValueKind.Binary       => HexOrNull(snap.Value),
        RegistryValueKind.String       => snap.Value,
        RegistryValueKind.ExpandString => snap.Value,
        _ => null,
    };

    private static byte[]? HexOrNull(string s)
    {
        try { return Convert.FromHexString(s); } catch { return null; }
    }

    private enum FirewallAuthor
    {
        Unknown,

        Own,

        FirewallService,

        Other,
    }

    private static FirewallAuthor FirewallPolicyAuthor()
    {
        var who = RegistryWriters.Recent(RegistryWriters.FirewallPolicy);
        if (who != null)
        {
            var image = who.Value.Image;
            if (SystemGuard.IsOwnComponent(image) || HipsSelfGuard.IsOwnProcessTree(who.Value.Pid))
                return FirewallAuthor.Own;
            if (IsServiceHost(image)) return FirewallAuthor.FirewallService;
            return FirewallAuthor.Other;
        }

        return OwnFirewallChangeAnnounced() ? FirewallAuthor.Own : FirewallAuthor.Unknown;
    }

    private static bool IsServiceHost(string? image)
    {
        if (string.IsNullOrEmpty(image)) return false;
        var name = Path.GetFileName(image);
        if (!name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) return false;

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        return image.StartsWith(system32, StringComparison.OrdinalIgnoreCase);
    }

    private static readonly TimeSpan FirewallIntentWindow = TimeSpan.FromSeconds(60);

    private static bool OwnFirewallChangeAnnounced()
    {
        try
        {
            var marker = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data", "fw-intent");
            if (!File.Exists(marker)) return false;
            var text = File.ReadAllText(marker).Trim();
            if (!DateTime.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
                                   System.Globalization.DateTimeStyles.RoundtripKind, out var when))
                return false;
            return DateTime.UtcNow - when.ToUniversalTime() <= FirewallIntentWindow;
        }
        catch { return false; }
    }

    private Handled Report(string snapKey, Snap? now, Snap? old, Change change)
    {
        Handled Unchanged() => Handled.With(change == Change.Removed ? null : now);

        var ruleId = snapKey.Split('|')[0];
        var rule = HipsRules.ById(ruleId);
        if (rule == null) return Unchanged();

        var (on, mode) = _hips.StateOf(ruleId);
        if (!_hips.Enabled || !on) return Unchanged();

        if (ruleId.Equals("reg.dns", StringComparison.OrdinalIgnoreCase))
        {
            if (ValueNameOf(snapKey).Equals("DhcpNameServer", StringComparison.OrdinalIgnoreCase))
            {
                Log.Debug("HIPS-Reg", $"DHCP-assigned DNS changed, not reported: {Readable(snapKey)}");
                return Unchanged();
            }

            if (mode == HipsRules.Mode.Block
                && change != Change.Removed
                && ValueNameOf(snapKey).Equals("NameServer", StringComparison.OrdinalIgnoreCase)
                && (LooksLikeDnsServerList(now?.Value) || string.IsNullOrWhiteSpace(now?.Value))
                && !ShieldConfig.PeekNetworkShieldEnabled())
            {
                Log.Info("HIPS", $"Network shield is off — DNS change at {Readable(snapKey)} is logged, not reverted.");
                mode = HipsRules.Mode.Log;
            }
        }

        if (ruleId.Equals("reg.firewall_policy", StringComparison.OrdinalIgnoreCase)
            && mode == HipsRules.Mode.Block)
        {
            switch (FirewallPolicyAuthor())
            {
                case FirewallAuthor.Own:
                    Log.Debug("HIPS-Reg", $"Firewall policy changed by Malward itself, skipping: {Readable(snapKey)}");
                    return Unchanged();

                case FirewallAuthor.FirewallService:

                    Log.Info("HIPS", $"Firewall policy changed through the Windows firewall service "
                                   + $"at {Readable(snapKey)} — recorded, not reverted.");
                    mode = HipsRules.Mode.Log;
                    break;
            }
        }

        string? extra;
        if (change == Change.Removed) extra = "wpis usunięty";
        else if (!Worth(ruleId, snapKey, now?.Value ?? "", out extra)) return Unchanged();

        if (HipsSelfGuard.IsOwnRegistryFootprint(ruleId, Readable(snapKey), now?.Value, old?.Value))
        {
            Log.Debug("HIPS-Reg", $"Malward's own footprint, skipping: {Readable(snapKey)}");
            return Unchanged();
        }

        var excepted = PathFromCommand(now?.Value ?? "");
        if (_hips.IsExcepted(ruleId, excepted) || _hips.IsExcepted(ruleId, Readable(snapKey)))
        {
            Log.Debug("HIPS-Reg", $"User exception for {ruleId}: {excepted ?? Readable(snapKey)}");
            return Unchanged();
        }

        if (_reportsThisPass >= MaxReportsPerPass)
        {
            _deferredThisPass++;
            if (_reportsThisPass == MaxReportsPerPass)
            {
                _reportsThisPass++;
                Log.Alert("HIPS", "Very many registry changes in a single pass — the rest is "
                                + "deferred to the next cycle, not accepted.");
            }

            return Handled.Later();
        }
        _reportsThisPass++;

        string where = Readable(snapKey);
        string detail = change switch
        {
            Change.Added   => $"Nowy wpis: {where} = {Trim(now!.Value)}",
            Change.Removed => $"Usunięto wpis: {where} (było: {Trim(old?.Value ?? "")})",
            _              => $"Zmieniono: {where}: {Trim(old?.Value ?? "")} -> {Trim(now!.Value)}",
        };
        if (extra != null) detail += $" ({extra})";

        string action = mode == HipsRules.Mode.Block ? "block" : mode == HipsRules.Mode.Log ? "log" : "ask";

        if (mode == HipsRules.Mode.Block)
        {
            var after = Revert(snapKey, old, change);
            bool undone = after.Ok;
            _activity.ReportHips(ruleId, rule.Name, "rejestr", where, detail, action,
                                 undone ? BuildUndo(snapKey, now, change) : null);
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — {(undone ? "reverted" : "FAILED to revert")}");
            _notify.Threat(undone ? "Registry change reverted" : "Failed to revert registry change",
                           where, rule.Name, AlertSeverity.High);
            if (undone) return Handled.With(after.State);
            return Unchanged();
        }

        _activity.ReportHips(ruleId, rule.Name, "rejestr", where, detail, action,
                             fix: mode == HipsRules.Mode.Ask ? BuildFix(snapKey, old, change) : null);

        if (mode == HipsRules.Mode.Ask)
        {
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — reported (mode: ask, awaiting user decision)");
            _notify.Threat("Registry change detected", where, rule.Name, AlertSeverity.Medium);
        }
        else Log.Info("HIPS", $"[{rule.Name}] {detail}");

        return Unchanged();
    }

    private static bool Worth(string ruleId, string snapKey, string newValue, out string? extra)
    {
        extra = null;
        try
        {
            switch (ruleId)
            {
                case "reg.run":
                case "reg.winlogon":
                case "reg.file_assoc":
                case "reg.script_host":
                case "reg.active_setup":
                case "reg.dll_loadpoints":
                case "reg.rdp":
                {
                    if (IsHarmlessToggle(ValueNameOf(snapKey))) return false;

                    var target = PathFromCommand(newValue);

                    if (target == null && !LooksLikePath(newValue)) return true;
                    extra = HipsTrust.SuspectReason(target);
                    return extra != null;
                }
                case "reg.ifeo":
                {
                    var hit = IfeoPayload(snapKey);
                    if (hit == null) return false;
                    extra = hit;
                    return true;
                }
                case "reg.services":
                case "reg.service_config":
                {
                    var name = ServiceNameOf(snapKey);
                    if (name == null) return false;
                    var img = ServiceImagePath(name);
                    if (img == null) return false;

                    if (SystemGuard.IsOwnComponent(img)) return false;
                    extra = HipsTrust.SuspectReason(img);
                    return extra != null;
                }
                case "reg.com_hijack":
                {
                    var clsid = snapKey[(snapKey.LastIndexOf('\\') + 1)..];
                    var user = ComServerUser(snapKey, clsid);
                    if (user == null) return false;
                    var machine = ComServerMachine(clsid);
                    if (machine == null) return false;
                    if (string.Equals(Path.GetFileName(user), Path.GetFileName(machine),
                                      StringComparison.OrdinalIgnoreCase)) return false;
                    extra = $"przesłania systemowy {machine} przez {user}";
                    return true;
                }
                case "reg.shell_folders":
                {
                    var cel = ExpandForSnapshot(snapKey, newValue);
                    if (cel == null) return true;
                    var profil = ProfileDirOf(snapKey);
                    if (profil == null) return true;
                    if (!cel.StartsWith(profil, StringComparison.OrdinalIgnoreCase))
                    {
                        extra = $"folder powłoki przekierowany poza profil użytkownika: {cel}";
                        return true;
                    }
                    if (IsVolatileArea(cel))
                    {
                        extra = $"folder powłoki przekierowany w miejsce tymczasowe: {cel}";
                        return true;
                    }
                    return false;
                }

                case "reg.session_manager":
                {
                    if (!snapKey.EndsWith("|PendingFileRenameOperations", StringComparison.OrdinalIgnoreCase))
                        return true;
                    var zly = SuspectRenameTarget(newValue);
                    if (zly == null) return false;
                    extra = zly;
                    return true;
                }

                case "reg.aedebug":
                {
                    var target = PathFromCommand(newValue) ?? PathFromValueName(snapKey);
                    if (target == null) return true;
                    extra = HipsTrust.SuspectReason(target);
                    return extra != null;
                }

                case "reg.proxy":
                {
                    var nazwa = ValueNameOf(snapKey);
                    if (nazwa.Equals("ProxyEnable", StringComparison.OrdinalIgnoreCase))
                        return !(newValue.Trim() is "0" or "0x0" or "");
                    return !string.IsNullOrWhiteSpace(newValue);
                }

                case "reg.environment":
                {
                    if (!ValueNameOf(snapKey).Equals("Path", StringComparison.OrdinalIgnoreCase))
                        return true;
                    foreach (var czesc in newValue.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        string c;
                        try { c = Environment.ExpandEnvironmentVariables(czesc.Trim().Trim('"')); }
                        catch { continue; }
                        if (IsVolatileArea(c))
                        {
                            extra = $"do ścieżki wyszukiwania dopisano katalog tymczasowy: {c}";
                            return true;
                        }
                    }
                    return false;
                }

                default: return true;
            }
        }
        catch { return true; }
    }

    private static bool IsHarmlessToggle(string valueName) =>
        valueName.Equals("ScreenSaveActive", StringComparison.OrdinalIgnoreCase)
        || valueName.Equals("ScreenSaverIsSecure", StringComparison.OrdinalIgnoreCase)
        || valueName.Equals("ScreenSaveTimeOut", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeDnsServerList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var parts = value.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0 || parts.Length > 8) return false;
        foreach (var p in parts)
        {
            if (!System.Net.IPAddress.TryParse(p, out var ip)) return false;
            if (System.Net.IPAddress.IsLoopback(ip)) return false;
            if (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any)) return false;
        }
        return true;
    }

    private static string ValueNameOf(string snapKey)
    {
        int i = snapKey.LastIndexOf('|');
        return i < 0 ? "" : snapKey[(i + 1)..];
    }

    private static string? PathFromValueName(string snapKey)
    {
        var n = ValueNameOf(snapKey);
        return n.Contains('\\') && n.Contains(':') ? n : null;
    }

    private static string? ProfileDirOf(string snapKey)
    {
        try
        {
            int i = snapKey.IndexOf("S-1-5-21-", StringComparison.OrdinalIgnoreCase);
            if (i < 0) return null;
            int end = snapKey.IndexOf('\\', i);
            var sid = end < 0 ? snapKey[i..] : snapKey[i..end];
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
            var p = k?.GetValue("ProfileImagePath") as string;
            return string.IsNullOrEmpty(p)
                ? null
                : Environment.ExpandEnvironmentVariables(p).TrimEnd('\\');
        }
        catch { return null; }
    }

    private static string? ExpandForSnapshot(string snapKey, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim().Trim('"');
        var profil = ProfileDirOf(snapKey);
        if (profil != null)
            v = v.Replace("%USERPROFILE%", profil, StringComparison.OrdinalIgnoreCase);
        try { v = Environment.ExpandEnvironmentVariables(v); } catch { }
        return v.TrimEnd('\\');
    }

    private static bool IsVolatileArea(string path)
    {
        var p = path.Replace('/', '\\');
        string[] m = { @"\temp\", @"\tmp\", @"\downloads\", @"\pobrane\", @"\public\",
                       "$recycle.bin", @"\windows\temp" };
        return m.Any(x => p.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    private static string? SuspectRenameTarget(string value)
    {
        var linie = value.Replace(MultiSep, "\n")
                         .Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var linia in linie)
        {
            var raw = linia.Trim();
            if (raw.Length == 0) continue;
            bool czyCel = raw.StartsWith('!');
            var p = raw.TrimStart('!').Replace(@"\??\", "").Trim();
            if (p.Length < 4 || !p.Contains(':')) continue;

            if (czyCel && IsSystemBinary(p))
                return $"po restarcie miał zostać podmieniony plik systemowy: {p}";

            if (!czyCel && IsExecutablePath(p) && File.Exists(p) && HipsTrust.SuspectReason(p) != null)
                return $"po restarcie miał zostać podstawiony niezaufany plik: {p}";
        }
        return null;
    }

    private static bool IsSystemBinary(string p)
    {
        var l = p.ToLowerInvariant().Replace('/', '\\');
        return (l.Contains(@"\windows\system32\") || l.Contains(@"\windows\syswow64\")
             || l.Contains(@"\system32\drivers\")) && IsExecutablePath(l);
    }

    private static bool IsExecutablePath(string p)
    {
        var e = Path.GetExtension(p).ToLowerInvariant();
        return e is ".exe" or ".dll" or ".sys" or ".ocx" or ".cpl" or ".drv" or ".scr";
    }

    private static bool LooksLikePath(string v) =>
        v.Contains('\\') || v.Contains(".exe", StringComparison.OrdinalIgnoreCase)
                         || v.Contains(".dll", StringComparison.OrdinalIgnoreCase);

    private static string? ServiceNameOf(string snapKey)
    {
        const string marker = @"CurrentControlSet\Services\";
        int i = snapKey.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;
        var rest = snapKey[(i + marker.Length)..];
        int cut = rest.IndexOfAny(new[] { '\\', '|' });
        var name = cut < 0 ? rest : rest[..cut];
        return name.Length == 0 ? null : name;
    }

    private static string? ServiceImagePath(string serviceName)
    {
        using var k = Registry.LocalMachine.OpenSubKey($@"System\CurrentControlSet\Services\{serviceName}");
        if (k == null) return null;
        var img = PathFromCommand(k.GetValue("ImagePath") as string);
        if (img != null) return img;
        using var p = k.OpenSubKey("Parameters");
        return PathFromCommand(p?.GetValue("ServiceDll") as string);
    }

    private static string? PathFromCommand(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = Environment.ExpandEnvironmentVariables(raw.Trim());
        if (s.StartsWith(@"\??\")) s = s[4..];
        if (s.StartsWith("\"")) { int e = s.IndexOf('"', 1); s = e > 0 ? s[1..e] : s[1..]; }
        else
        {
            int sp = s.IndexOf(" -", StringComparison.Ordinal);
            int sl = s.IndexOf(" /", StringComparison.Ordinal);
            if (sp < 0 || (sl >= 0 && sl < sp)) sp = sl;
            if (sp > 0) s = s[..sp];
        }
        s = s.Trim().Trim('"');
        if (s.Length == 0) return null;
        if (!Path.IsPathRooted(s))
        {
            var ext = Path.HasExtension(s) ? "" : ".exe";
            foreach (var dir in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.System),
                         Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
                         Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                     })
            {
                if (string.IsNullOrEmpty(dir)) continue;
                var kandydat = Path.Combine(dir, s + ext);
                if (File.Exists(kandydat)) return kandydat;
            }
            s = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), s);
        }
        return File.Exists(s) ? s : null;
    }

    private static string? IfeoPayload(string snapKey)
    {
        var parts = snapKey.Split('|');
        if (parts.Length < 4) return null;
        var view = parts[2] == "32" ? RegistryView.Registry32
                 : (Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
        using var k = hklm.OpenSubKey(parts[3]);
        if (k == null) return null;

        foreach (var name in Malward.Engine.Data.SignatureStore.List("ifeo_debug_values"))
        {
            var v = k.GetValue(name) as string;
            if (!string.IsNullOrWhiteSpace(v)) return $"{name} = {v}";
        }

        foreach (var sub in k.GetSubKeyNames())
        {
            using var s2 = k.OpenSubKey(sub);
            var v = s2?.GetValue("MonitorProcess") as string;
            if (!string.IsNullOrWhiteSpace(v)) return $"MonitorProcess = {v}";
        }
        return null;
    }

    private static string? ComServerUser(string snapKey, string clsid)
    {
        var parts = snapKey.Split('|');
        if (parts.Length < 4) return null;
        var token = parts[1];
        RegistryKey? root = null;
        bool ownRoot = false;
        try
        {
            if (token.StartsWith("HKU:")) { root = Registry.Users.OpenSubKey(token[4..]); ownRoot = true; }
            else root = Registry.CurrentUser;
            if (root == null) return null;
            foreach (var kind in new[] { "InprocServer32", "LocalServer32" })
            {
                using var k = root.OpenSubKey($@"Software\Classes\CLSID\{clsid}\{kind}");
                var v = k?.GetValue("") as string;
                if (!string.IsNullOrWhiteSpace(v)) return Environment.ExpandEnvironmentVariables(v.Trim('"'));
            }
            return null;
        }
        finally { if (ownRoot) root?.Dispose(); }
    }

    private static string? ComServerMachine(string clsid)
    {
        foreach (var kind in new[] { "InprocServer32", "LocalServer32" })
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"Software\Classes\CLSID\{clsid}\{kind}");
            var v = k?.GetValue("") as string;
            if (!string.IsNullOrWhiteSpace(v)) return Environment.ExpandEnvironmentVariables(v.Trim('"'));
        }
        return null;
    }

    private readonly record struct Undo(bool Ok, Snap? State);

    private static System.Text.Json.Nodes.JsonObject? BuildUndo(string snapKey, Snap? now, Change change)
    {
        var parts = snapKey.Split('|');
        if (parts.Length < 5) return null;
        var o = new System.Text.Json.Nodes.JsonObject
        {
            ["kind"] = "registry",
            ["loc"] = snapKey,
            ["where"] = Readable(snapKey),
        };
        if (change == Change.Removed)
        {
            o["op"] = "delete";
            return o;
        }
        if (now == null) return null;
        o["op"] = "write";
        o["value"] = now.Value;
        o["vkind"] = now.Kind.ToString();
        return o;
    }

    private static System.Text.Json.Nodes.JsonObject? BuildFix(string snapKey, Snap? old, Change change)
    {
        var parts = snapKey.Split('|');
        if (parts.Length < 5) return null;
        var o = new System.Text.Json.Nodes.JsonObject
        {
            ["kind"] = "registry",
            ["loc"] = snapKey,
            ["where"] = Readable(snapKey),
        };
        if (change == Change.Added)
        {
            o["op"] = "delete";
            return o;
        }
        if (old == null) return null;
        o["op"] = "write";
        o["value"] = old.Value;
        o["vkind"] = old.Kind.ToString();
        return o;
    }

    public static bool ApplyUndo(string loc, string op, string? value, string? vkind)
    {
        try
        {
            var parts = loc.Split('|');
            if (parts.Length < 5) return false;
            var token = parts[1];
            var view = parts[2] == "32" ? RegistryView.Registry32
                     : (Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            var pathPart = parts[3];
            var valueName = parts[4];

            RegistryKey? root;
            if (token == "HKLM") root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            else if (token == "HKCU") root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
            else
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
                root = users.OpenSubKey(token[4..], writable: true);
            }
            if (root == null) return false;

            using (root)
            {
                if (string.Equals(op, "delete", StringComparison.OrdinalIgnoreCase))
                {
                    using var key = root.OpenSubKey(pathPart, writable: true);
                    if (key == null) return false;
                    key.DeleteValue(valueName, throwOnMissingValue: false);

                    Log.Alert("HIPS", $"Deleted at the user's request: {Readable(loc)}");
                    return true;
                }

                if (value == null || vkind == null) return false;
                if (!Enum.TryParse<RegistryValueKind>(vkind, out var kind)) return false;
                var typed = Deserialize(new Snap(value, kind, ""));
                if (typed == null) return false;
                using var wk = root.CreateSubKey(pathPart, writable: true);
                if (wk == null) return false;
                wk.SetValue(valueName, typed, kind);
                Log.Alert("HIPS", $"Written at the user's request: {Readable(loc)}");
                return true;
            }
        }
        catch (Exception ex)
        {
            Log.Warn("HIPS-Reg", $"Failed to undo the repair: {ex.Message}");
            return false;
        }
    }

    private static Undo Revert(string snapKey, Snap? old, Change change)
    {
        try
        {
            var parts = snapKey.Split('|');
            if (parts.Length < 4) return new Undo(false, null);
            var token = parts[1];
            var view = parts[2] == "32" ? RegistryView.Registry32
                     : (Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            var pathPart = parts[3];
            string? valueName = parts.Length > 4 ? parts[4] : null;

            RegistryKey? root;
            if (token == "HKLM") root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            else if (token == "HKCU") root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view);
            else
            {
                using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
                root = users.OpenSubKey(token[4..], writable: true);
            }
            if (root == null) return new Undo(false, null);

            using (root)
            {
                if (valueName == null)
                {
                    if (change != Change.Added)
                    {
                        Log.Warn("HIPS-Reg", $"A deleted subkey cannot be recreated automatically: {Readable(snapKey)}");
                        return new Undo(false, null);
                    }
                    int slash = pathPart.LastIndexOf('\\');
                    if (slash <= 0) return new Undo(false, null);
                    using var pk = root.OpenSubKey(pathPart[..slash], writable: true);
                    if (pk == null) return new Undo(false, null);
                    pk.DeleteSubKeyTree(pathPart[(slash + 1)..], throwOnMissingSubKey: false);
                    return new Undo(true, null);
                }

                if (change == Change.Added)
                {
                    using var key = root.OpenSubKey(pathPart, writable: true);
                    if (key == null) return new Undo(false, null);
                    key.DeleteValue(valueName, throwOnMissingValue: false);
                    return new Undo(true, null);
                }

                if (old == null) return new Undo(false, null);
                var restored = Deserialize(old);
                if (restored == null)
                {
                    Log.Warn("HIPS-Reg", $"Unknown value type, not restored: {Readable(snapKey)} ({old.Kind})");
                    return new Undo(false, null);
                }
                using var wk = root.CreateSubKey(pathPart, writable: true);
                if (wk == null) return new Undo(false, null);
                wk.SetValue(valueName, restored, old.Kind);
                return new Undo(true, old);
            }
        }
        catch (Exception ex) { Log.Warn("HIPS-Reg", $"Revert failed: {ex.Message}"); return new Undo(false, null); }
    }

    private static string Readable(string snapKey)
    {
        var parts = snapKey.Split('|');
        if (parts.Length < 4) return snapKey;
        string hive = parts[1].StartsWith("HKU:") ? $@"HKU\{parts[1][4..]}" : parts[1];
        if (parts[2] == "32" && hive == "HKLM") hive = "HKLM32";
        return parts.Length > 4 ? $@"{hive}\{parts[3]}|{parts[4]}" : $@"{hive}\{parts[3]}";
    }

    private static string Trim(string s) => s.Length <= 120 ? s : s[..117] + "...";

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _loop?.Wait(2000); } catch { }
        _cts?.Dispose();
    }
}
