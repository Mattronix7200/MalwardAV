using System.Management;

namespace Malward.ResidentShield.Hips;

public sealed class HipsWmiWatcher : IDisposable
{
    private const string Ns = @"root\subscription";
    private const string RuleId = "reg.wmi_subscription";

    private readonly HipsConfig _hips;
    private readonly ActivityReporter _activity;
    private readonly Notifier _notify;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    private readonly Dictionary<string, string> _snapshot = new(StringComparer.OrdinalIgnoreCase);
    private bool _primed;

    public static IEnumerable<string> Detectors => new[] { "Wmi:subscription" };

    private static readonly string[] ExecutingConsumers =
        { "CommandLineEventConsumer", "ActiveScriptEventConsumer" };

    public HipsWmiWatcher(HipsConfig hips, ActivityReporter activity, Notifier notify)
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
                catch (ManagementException ex) { Log.Debug("HIPS-WMI", ex.Message); }
                catch (Exception ex) { Log.Debug("HIPS-WMI", ex.Message); }
                try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch { break; }
            }
        }, ct);
        Log.Info("HIPS", "WMI subscription watcher started.");
    }

    public void Scan()
    {
        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        bool ok = true;

        ok &= Collect("__EventFilter", current, o =>
            $"filtr: {Str(o, "Name")} | zapytanie: {Str(o, "Query")}");

        foreach (var cls in ExecutingConsumers)
            ok &= Collect(cls, current, o => cls == "CommandLineEventConsumer"
                ? $"konsument: {Str(o, "Name")} | polecenie: {Str(o, "CommandLineTemplate")} {Str(o, "ExecutablePath")}"
                : $"konsument: {Str(o, "Name")} | skrypt: {Trim(Str(o, "ScriptText"))}");

        ok &= Collect("__FilterToConsumerBinding", current, o =>
            $"powiązanie: {Str(o, "Filter")} -> {Str(o, "Consumer")}");

        if (!ok) return;

        if (!_primed)
        {
            foreach (var kv in current) _snapshot[kv.Key] = kv.Value;
            _primed = true;
            Log.Info("HIPS", $"WMI: baseline recorded ({_snapshot.Count} objects).");
            return;
        }

        foreach (var kv in current)
        {
            if (_snapshot.TryGetValue(kv.Key, out var old) && old == kv.Value) continue;
            _snapshot[kv.Key] = kv.Value;
            if (Report(kv.Key, kv.Value)) _snapshot.Remove(kv.Key);
        }
        foreach (var key in _snapshot.Keys.Where(k => !current.ContainsKey(k)).ToList())
            _snapshot.Remove(key);
    }

    private static bool Collect(string wmiClass, Dictionary<string, string> into,
                                Func<ManagementBaseObject, string> describe)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(Ns), new ObjectQuery($"SELECT * FROM {wmiClass}"));
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                using (o)
                {
                    var path = o["__RELPATH"]?.ToString() ?? Str(o, "Name");
                    if (string.IsNullOrEmpty(path)) continue;
                    into[$"{wmiClass}|{path}"] = describe(o);
                }
            }
            return true;
        }
        catch (Exception ex)
        {
            Log.Debug("HIPS-WMI", $"{wmiClass}: {ex.Message}");
            return false;
        }
    }

    private static string Str(ManagementBaseObject o, string prop)
    {
        try { return o[prop]?.ToString() ?? ""; } catch { return ""; }
    }

    private static string Trim(string s) => s.Length <= 200 ? s : s[..197] + "...";

    private bool Report(string key, string description)
    {
        var rule = HipsRules.ById(RuleId);
        if (rule == null) return false;
        var (on, mode) = _hips.StateOf(RuleId);
        if (!_hips.Enabled || !on) return false;

        var where = key.Replace('|', ' ');
        string detail = $"Nowa subskrypcja WMI — {description}";

        if (_hips.IsExcepted(RuleId, where) || _hips.IsExcepted(RuleId, description))
        {
            Log.Debug("HIPS-WMI", $"User exception: {where}");
            return false;
        }
        string action = mode == HipsRules.Mode.Block ? "block" : mode == HipsRules.Mode.Log ? "log" : "ask";
        _activity.ReportHips(RuleId, rule.Name, "WMI", where, detail, action);

        if (mode == HipsRules.Mode.Block)
        {
            bool undone = Remove(key);
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — {(undone ? "removed" : "FAILED to remove")}");
            _notify.Threat(undone ? "Permanent WMI subscription removed" : "Failed to remove WMI subscription",
                           where, rule.Name, AlertSeverity.High);
            return undone;
        }
        if (mode == HipsRules.Mode.Ask)
        {
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — reported (mode: ask, no automatic action)");
            _notify.Threat("Permanent WMI subscription detected", where, rule.Name, AlertSeverity.Medium);
        }
        else Log.Info("HIPS", detail);
        return false;
    }

    private static bool Remove(string key)
    {
        try
        {
            var relPath = key[(key.IndexOf('|') + 1)..];
            using var obj = new ManagementObject(new ManagementScope(Ns), new ManagementPath(relPath), null);
            obj.Delete();
            return true;
        }
        catch (Exception ex) { Log.Warn("HIPS-WMI", $"Removal failed: {ex.Message}"); return false; }
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _loop?.Wait(2000); } catch { }
        _cts?.Dispose();
    }
}
