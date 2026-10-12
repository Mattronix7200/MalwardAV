using System.Text.Json.Nodes;

namespace Malward.ResidentShield.Hips;

public sealed class HipsConfig
{
    private readonly string _path;
    private readonly object _lock = new();
    private Dictionary<string, (bool Enabled, HipsRules.Mode Mode)> _state = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, List<string>> _exceptions = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _loadedAt = DateTime.MinValue;

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "hips-rules.json");

    public HipsConfig(string? path = null) { _path = path ?? DefaultPath; Load(); }

    public bool Enabled { get; private set; }

    public string Tier { get; private set; } = "medium";

    public void Load()
    {
        lock (_lock)
        {
            var fresh = new Dictionary<string, (bool, HipsRules.Mode)>(StringComparer.OrdinalIgnoreCase);

            string? materializeTier = null;
            try
            {
                if (File.Exists(_path) && JsonNode.Parse(File.ReadAllText(_path)) is JsonObject o)
                {
                    bool hasRules = o["rules"] is JsonObject rr && rr.Count > 0;
                    string? tier = o["tier"]?.GetValue<string>();

                    if (!string.IsNullOrWhiteSpace(tier)) Tier = tier.Trim().ToLowerInvariant();
                    if (!hasRules && !string.IsNullOrWhiteSpace(tier))
                    {
                        Enabled = o["enabled"]?.GetValue<bool>() ?? true;
                        materializeTier = tier;
                    }
                    else
                    {
                        Enabled = o["enabled"]?.GetValue<bool>() ?? false;
                        if (o["rules"] is JsonObject rules)
                            foreach (var kv in rules)
                            {
                                if (kv.Value is not JsonObject r) continue;
                                bool on = r["on"]?.GetValue<bool>() ?? true;
                                var mode = ParseMode(r["mode"]?.GetValue<string>());
                                fresh[kv.Key] = (on, mode);
                            }
                    }
                }
                else if (!File.Exists(_path))
                {
                    Enabled = true;
                    materializeTier = "medium";
                }
            }
            catch {  }
            if (materializeTier != null) Tier = materializeTier.Trim().ToLowerInvariant();

            HipsTrust.TrustSignedInUserArea = Tier is "low" or "medium";
            if (materializeTier != null)
            {
                var ids = HipsRules.TierIds(materializeTier);
                foreach (var r in HipsRules.All) fresh[r.Id] = (ids.Contains(r.Id), r.Default);
            }

            var freshEx = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (File.Exists(_path) && JsonNode.Parse(File.ReadAllText(_path)) is JsonObject o2
                    && o2["exceptions"] is JsonObject ex)
                {
                    foreach (var kv in ex)
                    {
                        if (kv.Value is not JsonArray arr) continue;
                        var list = new List<string>();
                        foreach (var item in arr)
                        {
                            var v = item?.GetValue<string>();
                            if (!string.IsNullOrWhiteSpace(v)) list.Add(v.Trim());
                        }
                        if (list.Count > 0) freshEx[kv.Key] = list;
                    }
                }
            }
            catch { }

            _state = fresh;
            _exceptions = freshEx;
            _loadedAt = DateTime.UtcNow;

            if (materializeTier != null)
            {
                try
                {
                    WriteFile(Enabled, fresh, freshEx);
                    int on = fresh.Count(kv => kv.Value.Item1);
                    Log.Info("HIPS", $"Rules set according to tier \"{materializeTier}\": {on}/{fresh.Count} enabled.");
                }
                catch (Exception ex) { Log.Warn("HIPS", $"Failed to save tier rules: {ex.Message}"); }
                _loadedAt = DateTime.UtcNow;
            }
        }
    }

    public bool EnabledNow
    {
        get { RefreshIfStale(); return Enabled; }
    }

    private void RefreshIfStale()
    {
        if ((DateTime.UtcNow - _loadedAt) < TimeSpan.FromSeconds(5)) return;
        try
        {
            if (!File.Exists(_path)) { _loadedAt = DateTime.UtcNow; return; }
            if (File.GetLastWriteTimeUtc(_path) > _loadedAt.AddSeconds(-5)) Load();
            else _loadedAt = DateTime.UtcNow;
        }
        catch { _loadedAt = DateTime.UtcNow; }
    }

    private static HipsRules.Mode ParseMode(string? s) => s?.ToLowerInvariant() switch
    {
        "block" => HipsRules.Mode.Block,
        "log"   => HipsRules.Mode.Log,
        _       => HipsRules.Mode.Ask,
    };

    private static string ModeName(HipsRules.Mode m) => m switch
    {
        HipsRules.Mode.Block => "block",
        HipsRules.Mode.Log   => "log",
        _                    => "ask",
    };

    public (bool Enabled, HipsRules.Mode Mode) StateOf(string ruleId)
    {
        RefreshIfStale();
        lock (_lock)
        {
            if (_state.TryGetValue(ruleId, out var v)) return v;
            var rule = HipsRules.ById(ruleId);
            return (true, rule?.Default ?? HipsRules.Mode.Ask);
        }
    }

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Exceptions
    {
        get
        {
            RefreshIfStale();
            lock (_lock)
                return _exceptions.ToDictionary(
                    kv => kv.Key,
                    kv => (IReadOnlyList<string>)kv.Value.ToList(),
                    StringComparer.OrdinalIgnoreCase);
        }
    }

    public bool IsExcepted(string ruleId, string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        RefreshIfStale();
        lock (_lock)
        {
            return Matches("*", path) || Matches(ruleId, path);
        }

        bool Matches(string key, string subject)
        {
            if (!_exceptions.TryGetValue(key, out var list)) return false;
            foreach (var raw in list)
            {
                var pat = raw.Trim();
                if (pat.Length == 0) continue;
                if (pat.EndsWith('\\') || pat.EndsWith('/'))
                {
                    if (subject.StartsWith(pat, StringComparison.OrdinalIgnoreCase)) return true;
                }
                else if (pat.Contains('*') || pat.Contains('?'))
                {
                    var rx = "^" + System.Text.RegularExpressions.Regex.Escape(pat)
                                       .Replace("\\*", ".*").Replace("\\?", ".") + "$";
                    if (System.Text.RegularExpressions.Regex.IsMatch(subject, rx,
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return true;
                }
                else if (!pat.Contains('\\') && !pat.Contains('/'))
                {
                    if (string.Equals(Path.GetFileName(subject), pat, StringComparison.OrdinalIgnoreCase)) return true;
                }
                else if (string.Equals(subject, pat, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    public void AddException(string ruleId, string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        lock (_lock)
        {
            if (!_exceptions.TryGetValue(ruleId, out var list))
                _exceptions[ruleId] = list = new List<string>();
            if (list.Any(e => string.Equals(e, path, StringComparison.OrdinalIgnoreCase))) return;
            list.Add(path.Trim());
            WriteFile(Enabled, _state, _exceptions);
        }
    }

    public void RemoveException(string ruleId, string path)
    {
        lock (_lock)
        {
            if (!_exceptions.TryGetValue(ruleId, out var list)) return;
            list.RemoveAll(e => string.Equals(e, path, StringComparison.OrdinalIgnoreCase));
            if (list.Count == 0) _exceptions.Remove(ruleId);
            WriteFile(Enabled, _state, _exceptions);
        }
    }

    public (HipsRules.Rule Rule, HipsRules.Mode Mode)? Decide(string detector, string? path = null)
    {
        if (!Enabled) return null;
        foreach (var rule in HipsRules.ForDetector(detector))
        {
            var (on, mode) = StateOf(rule.Id);
            if (!on) continue;
            if (IsExcepted(rule.Id, path)) return null;
            return (rule, mode);
        }
        return null;
    }

    public void Save(bool enabled, IEnumerable<(string Id, bool On, string Mode)> rules)
    {
        lock (_lock)
        {
            var o = new JsonObject { ["enabled"] = enabled };
            var r = new JsonObject();
            var fresh = new Dictionary<string, (bool, HipsRules.Mode)>(StringComparer.OrdinalIgnoreCase);
            foreach (var (id, on, mode) in rules)
            {
                if (HipsRules.ById(id) == null) continue;
                var m = ParseMode(mode);
                r[id] = new JsonObject { ["on"] = on, ["mode"] = ModeName(m) };
                fresh[id] = (on, m);
            }
            o["rules"] = r;
            Enabled = enabled;
            _state = fresh;

            WriteFile(enabled, fresh, _exceptions);
        }
    }

    public void Save(bool enabled, IEnumerable<(string Id, bool On, string Mode)> rules,
                     IEnumerable<(string RuleId, string Path)> exceptions)
    {
        lock (_lock)
        {
            var fresh = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var (ruleId, path) in exceptions)
            {
                if (string.IsNullOrWhiteSpace(path)) continue;
                if (!string.Equals(ruleId, "*", StringComparison.Ordinal) && HipsRules.ById(ruleId) == null) continue;
                if (!fresh.TryGetValue(ruleId, out var list)) fresh[ruleId] = list = new List<string>();
                if (!list.Any(e => string.Equals(e, path, StringComparison.OrdinalIgnoreCase)))
                    list.Add(path.Trim());
            }
            _exceptions = fresh;
        }
        Save(enabled, rules);
    }

    private void WriteFile(bool enabled,
                           Dictionary<string, (bool Enabled, HipsRules.Mode Mode)> state,
                           Dictionary<string, List<string>> exceptions)
    {
        var o = new JsonObject { ["enabled"] = enabled, ["tier"] = Tier };
        var r = new JsonObject();
        foreach (var kv in state)
            r[kv.Key] = new JsonObject { ["on"] = kv.Value.Enabled, ["mode"] = ModeName(kv.Value.Mode) };
        o["rules"] = r;

        var ex = new JsonObject();
        foreach (var kv in exceptions)
        {
            if (kv.Value.Count == 0) continue;
            var arr = new JsonArray();
            foreach (var v in kv.Value) arr.Add(v);
            ex[kv.Key] = arr;
        }
        o["exceptions"] = ex;

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, Malward.ResidentShield.JsonText.Indented(o));
        }
        catch (Exception werr)
        {
            Log.Warn("HIPS", $"Failed to save settings to {_path}: {werr.GetType().Name}: {werr.Message}");
        }
        _loadedAt = DateTime.UtcNow;
    }
}
