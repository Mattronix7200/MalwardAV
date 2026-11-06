namespace Malward.ConsoleShell;

/// <summary>Switch parser shared by every shell: accepts both /x and --long forms.</summary>
public sealed class CommandLine
{
    private readonly List<string> _raw;
    private readonly HashSet<string> _used = new(StringComparer.OrdinalIgnoreCase);

    public CommandLine(IEnumerable<string> args) => _raw = args.ToList();

    public IReadOnlyList<string> Raw => _raw;

    private static string Normalise(string token)
    {
        var t = token.Trim();
        if (t.StartsWith("--", StringComparison.Ordinal)) return t[2..].ToLowerInvariant();
        if (t.StartsWith('/') || t.StartsWith('-')) return t[1..].ToLowerInvariant();
        return "";
    }

    public static bool IsSwitch(string token) => Normalise(token).Length > 0;

    private int IndexOf(params string[] names)
    {
        for (int i = 0; i < _raw.Count; i++)
        {
            var n = Normalise(_raw[i]);
            if (n.Length == 0) continue;
            foreach (var name in names)
                if (n.Equals(name, StringComparison.OrdinalIgnoreCase)) { _used.Add(_raw[i]); return i; }
        }
        return -1;
    }

    public bool Has(params string[] names) => IndexOf(names) >= 0;

    /// <summary>A flag that defaults to on: present alone turns it on, "name off|0|no" turns it off.</summary>
    public bool Flag(bool fallback, params string[] names)
    {
        int i = IndexOf(names);
        if (i < 0) return fallback;

        var next = i + 1 < _raw.Count ? _raw[i + 1] : "";
        if (next.Length > 0 && !IsSwitch(next))
        {
            if (next.Equals("off", StringComparison.OrdinalIgnoreCase)
             || next.Equals("no", StringComparison.OrdinalIgnoreCase)
             || next == "0") { _used.Add(next); return false; }
            if (next.Equals("on", StringComparison.OrdinalIgnoreCase)
             || next.Equals("yes", StringComparison.OrdinalIgnoreCase)
             || next == "1") { _used.Add(next); return true; }
        }
        return true;
    }

    public string? Value(params string[] names)
    {
        int i = IndexOf(names);
        if (i < 0 || i + 1 >= _raw.Count) return null;
        var v = _raw[i + 1];
        if (IsSwitch(v)) return null;
        _used.Add(v);
        return v;
    }

    public int? Number(params string[] names)
    {
        var v = Value(names);
        return int.TryParse(v, out var n) ? n : null;
    }

    /// <summary>Everything that was not consumed as a switch or its value - used for paths.</summary>
    public List<string> Positional()
    {
        var o = new List<string>();
        for (int i = 0; i < _raw.Count; i++)
        {
            if (IsSwitch(_raw[i])) continue;
            if (_used.Contains(_raw[i])) continue;
            o.Add(_raw[i]);
        }
        return o;
    }

    public List<string> ValuesAfter(params string[] names)
    {
        int i = IndexOf(names);
        var o = new List<string>();
        if (i < 0) return o;
        for (int k = i + 1; k < _raw.Count && !IsSwitch(_raw[k]); k++)
        {
            _used.Add(_raw[k]);
            foreach (var part in _raw[k].Split(',', StringSplitOptions.RemoveEmptyEntries
                                                  | StringSplitOptions.TrimEntries))
                o.Add(part.Trim('{', '}', '"'));
        }
        return o;
    }
}
