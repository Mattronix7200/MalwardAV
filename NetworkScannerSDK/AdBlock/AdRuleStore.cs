using System.Collections.Concurrent;
using System.IO.MemoryMappedFiles;
using System.Text;
namespace Malward.NetworkScanner.AdBlock;

public sealed class AdRuleStats
{
    public long BlockDomains;
    public long BlockDomainsDns;
    public long BlockDomainsHttp;
    public long AllowDomains;
    public long NetworkRules;
    public long CosmeticGeneric;
    public long CosmeticSpecific;
    public long Scriptlets;
    public long HideExceptions;
    public long ScriptletSkipped;

    public long ScriptletConflicts;

    public long CosmeticExceptions;
    public long ReplaceRules;
    public long StealthExceptions;
    public long Procedural;
    public long DbBytes;
}

public sealed class AdRuleStore : IDisposable
{
    private readonly string _dir;

    private AdMmap? _block, _allow, _netIdx, _netDat, _cosIdx, _cosDat, _scrIdx, _scrDat, _hideIdx, _hideDat, _blockDns, _blockHttp;
    private AdMmap? _stealthIdx, _stealthDat;
    private AdMmap? _permIdx, _permDat;
    private AdMmap? _procIdx, _procDat;
    private AdMmap? _blockSrc, _blockDnsSrc, _blockHttpSrc;
    private string[] _listNames = Array.Empty<string>();
    private string _genericCss = "";
    private List<(AdFilterRule rule, string list)> _netNoToken = new();
    private List<AdReplaceRule> _replace = new();

    private readonly ConcurrentDictionary<string, AdFilterRule?> _ruleCache = new();

    private const int RuleCacheCap = 1500;

    public AdRuleStats Stats { get; private set; } = new();
    public bool IsLoaded { get; private set; }

    private const int IdxRec = 20;

    public AdRuleStore(string dir) => _dir = dir;

    private string P(string name) => Path.Combine(_dir, name);

    public void Load()
    {
        Dispose();
        _block = AdMmap.OpenOrNull(P("block.bin"));
        _blockDns = AdMmap.OpenOrNull(P("blockdns.bin"));
        _blockHttp = AdMmap.OpenOrNull(P("blockhttp.bin"));
        _stealthIdx = AdMmap.OpenOrNull(P("stealth.idx"));
        _stealthDat = AdMmap.OpenOrNull(P("stealth.dat"));
        _permIdx = AdMmap.OpenOrNull(P("perm.idx"));
        _permDat = AdMmap.OpenOrNull(P("perm.dat"));
        _procIdx = AdMmap.OpenOrNull(P("proc.idx"));
        _procDat = AdMmap.OpenOrNull(P("proc.dat"));
        _blockSrc = AdMmap.OpenOrNull(P("blocksrc.bin"));
        _blockDnsSrc = AdMmap.OpenOrNull(P("blockdnssrc.bin"));
        _blockHttpSrc = AdMmap.OpenOrNull(P("blockhttpsrc.bin"));
        try { _listNames = File.Exists(P("lists.txt")) ? File.ReadAllLines(P("lists.txt")) : Array.Empty<string>(); }
        catch { _listNames = Array.Empty<string>(); }
        _allow = AdMmap.OpenOrNull(P("allow.bin"));
        _netIdx = AdMmap.OpenOrNull(P("net.idx"));
        _netDat = AdMmap.OpenOrNull(P("net.dat"));
        _cosIdx = AdMmap.OpenOrNull(P("cos.idx"));
        _cosDat = AdMmap.OpenOrNull(P("cos.dat"));
        _scrIdx = AdMmap.OpenOrNull(P("scr.idx"));
        _scrDat = AdMmap.OpenOrNull(P("scr.dat"));
        _hideIdx = AdMmap.OpenOrNull(P("hide.idx"));
        _hideDat = AdMmap.OpenOrNull(P("hide.dat"));
        _genericCss = File.Exists(P("generic.css")) ? File.ReadAllText(P("generic.css")) : "";
        _netNoToken = LoadNoToken();
        _replace = LoadReplace();
        _ruleCache.Clear();
        Stats = ReadMeta();
        IsLoaded = _block != null || _netIdx != null || _blockDns != null
                   || _cosIdx != null || _scrIdx != null || _procIdx != null
                   || _genericCss.Length > 0 || _netNoToken.Count > 0;
    }

    private List<(AdFilterRule rule, string list)> LoadNoToken()
    {
        var list = new List<(AdFilterRule, string)>();
        var f = P("netnotoken.txt");
        if (!File.Exists(f)) return list;
        foreach (var line in File.ReadLines(f))
        {
            var (ruleText, itemName) = SplitSourcePrefix(line);
            var r = AdFilterRule.Parse(ruleText);
            if (r != null) list.Add((r, itemName));
        }
        return list;
    }

    public bool IsBlockedDomain(string host, bool dnsLayer = true)
        => IsBlockedDomain(host, dnsLayer, out _);

    public bool IsBlockedDomain(string host, bool dnsLayer, bool withStubHosts, out string listName)
        => IsBlockedDomainCore(host, dnsLayer, withStubHosts, out listName);

    public bool IsAllowedDomain(string host)
    {
        if (_allow == null) return false;
        host = AdRuleHash.NormalizeHost(host);
        foreach (var suf in AdRuleHash.Suffixes(host))
            if (SortedContains(_allow, AdRuleHash.Fnv1a(suf))) return true;
        return false;
    }

    public bool IsBlockedDomain(string host, bool dnsLayer, out string listName)
        => IsBlockedDomainCore(host, dnsLayer, withStubHosts: !dnsLayer, out listName);

    private bool IsBlockedDomainCore(string host, bool dnsLayer, bool withStubHosts, out string listName)
    {
        listName = "";
        host = AdRuleHash.NormalizeHost(host);
        bool blocked = false;
        foreach (var suf in AdRuleHash.Suffixes(host))
        {
            ulong h = AdRuleHash.Fnv1a(suf);
            if (_allow != null && SortedContains(_allow, h)) { listName = ""; return false; }
            if (!blocked && _block != null)
            {
                int i = SortedIndexOf(_block, h);
                if (i >= 0) { blocked = true; listName = HashSourceList(_blockSrc, i); }
            }
            if (!blocked && dnsLayer && _blockDns != null)
            {
                int i = SortedIndexOf(_blockDns, h);
                if (i >= 0) { blocked = true; listName = HashSourceList(_blockDnsSrc, i); }
            }
            if (!blocked && withStubHosts && _blockHttp != null)
            {
                int i = SortedIndexOf(_blockHttp, h);
                if (i >= 0) { blocked = true; listName = HashSourceList(_blockHttpSrc, i); }
            }
        }
        return blocked;
    }

    private string HashSourceList(AdMmap? src, int index)
    {
        if (src == null || index < 0) return "";
        long off = (long)index * sizeof(ushort);
        if (off + sizeof(ushort) > src.Length) return "";
        return ListNameAt(src.ReadUInt16(off));
    }

    public bool ShouldBlockRequest(string url, string host, string? docHost, AdResourceType type)
        => ShouldBlockRequest(url, host, docHost, type, out _);

    public bool ShouldBlockRequest(string url, string host, string? docHost, AdResourceType type, out string rule)
        => ShouldBlockRequest(url, host, docHost, type, out rule, out _);

    public bool ShouldBlockRequest(string url, string host, string? docHost, AdResourceType type,
        out string rule, out string? redirect)
        => ShouldBlockRequest(url, host, docHost, type, out rule, out redirect, out _);

    public bool ShouldBlockRequest(string url, string host, string? docHost, AdResourceType type,
        out string rule, out string? redirect, out string listName)
    {
        rule = ""; redirect = null; listName = "";
        host = AdRuleHash.NormalizeHost(host);

        if (MatchNet(url, host, docHost, type, exceptions: true, out _) != null) return false;

        var rr = MatchNet(url, host, docHost, type, exceptions: false, out listName, redirectOnly: true);
        if (rr != null && !rr.RedirectOnly) { rule = rr.Raw; redirect = rr.Redirect; return true; }

        var dm = BlockedDomainRule(host, out var domainListName);
        if (dm != null) { rule = "||" + dm + "^"; listName = domainListName; return true; }

        var nr = MatchNet(url, host, docHost, type, exceptions: false, out listName);
        if (nr != null) { rule = nr.Raw; redirect = nr.Redirect; return true; }
        listName = "";
        return false;
    }

    private AdFilterRule? MatchNet(string url, string host, string? docHost, AdResourceType type,
        bool exceptions, out string listName, bool redirectOnly = false)
    {
        listName = "";
        foreach (var tok in Tokenize(url))
        {
            if (_netIdx == null || _netDat == null) break;
            if (!IdxFind(_netIdx, AdRuleHash.Fnv1a(tok), out long off, out int len)) continue;
            foreach (var textLine in ReadLines(_netDat, off, len))
            {
                var (raw, itemName) = SplitSourcePrefix(textLine);
                bool isExc = raw.StartsWith("@@", StringComparison.Ordinal);
                if (isExc != exceptions) continue;
                var rule = GetRule(raw);
                if (rule == null) continue;
                if (redirectOnly && rule.Redirect == null) continue;

                if (!redirectOnly && !exceptions && rule.RedirectOnly) continue;
                if (rule.Matches(url, host, docHost, type)) { listName = itemName; return rule; }
            }
        }
        foreach (var (r, itemName) in _netNoToken)
        {
            if (r.IsException != exceptions) continue;
            if (redirectOnly && r.Redirect == null) continue;
            if (!redirectOnly && !exceptions && r.RedirectOnly) continue;
            if (r.Matches(url, host, docHost, type)) { listName = itemName; return r; }
        }
        return null;
    }

    private string? BlockedDomainRule(string host, out string listName)
    {
        listName = "";
        string? blocked = null;
        foreach (var suf in AdRuleHash.Suffixes(host))
        {
            ulong h = AdRuleHash.Fnv1a(suf);
            if (_allow != null && SortedContains(_allow, h)) { listName = ""; return null; }

            if (blocked == null && _block != null)
            {
                int i = SortedIndexOf(_block, h);
                if (i >= 0) { blocked = suf; listName = HashSourceList(_blockSrc, i); }
            }
            if (blocked == null && _blockHttp != null)
            {
                int i = SortedIndexOf(_blockHttp, h);
                if (i >= 0) { blocked = suf; listName = HashSourceList(_blockHttpSrc, i); }
            }
        }
        return blocked;
    }

    public string GetHideFlags(string host)
    {
        if (_hideIdx == null || _hideDat == null) return "";
        host = AdRuleHash.NormalizeHost(host);
        var sb = new StringBuilder(3);
        foreach (var suf in AdRuleHash.Suffixes(host))
            if (IdxFind(_hideIdx, AdRuleHash.Fnv1a(suf), out long off, out int len))
                foreach (var f in ReadLines(_hideDat, off, len))
                {
                    if (f.Length == 0) continue;
                    bool alreadyAdded = false;
                    for (int k = 0; k < sb.Length; k++) if (sb[k] == f[0]) { alreadyAdded = true; break; }
                    if (!alreadyAdded) sb.Append(f[0]);
                }
        return sb.ToString();
    }

    public (string generic, string specific) GetHidingCssSplit(string host)
    {
        host = AdRuleHash.NormalizeHost(host);

        var flags = GetHideFlags(host);
        if (flags.Contains('e')) return ("", "");
        var genericPart = flags.Contains('g') ? "" : _genericCss;
        if (_cosIdx == null || _cosDat == null || flags.Contains('s')) return (genericPart, "");

        var specific = CollectRespectingExclusions(_cosIdx, _cosDat, host);
        if (specific.Count == 0) return (genericPart, "");
        return (genericPart, BuildSpecificCss(specific));
    }

    public string GenericCss => _genericCss;

    private List<string> CollectRespectingExclusions(AdMmap? idx, AdMmap? dat, string host)
    {
        var result = new List<string>();
        if (idx == null || dat == null) return result;
        HashSet<string>? excluded = null;
        foreach (var suf in AdRuleHash.Suffixes(host))
        {
            if (!IdxFind(idx, AdRuleHash.Fnv1a(suf), out long off, out int len)) continue;
            foreach (var line in ReadLines(dat, off, len))
            {
                if (line.Length > 0 && line[0] == AdRuleCompiler.ExcludeMark)
                    (excluded ??= new()).Add(line[1..]);
                else
                    result.Add(line);
            }
        }
        if (excluded != null) result.RemoveAll(excluded.Contains);
        return result;
    }

    public string GetHidingCss(string host)
    {
        host = AdRuleHash.NormalizeHost(host);

        var flags = GetHideFlags(host);
        if (flags.Contains('e')) return "";
        var genericPart = flags.Contains('g') ? "" : _genericCss;
        bool skipSpecific = flags.Contains('s');

        if (_cosIdx == null || _cosDat == null || skipSpecific) return genericPart;

        var specific = CollectRespectingExclusions(_cosIdx, _cosDat, host);
        if (specific.Count == 0) return genericPart;
        var specificCss = BuildSpecificCss(specific);
        if (specificCss.Length == 0) return genericPart;
        var sb = new StringBuilder(genericPart);
        if (sb.Length > 0) sb.Append('\n');
        sb.Append(specificCss);
        return sb.ToString();
    }

    public HashSet<string> GetPermissionExemptions(string host)
    {
        var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (_permIdx == null || _permDat == null) return res;
        foreach (var suf in AdRuleHash.Suffixes(AdRuleHash.NormalizeHost(host)))
            if (IdxFind(_permIdx, AdRuleHash.Fnv1a(suf), out long off, out int len))
                foreach (var line in ReadLines(_permDat, off, len)) res.Add(line.Trim());
        return res;
    }

    public HashSet<string> GetStealthExemptions(string host)
    {
        var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (_stealthIdx == null || _stealthDat == null) return res;
        foreach (var suf in AdRuleHash.Suffixes(AdRuleHash.NormalizeHost(host)))
        {
            if (!IdxFind(_stealthIdx, AdRuleHash.Fnv1a(suf), out long off, out int len)) continue;
            foreach (var line in ReadLines(_stealthDat, off, len))
                foreach (var part in line.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    res.Add(part.Trim());
        }
        return res;
    }

    public List<string> GetProceduralSelectors(string host)
    {
        var res = new List<string>();
        if (_procIdx == null || _procDat == null) return res;
        var flags = GetHideFlags(host);
        if (flags.Contains('e') || flags.Contains('s')) return res;
        foreach (var s in CollectRespectingExclusions(_procIdx, _procDat, AdRuleHash.NormalizeHost(host)))
            if (!res.Contains(s)) res.Add(s);
        return res;
    }

    private static string BuildSpecificCss(List<string> entries)
    {
        var selectors = new List<string>();
        var cached = new List<string>();
        foreach (var w in entries)
        {
            if (w.Length > 1 && w[0] == AdRuleCompiler.StyleMark) cached.Add(w[1..]);
            else if (AdRuleCompiler.IsSafeSelector(w)) selectors.Add(w);
        }
        var sb = new StringBuilder();
        if (selectors.Count > 0) sb.Append(AdRuleCompiler.BuildCss(selectors));
        foreach (var g in cached) { if (sb.Length > 0) sb.Append('\n'); sb.Append(g); }
        return sb.ToString();
    }

    public List<string> GetScriptlets(string host)
    {
        if (_scrIdx == null || _scrDat == null) return new List<string>();
        var res = new List<string>();
        foreach (var s in CollectRespectingExclusions(_scrIdx, _scrDat, AdRuleHash.NormalizeHost(host)))
            if (!res.Contains(s)) res.Add(s);
        return res;
    }

    private List<AdReplaceRule> LoadReplace()
    {
        var res = new List<AdReplaceRule>();
        try
        {
            var f = P("replace.txt");
            if (!File.Exists(f)) return res;
            foreach (var line in File.ReadLines(f))
            {
                var r = AdReplaceRule.Parse(line);
                if (r != null) res.Add(r);
            }
        }
        catch (Exception ex) { Log.Warn("AdBlock", "Loading $replace rules: " + ex.Message); }
        return res;
    }

    public List<AdReplaceRule> GetReplaceRules(string url, string host, string? docHost,
                                                       AdResourceType type)
    {
        var res = new List<AdReplaceRule>();
        if (_replace.Count == 0) return res;
        bool excluded = false;
        foreach (var r in _replace)
        {
            if (!r.Matcher.Matches(url, host, docHost, type)) continue;
            if (r.IsException) { excluded = true; break; }
            res.Add(r);
        }
        return excluded ? new List<AdReplaceRule>() : res;
    }

    public string ListNameAt(int nr) =>
        nr >= 0 && nr < _listNames.Length ? _listNames[nr] : "";

    private (string rule, string list) SplitSourcePrefix(string textLine)
    {
        int i = textLine.IndexOf(AdRuleCompiler.SourceSep);
        if (i <= 0) return (textLine, "");
        return int.TryParse(textLine[..i], out var nr)
            ? (textLine[(i + 1)..], ListNameAt(nr))
            : (textLine[(i + 1)..], "");
    }

    private AdFilterRule? GetRule(string raw)
    {
        if (_ruleCache.TryGetValue(raw, out var r)) return r;
        if (_ruleCache.Count > RuleCacheCap) _ruleCache.Clear();
        var parsed = AdFilterRule.Parse(raw);
        _ruleCache[raw] = parsed;
        return parsed;
    }

    private static int SortedIndexOf(AdMmap m, ulong key)
    {
        long lo = 0, hi = m.Length / 8 - 1;
        while (lo <= hi)
        {
            long mid = (lo + hi) >> 1;
            ulong v = m.ReadUInt64(mid * 8);
            if (v == key) return (int)mid;
            if (v < key) lo = mid + 1; else hi = mid - 1;
        }
        return -1;
    }

    private static bool SortedContains(AdMmap m, ulong key)
    {
        long lo = 0, hi = m.Length / 8 - 1;
        while (lo <= hi)
        {
            long mid = (lo + hi) >> 1;
            ulong v = m.ReadUInt64(mid * 8);
            if (v == key) return true;
            if (v < key) lo = mid + 1; else hi = mid - 1;
        }
        return false;
    }

    private static bool IdxFind(AdMmap idx, ulong key, out long offset, out int length)
    {
        offset = 0; length = 0;
        long lo = 0, hi = idx.Length / IdxRec - 1;
        while (lo <= hi)
        {
            long mid = (lo + hi) >> 1;
            ulong v = idx.ReadUInt64(mid * IdxRec);
            if (v == key)
            {
                offset = idx.ReadInt64(mid * IdxRec + 8);
                length = idx.ReadInt32(mid * IdxRec + 16);
                return true;
            }
            if (v < key) lo = mid + 1; else hi = mid - 1;
        }
        return false;
    }

    private static IEnumerable<string> ReadLines(AdMmap dat, long offset, int length)
    {
        var bytes = dat.ReadBytes(offset, length);
        int start = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == (byte)'\n')
            {
                if (i > start) yield return Encoding.UTF8.GetString(bytes, start, i - start);
                start = i + 1;
            }
        }
        if (start < bytes.Length) yield return Encoding.UTF8.GetString(bytes, start, bytes.Length - start);
    }

    internal static IEnumerable<string> Tokenize(string url)
    {
        var lower = url.ToLowerInvariant();
        int i = 0, n = lower.Length;
        while (i < n)
        {
            if (!char.IsLetterOrDigit(lower[i])) { i++; continue; }
            int j = i;
            while (j < n && char.IsLetterOrDigit(lower[j])) j++;
            if (j - i >= 3) yield return lower[i..j];
            i = j;
        }
    }

    public static int StoredFormatVersion(string dir)
    {
        try
        {
            var f = Path.Combine(dir, "dbver.txt");
            return File.Exists(f) && int.TryParse(File.ReadAllText(f).Trim(), out var v) ? v : 0;
        }
        catch { return 0; }
    }

    public static AdRuleStats ReadStatsOnly(string dir)
    {
        var probe = new AdRuleStore(dir);
        return probe.ReadMeta();
    }

    private AdRuleStats ReadMeta()
    {
        try
        {
            var f = P("meta.txt");
            if (!File.Exists(f)) return new AdRuleStats();
            var s = new AdRuleStats();
            foreach (var line in File.ReadLines(f))
            {
                var kv = line.Split('=', 2);
                if (kv.Length != 2 || !long.TryParse(kv[1], out var v)) continue;
                switch (kv[0])
                {
                    case "block": s.BlockDomains = v; break;
                    case "blockdns": s.BlockDomainsDns = v; break;
                    case "allow": s.AllowDomains = v; break;
                    case "net": s.NetworkRules = v; break;
                    case "cosG": s.CosmeticGeneric = v; break;
                    case "cosS": s.CosmeticSpecific = v; break;
                    case "scr": s.Scriptlets = v; break;
                    case "hide": s.HideExceptions = v; break;
                    case "replace": s.ReplaceRules = v; break;
                    case "stealth": s.StealthExceptions = v; break;
                    case "proc": s.Procedural = v; break;
                    case "skip": s.ScriptletSkipped = v; break;
                }
            }
            s.DbBytes = DirSize();
            return s;
        }
        catch { return new AdRuleStats(); }
    }

    private long DirSize()
    {
        long total = 0;
        foreach (var f in new[] { "block.bin", "blockdns.bin", "blockhttp.bin", "allow.bin", "net.idx", "net.dat", "cos.idx", "cos.dat", "scr.idx", "scr.dat", "hide.idx", "hide.dat", "generic.css", "netnotoken.txt" })
            if (File.Exists(P(f))) total += new FileInfo(P(f)).Length;
        return total;
    }

    public void Dispose()
    {
        _block?.Dispose(); _blockDns?.Dispose(); _blockHttp?.Dispose(); _allow?.Dispose();
        _stealthIdx?.Dispose(); _stealthDat?.Dispose(); _stealthIdx = null; _stealthDat = null;
        _permIdx?.Dispose(); _permDat?.Dispose(); _permIdx = null; _permDat = null;
        _procIdx?.Dispose(); _procDat?.Dispose(); _procIdx = null; _procDat = null;
        _blockSrc?.Dispose(); _blockDnsSrc?.Dispose(); _blockHttpSrc?.Dispose();
        _blockSrc = null; _blockDnsSrc = null; _blockHttpSrc = null;
        _netIdx?.Dispose(); _netDat?.Dispose();
        _cosIdx?.Dispose(); _cosDat?.Dispose();
        _scrIdx?.Dispose(); _scrDat?.Dispose();
        _hideIdx?.Dispose(); _hideDat?.Dispose();
        _blockHttp = null;
        _block = _blockDns = _allow = _netIdx = _netDat = _cosIdx = _cosDat = _scrIdx = _scrDat = _hideIdx = _hideDat = null;
        IsLoaded = false;
    }
}

public sealed class AdMmap : IDisposable
{
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _acc;
    public long Length { get; }

    private AdMmap(string path, long length)
    {
        Length = length;
        _mmf = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        _acc = _mmf.CreateViewAccessor(0, length, MemoryMappedFileAccess.Read);
    }

    public static AdMmap? OpenOrNull(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            long len = new FileInfo(path).Length;
            return len == 0 ? null : new AdMmap(path, len);
        }
        catch { return null; }
    }

    public ulong ReadUInt64(long pos) => _acc.ReadUInt64(pos);
    public long ReadInt64(long pos) => _acc.ReadInt64(pos);
    public int ReadInt32(long pos) => _acc.ReadInt32(pos);
    public ushort ReadUInt16(long pos) => _acc.ReadUInt16(pos);
    public byte[] ReadBytes(long pos, int len) { var b = new byte[len]; _acc.ReadArray(pos, b, 0, len); return b; }

    public void Dispose() { _acc.Dispose(); _mmf.Dispose(); }
}
