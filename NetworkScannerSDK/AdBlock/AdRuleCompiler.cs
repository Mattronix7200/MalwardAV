using System.Text;
using Malward.NetworkScanner.AdBlock;

namespace Malward.NetworkScanner.AdBlock;

public static class AdRuleCompiler
{
    private const int GenericCap = 60000;

    public const char ExcludeMark = '';

    public const char StyleMark = '';

    public const int FormatVersion = 13;

    public const char SourceSep = '\u0003';

    public static AdRuleStats Build(string dir, IEnumerable<string> filePaths, IEnumerable<string> inlineContents)
        => Build(dir, filePaths.Select(f => (f, false)), inlineContents);

    public static AdRuleStats Build(string dir, IEnumerable<(string path, bool dnsOnly)> filePaths,
                                    IEnumerable<string> inlineContents)
        => Build(dir, filePaths.Select(f => (f.path, f.dnsOnly, Path.GetFileNameWithoutExtension(f.path))),
                 inlineContents);

    public static AdRuleStats Build(string dir, IEnumerable<(string path, bool dnsOnly, string name)> filePaths,
                                    IEnumerable<string> inlineContents)
        => Build(dir, filePaths, inlineContents, null);

    public static AdRuleStats Build(string dir, IEnumerable<(string path, bool dnsOnly, string name)> filePaths,
                                    IEnumerable<string> inlineContents,
                                    IReadOnlySet<string>? trustedJsSources)
    {
        Directory.CreateDirectory(dir);

        var listNames = new List<string>();
        ushort currentListIndex = 0;

        var block = new List<(ulong h, ushort src)>();
        var blockDns = new List<(ulong h, ushort src)>();
        var blockHttp = new List<(ulong h, ushort src)>();
        var domainBlocks = new List<(string host, ushort src, bool dnsOnly)>();
        var stubHosts = new HashSet<string>(StringComparer.Ordinal);
        var allow = new List<ulong>();
        var generic = new List<string>();
        var specific = new Dictionary<ulong, List<string>>();
        var netByToken = new Dictionary<ulong, List<string>>();
        var netNoToken = new List<string>();
        var scriptlet = new Dictionary<ulong, List<string>>();
        var hideExc = new Dictionary<ulong, List<string>>();
        var replaces = new List<string>();
        var stealthExc = new Dictionary<ulong, List<string>>();
        var permExc = new Dictionary<ulong, List<string>>();
        var proc = new Dictionary<ulong, List<string>>();

        var genericExc = new HashSet<string>(StringComparer.Ordinal);
        var procExc = new HashSet<(ulong, string)>();
        var stats = new AdRuleStats();

        void Feed(IEnumerable<string> lines, bool dnsOnly, bool trustedJs)
        {
            var target = dnsOnly ? blockDns : block;
            foreach (var line in lines)
            {
                try
                {
                    NoteStubHost(line, stubHosts);
                    Classify(line, target, currentListIndex, allow, generic, specific, netByToken, netNoToken, scriptlet, hideExc, replaces, stealthExc, permExc, proc, genericExc, procExc, stats, dnsOnly, trustedJs, domainBlocks);
                }
                catch {  }
            }
        }

        foreach (var (path, dnsOnly, name) in filePaths)
        {
            if (!File.Exists(path)) continue;
            listNames.Add(string.IsNullOrWhiteSpace(name) ? Path.GetFileName(path) : name);
            currentListIndex = (ushort)(listNames.Count - 1);
            Feed(File.ReadLines(path), dnsOnly,
                 trustedJsSources != null && trustedJsSources.Contains(path));
        }
        listNames.Add("Reguły wbudowane i własne");
        currentListIndex = (ushort)(listNames.Count - 1);
        foreach (var content in inlineContents)
            Feed(SplitLines(content), false, false);
        File.WriteAllLines(Path.Combine(dir, "lists.txt"), listNames);

        foreach (var (host, src, dnsOnly) in domainBlocks)
        {
            ulong h = AdRuleHash.Fnv1a(host);
            if (NeedsStub(host, stubHosts)) blockHttp.Add((h, src));
            else if (dnsOnly) blockDns.Add((h, src));
            else block.Add((h, src));
        }

        stats.BlockDomains = WriteHashes(Path.Combine(dir, "block.bin"), block,
                                         Path.Combine(dir, "blocksrc.bin"));
        stats.BlockDomainsHttp = WriteHashes(Path.Combine(dir, "blockhttp.bin"), blockHttp,
                                             Path.Combine(dir, "blockhttpsrc.bin"));
        stats.BlockDomainsDns = WriteHashes(Path.Combine(dir, "blockdns.bin"), blockDns,
                                            Path.Combine(dir, "blockdnssrc.bin"));
        stats.AllowDomains = WriteHashes(Path.Combine(dir, "allow.bin"),
                                         allow.Select(h => (h, (ushort)0)).ToList(), null);

        var gen = generic.Where(IsSafeSelector).ToList();
        int beforeExceptions = gen.Count;
        if (genericExc.Count > 0) gen.RemoveAll(genericExc.Contains);
        stats.CosmeticExceptions = beforeExceptions - gen.Count;
        if (procExc.Count > 0)
            foreach (var (h, sel) in procExc)
                if (proc.TryGetValue(h, out var lp)) { if (lp.Remove(sel)) stats.CosmeticExceptions++; }
        if (gen.Count > GenericCap) gen = gen.GetRange(0, GenericCap);
        File.WriteAllText(Path.Combine(dir, "generic.css"), BuildCss(gen));
        stats.CosmeticGeneric = gen.Count;

        stats.NetworkRules = WriteIndexed(Path.Combine(dir, "net.idx"), Path.Combine(dir, "net.dat"), netByToken);
        stats.CosmeticSpecific = WriteIndexed(Path.Combine(dir, "cos.idx"), Path.Combine(dir, "cos.dat"), specific);
        stats.ScriptletConflicts = DropCompetingNodeRewrites(scriptlet);
        stats.Scriptlets = WriteIndexed(Path.Combine(dir, "scr.idx"), Path.Combine(dir, "scr.dat"), scriptlet);
        stats.HideExceptions = WriteIndexed(Path.Combine(dir, "hide.idx"), Path.Combine(dir, "hide.dat"), hideExc);
        stats.StealthExceptions = WriteIndexed(Path.Combine(dir, "stealth.idx"), Path.Combine(dir, "stealth.dat"), stealthExc);
        WriteIndexed(Path.Combine(dir, "perm.idx"), Path.Combine(dir, "perm.dat"), permExc);
        stats.Procedural = WriteIndexed(Path.Combine(dir, "proc.idx"), Path.Combine(dir, "proc.dat"), proc);

        File.WriteAllLines(Path.Combine(dir, "netnotoken.txt"), netNoToken);
        File.WriteAllLines(Path.Combine(dir, "replace.txt"), replaces);
        File.WriteAllText(Path.Combine(dir, "dbver.txt"), FormatVersion.ToString());
        stats.DbBytes = DirSize(dir);

        File.WriteAllText(Path.Combine(dir, "meta.txt"),
            $"block={stats.BlockDomains}\nblockdns={stats.BlockDomainsDns}\n" +
            $"allow={stats.AllowDomains}\nnet={stats.NetworkRules}\n" +
            $"cosG={stats.CosmeticGeneric}\ncosS={stats.CosmeticSpecific}\nscr={stats.Scriptlets}\n" +
            $"hide={stats.HideExceptions}\nskip={stats.ScriptletSkipped}\n" +
            $"replace={stats.ReplaceRules}\nstealth={stats.StealthExceptions}\n" +
            $"proc={stats.Procedural}\n");

        return stats;
    }

    private static void Classify(
        string raw, List<(ulong h, ushort src)> block, ushort src, List<ulong> allow, List<string> generic,
        Dictionary<ulong, List<string>> specific, Dictionary<ulong, List<string>> netByToken,
        List<string> netNoToken, Dictionary<ulong, List<string>> scriptlet,
        Dictionary<ulong, List<string>> hideExc, List<string> replaces,
        Dictionary<ulong, List<string>> stealthExc, Dictionary<ulong, List<string>> permExc,
        Dictionary<ulong, List<string>> proc,
        HashSet<string> genericExc, HashSet<(ulong, string)> procExc,
        AdRuleStats stats, bool dnsOnly = false, bool trustedJs = false,
        List<(string host, ushort src, bool dnsOnly)>? domainBlocks = null)
    {
        var line = raw.Trim();
        if (line.Length == 0 || line[0] == '!' || line[0] == '[') return;

        if (AdReplaceRule.LooksLikeReplace(line))
        {
            if (!dnsOnly && AdReplaceRule.Parse(line) != null)
            {
                replaces.Add(line);
                stats.ReplaceRules++;
            }
            return;
        }

        int hh = IndexOfCosmetic(line, out var kind);
        if (hh >= 0)
        {
            var domainsPart = line[..hh];
            var body = line[(hh + kind.Length)..];

            bool isExceptionRule = kind.Length > 1 && kind[1] == '@';

            if ((kind == "##" || kind == "#@#") && body.StartsWith("+js(") && body.EndsWith(")"))
            { AddScriptlet(domainsPart, body[4..^1], adguard: false, scriptlet, stats, isExceptionRule); return; }
            if ((kind == "#%#" || kind == "#@%#") && body.Contains("//scriptlet("))
            {
                int lp = body.IndexOf('('), rp = body.LastIndexOf(')');
                if (lp >= 0 && rp > lp)
                    AddScriptlet(domainsPart, body[(lp + 1)..rp], adguard: true, scriptlet, stats, isExceptionRule);
                return;
            }

            if (kind == "#%#" && trustedJs && domainsPart.Length > 0
                && body.Length > 0 && !body.StartsWith("//"))
            { AddRawJs(domainsPart, body, scriptlet, stats); return; }

            if (body.Length == 0 || body.Contains("+js(") || kind == "#%#" || kind == "#@%#" || body.StartsWith("//"))
            { stats.ScriptletSkipped++; return; }

            if (TryPlainStyle(body, out var styleSel, out var styleCss))
            {

                var reguła = StyleMark + styleSel + "{" + styleCss + "}";
                if (domainsPart.Length == 0) { stats.ScriptletSkipped++; return; }
                foreach (var d0 in domainsPart.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    var t0 = d0.Trim();
                    bool ex0 = t0.StartsWith('~');
                    var dm0 = (ex0 ? t0[1..] : t0).ToLowerInvariant();
                    if (dm0.Length == 0 || !dm0.Contains('.')) continue;
                    ulong hh0 = AdRuleHash.Fnv1a(dm0);
                    if (!specific.TryGetValue(hh0, out var l0)) specific[hh0] = l0 = new();
                    l0.Add(ex0 || isExceptionRule ? ExcludeMark + reguła : reguła);
                }
                return;
            }

            if (AdProcedural.IsProcedural(body))
            {
                if (domainsPart.Length == 0 || !AdProcedural.IsSupported(body))
                { stats.ScriptletSkipped++; return; }
                foreach (var d1 in domainsPart.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    var t1 = d1.Trim();
                    if (t1.StartsWith('~')) continue;
                    var dm1 = t1.ToLowerInvariant();
                    if (dm1.Length == 0 || !dm1.Contains('.')) continue;
                    ulong hh1 = AdRuleHash.Fnv1a(dm1);
                    if (!proc.TryGetValue(hh1, out var l1)) proc[hh1] = l1 = new();
                    if (isExceptionRule) { procExc.Add((hh1, body)); continue; }
                    if (l1.Count < 60 && !l1.Contains(body)) l1.Add(body);
                }
                return;
            }

            if (isExceptionRule) { genericExc.Add(body); }

            if (domainsPart.Length == 0) { if (!isExceptionRule) generic.Add(body); }
            else
                foreach (var d in domainsPart.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    var tok = d.Trim();

                    bool exclude = tok.StartsWith('~');
                    var domain = (exclude ? tok[1..] : tok).ToLowerInvariant();
                    if (domain.Length == 0 || !domain.Contains('.')) continue;
                    ulong h = AdRuleHash.Fnv1a(domain);
                    if (!specific.TryGetValue(h, out var list)) specific[h] = list = new();
                    list.Add(exclude || isExceptionRule ? ExcludeMark + body : body);
                }
            return;
        }

        if ((line[0] is '0' or '1' or ':') && (line.Contains(' ') || line.Contains('\t')))
        {
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && (parts[0] is "0.0.0.0" or "127.0.0.1" or "::" or "::1"))
            {
                for (int i = 1; i < parts.Length; i++)
                {
                    var h = parts[i].Trim().TrimEnd('.').ToLowerInvariant();
                    if (h != "localhost" && h.Contains('.')) block.Add((AdRuleHash.Fnv1a(h), src));
                }
                return;
            }
        }

        bool isException = line.StartsWith("@@");

        if (isException && line.Contains("$permissions=", StringComparison.OrdinalIgnoreCase))
        {
            int dp = line.IndexOf("$permissions=", StringComparison.OrdinalIgnoreCase);
            var pat3 = line[2..dp];
            var value = line[(dp + "$permissions=".Length)..];
            int dm = value.IndexOf(",domain=", StringComparison.OrdinalIgnoreCase);
            if (dm >= 0) value = value[..dm];

            var itemName = value.Split('=')[0].Trim().ToLowerInvariant();
            if (pat3.StartsWith("||")) pat3 = pat3[2..];
            int uk = pat3.IndexOf('/');
            var dom3 = (uk > 0 ? pat3[..uk] : pat3).TrimEnd('^').TrimEnd('.').ToLowerInvariant();
            if (itemName.Length > 0 && dom3.Length > 0 && dom3.Contains('.') && !dom3.Contains('*'))
            {
                ulong h3 = AdRuleHash.Fnv1a(dom3);
                if (!permExc.TryGetValue(h3, out var pl)) permExc[h3] = pl = new();
                if (!pl.Contains(itemName)) pl.Add(itemName);
            }
            return;
        }

        if (isException && line.Contains("$stealth", StringComparison.OrdinalIgnoreCase))
        {
            int stealthAt = line.IndexOf("$stealth", StringComparison.OrdinalIgnoreCase);
            var patt2 = line[2..stealthAt];

            var rest = line[(stealthAt + "$stealth".Length)..];
            string mods = "";
            if (rest.StartsWith("=", StringComparison.Ordinal))
            {
                var v = rest[1..];
                int endPos = v.IndexOf(",domain=", StringComparison.OrdinalIgnoreCase);
                mods = (endPos >= 0 ? v[..endPos] : v).Trim();
            }
            if (patt2.StartsWith("||")) patt2 = patt2[2..];
            int slash = patt2.IndexOf('/');
            var dom2 = (slash > 0 ? patt2[..slash] : patt2).TrimEnd('^').TrimEnd('.').ToLowerInvariant();
            if (dom2.Length > 0 && dom2.Contains('.') && !dom2.Contains('*'))
            {
                ulong h2 = AdRuleHash.Fnv1a(dom2);
                if (!stealthExc.TryGetValue(h2, out var lst)) stealthExc[h2] = lst = new();
                var record_ = mods.Length == 0 ? "*" : mods.ToLowerInvariant();
                if (!lst.Contains(record_)) lst.Add(record_);
            }
            return;
        }

        if (isException && line.Contains('$'))
        {
            var optPart = line[(line.IndexOf('$') + 1)..];
            char flag = '\0';
            if (Contains(optPart, "elemhide") || Contains(optPart, "ehide")) flag = 'e';
            else if (Contains(optPart, "generichide") || Contains(optPart, "ghide")) flag = 'g';
            else if (Contains(optPart, "specifichide") || Contains(optPart, "shide")) flag = 's';
            if (flag != '\0')
            {
                var patt = line[2..line.IndexOf('$')];
                if (patt.StartsWith("||")) patt = patt[2..];
                var domain = patt.TrimEnd('^', '/').TrimEnd('.').ToLowerInvariant();
                if (domain.Length > 0 && domain.Contains('.') && !domain.Contains('*') && !domain.Contains('/'))
                {
                    ulong h = AdRuleHash.Fnv1a(domain);
                    if (!hideExc.TryGetValue(h, out var fl)) hideExc[h] = fl = new();
                    var fs = flag.ToString();
                    if (!fl.Contains(fs)) fl.Add(fs);
                }
                return;
            }
        }

        if (TryPureDomainRule(line, out var host))
        {
            if (isException)
            {
                allow.Add(AdRuleHash.Fnv1a(host));

                var exceptionRule = AdFilterRule.Parse(line);
                if (exceptionRule != null)
                {
                    if (exceptionRule.Token.Length >= 3)
                    {
                        ulong ht = AdRuleHash.Fnv1a(exceptionRule.Token);
                        if (!netByToken.TryGetValue(ht, out var lw)) netByToken[ht] = lw = new();
                        lw.Add($"{src}{SourceSep}{line}");
                    }
                    else netNoToken.Add($"{src}{SourceSep}{line}");
                }
            }
            else if (domainBlocks != null) domainBlocks.Add((host, src, dnsOnly));
            else block.Add((AdRuleHash.Fnv1a(host), src));
            return;
        }

        if (line.Contains("||") || line.StartsWith("|") || line.Contains('/') || line.Contains('*') || line.Contains('^'))
        {
            var rule = AdFilterRule.Parse(line);
            if (rule == null) return;
            if (rule.Token.Length >= 3)
            {
                ulong h = AdRuleHash.Fnv1a(rule.Token);
                if (!netByToken.TryGetValue(h, out var list)) netByToken[h] = list = new();
                list.Add($"{src}{SourceSep}{line}");
            }
            else netNoToken.Add($"{src}{SourceSep}{line}");
            return;
        }

        var plain = line.TrimEnd('.').ToLowerInvariant();
        if (plain.Contains('.') && !plain.Contains(' ')) block.Add((AdRuleHash.Fnv1a(plain), src));
    }

    private static bool Contains(string s, string needle) =>
        s.Contains(needle, StringComparison.OrdinalIgnoreCase);

    public const int SelectorsPerRule = 20;

    public static string BuildCss(IReadOnlyList<string> selectors)
    {
        if (selectors.Count == 0) return "";
        var sb = new StringBuilder(selectors.Count * 24);
        for (int i = 0; i < selectors.Count; i += SelectorsPerRule)
        {
            int end = Math.Min(i + SelectorsPerRule, selectors.Count);
            for (int j = i; j < end; j++)
            {
                if (j > i) sb.Append(',');
                sb.Append(selectors[j]);
            }
            sb.Append("{display:none!important}\n");
        }
        return sb.ToString();
    }

    public static bool IsSafeSelector(string sel)
    {
        if (string.IsNullOrWhiteSpace(sel)) return false;
        if (sel.Length > 250) return false;
        if (sel.IndexOf('{') >= 0 || sel.IndexOf('}') >= 0 || sel.IndexOf(';') >= 0) return false;
        if (sel.Contains("/*") || sel.Contains("*/")) return false;
        if (sel.Contains('\\')) return false;
        if (IsProceduralSelector(sel)) return false;
        if (sel.StartsWith(",") || sel.EndsWith(",")) return false;
        if (sel.EndsWith(">") || sel.EndsWith("+") || sel.EndsWith("~")) return false;

        int round = 0, square = 0;
        char quote = '\0';
        foreach (var c in sel)
        {
            if (quote != '\0') { if (c == quote) quote = '\0'; continue; }
            switch (c)
            {
                case '"': case '\'': quote = c; break;
                case '(': round++; break;
                case ')': round--; if (round < 0) return false; break;
                case '[': square++; break;
                case ']': square--; if (square < 0) return false; break;
            }
        }
        return round == 0 && square == 0 && quote == '\0';
    }

    private static readonly HashSet<string> NodeTextRewriters = new(StringComparer.Ordinal)
    {
        "replace-node-text", "rpnt", "trusted-replace-node-text", "trusted-rpnt",
        "xml-prune", "trusted-set-attr",
    };

    private static long DropCompetingNodeRewrites(Dictionary<ulong, List<string>> scriptlet)
    {
        long dropped = 0;
        foreach (var items in scriptlet.Values)
        {
            if (items.Count < 2) continue;
            HashSet<string>? taken = null;
            for (int i = 0; i < items.Count; i++)
            {
                var record_ = items[i];
                var plainEntry = record_.Length > 0 && record_[0] == ExcludeMark ? record_[1..] : record_;
                var segments = plainEntry.Split(AdScriptlet.Sep);
                if (segments.Length < 2 || !NodeTextRewriters.Contains(segments[0])) continue;

                var cacheKey = segments[1];
                taken ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (taken.Add(cacheKey)) continue;

                items.RemoveAt(i--);
                dropped++;
            }
        }
        return dropped;
    }

    private static void AddRawJs(string domainsPart, string js,
        Dictionary<ulong, List<string>> scriptlet, AdRuleStats stats)
    {
        if (js.Length > 8000) { stats.ScriptletSkipped++; return; }
        var spec = AdScriptlet.RawJsName + AdScriptlet.Sep + js;

        foreach (var d in domainsPart.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var raw = d.Trim();
            if (raw.StartsWith('~')) continue;
            var domain = raw.ToLowerInvariant();
            if (domain.Length == 0 || !domain.Contains('.')) continue;
            ulong h = AdRuleHash.Fnv1a(domain);
            if (!scriptlet.TryGetValue(h, out var list)) scriptlet[h] = list = new();
            if (list.Count < 40 && !list.Contains(spec)) list.Add(spec);
        }
    }

    private static void AddScriptlet(string domainsPart, string inner,
        bool adguard, Dictionary<ulong, List<string>> scriptlet, AdRuleStats stats,
        bool isExceptionRule = false)
    {
        if (domainsPart.Length == 0) return;
        var tokens = SplitScriptletArgs(inner, adguard);
        if (tokens.Count == 0 || tokens[0].Length == 0) return;
        var spec = string.Join(AdScriptlet.Sep, tokens);

        foreach (var d in domainsPart.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var raw = d.Trim();
            bool exclude = raw.StartsWith('~');
            var domain = (exclude ? raw[1..] : raw).ToLowerInvariant();
            if (domain.Length == 0 || !domain.Contains('.')) continue;
            ulong h = AdRuleHash.Fnv1a(domain);
            if (!scriptlet.TryGetValue(h, out var list)) scriptlet[h] = list = new();
            var entry = exclude || isExceptionRule ? ExcludeMark + spec : spec;
            if (list.Count < 40 && !list.Contains(entry)) list.Add(entry);
        }
    }

    private static List<string> SplitScriptletArgs(string s, bool adguard)
    {
        var res = new List<string>();
        var cur = new StringBuilder();
        char quote = '\0';
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (quote != '\0')
            {

                if (c == '\\' && i + 1 < s.Length && (s[i + 1] == quote || s[i + 1] == '\\'))
                    cur.Append(s[++i]);
                else if (c == quote) quote = '\0';
                else cur.Append(c);
            }
            else if (c == '`' || (adguard && (c == '\'' || c == '"'))) quote = c;
            else if (c == '\\' && i + 1 < s.Length && s[i + 1] == ',') { cur.Append(','); i++; }
            else if (c == ',') { res.Add(cur.ToString().Trim()); cur.Clear(); }
            else cur.Append(c);
        }
        if (cur.Length > 0 || res.Count > 0) res.Add(cur.ToString().Trim());

        while (res.Count > 0 && res[^1].Length == 0) res.RemoveAt(res.Count - 1);
        if (res.Count > 0 && res[0].Length == 0) res.Clear();

        for (int k = 0; k < res.Count; k++)
        {
            var t = res[k];
            if (t.Length >= 2 && (t[0] == '\'' || t[0] == '"') && t[^1] == t[0])
                res[k] = t[1..^1];
        }
        return res;
    }

    private static long WriteHashes(string path, List<(ulong h, ushort src)> hashes, string? srcPath)
    {

        hashes.Sort((a, b) => a.h != b.h ? a.h.CompareTo(b.h) : a.src.CompareTo(b.src));
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        using var bw = new BinaryWriter(fs);
        FileStream? sf = null; BinaryWriter? sw = null;
        if (srcPath != null)
        {
            sf = new FileStream(srcPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
            sw = new BinaryWriter(sf);
        }
        try
        {
            ulong prev = 0; bool first = true; long count = 0;
            foreach (var (h, src) in hashes)
            {
                if (!first && h == prev) continue;
                bw.Write(h); sw?.Write(src);
                prev = h; first = false; count++;
            }
            return count;
        }
        finally { sw?.Dispose(); sf?.Dispose(); }
    }

    private static long WriteIndexed(string idxPath, string datPath, Dictionary<ulong, List<string>> map)
    {
        var records = new List<(ulong key, long off, int len)>(map.Count);
        long total = 0;
        using (var dat = new FileStream(datPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        {
            foreach (var kv in map)
            {
                var blob = Encoding.UTF8.GetBytes(string.Join("\n", kv.Value));
                long off = dat.Position;
                dat.Write(blob, 0, blob.Length);
                records.Add((kv.Key, off, blob.Length));
                total += kv.Value.Count;
            }
        }
        records.Sort((a, b) => a.key.CompareTo(b.key));
        using (var idx = new FileStream(idxPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
        using (var bw = new BinaryWriter(idx))
            foreach (var r in records) { bw.Write(r.key); bw.Write(r.off); bw.Write(r.len); }
        return total;
    }

    private static long DirSize(string dir)
    {
        long total = 0;
        try
        {
            foreach (var f in Directory.GetFiles(dir)) total += new FileInfo(f).Length;
        }
        catch { }
        return total;
    }

    private static IEnumerable<string> SplitLines(string content)
    {
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) != null) yield return line;
    }

    private static readonly string[] CosmeticMarks =
        { "#@?#", "#@$#", "#@%#", "#@#", "#?#", "#$#", "#%#", "##" };

    private static int IndexOfCosmetic(string line, out string kind)
    {
        foreach (var k in CosmeticMarks)
        {
            int idx = line.IndexOf(k, StringComparison.Ordinal);
            if (idx >= 0) { kind = k; return idx; }
        }
        kind = "";
        return -1;
    }

    private static bool TryPlainStyle(string body, out string sel, out string css)
    {
        sel = ""; css = "";
        int i = body.IndexOf(":style(", StringComparison.Ordinal);
        if (i <= 0 || !body.EndsWith(")", StringComparison.Ordinal)) return false;
        sel = body[..i];
        css = body[(i + ":style(".Length)..^1].Trim();
        if (css.Length == 0 || css.Length > 200) return false;
        if (css.Contains('{') || css.Contains('}') || css.Contains('<')) return false;
        if (AdProcedural.IsProcedural(sel)) return false;
        return IsSafeSelector(sel);
    }

    private static bool IsProceduralSelector(string sel) =>
        sel.Contains(":-abp-") || sel.Contains(":has-text(") || sel.Contains(":matches-")
        || sel.Contains(":xpath(") || sel.Contains(":upward(") || sel.Contains(":style(")
        || sel.Contains(":watch-attr") || sel.Contains(":remove()") || sel.Contains(":min-text-length");


    private static void NoteStubHost(string line, HashSet<string> stubHosts)
    {
        if (line.Length == 0 || line[0] == '!' || line[0] == '#') return;
        int opt = line.IndexOf('$');
        if (opt < 0) return;
        var options = line[(opt + 1)..];
        if (options.IndexOf("redirect", StringComparison.Ordinal) < 0) return;

        var pattern = line[..opt];
        if (pattern.StartsWith("@@", StringComparison.Ordinal)) pattern = pattern[2..];
        if (pattern.StartsWith("||", StringComparison.Ordinal)) pattern = pattern[2..];
        else return;

        int end = pattern.IndexOfAny(new[] { '/', '^', '*', '|' });
        var host = (end < 0 ? pattern : pattern[..end]).Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Length > 3 && host.Contains('.') && !host.Contains('*')) stubHosts.Add(host);
    }

    private static bool NeedsStub(string host, HashSet<string> stubHosts)
    {
        var h = host;
        while (true)
        {
            if (stubHosts.Contains(h)) return true;
            int dot = h.IndexOf('.');
            if (dot < 0) return false;
            h = h[(dot + 1)..];
            if (!h.Contains('.')) return false;
        }
    }

    private static bool TryPureDomainRule(string line, out string host)
    {
        host = "";
        var s = line;
        if (s.StartsWith("@@")) s = s[2..];
        if (!s.StartsWith("||")) return false;
        if (s.Contains('$') || s.Contains('*')) return false;
        s = s[2..];
        if (s.EndsWith("^")) s = s[..^1];
        if (s.Contains('/') || s.Contains('^') || s.Contains('|')) return false;
        s = s.TrimEnd('.').ToLowerInvariant();
        if (!s.Contains('.') || s.Length == 0) return false;
        foreach (var c in s) if (!(char.IsLetterOrDigit(c) || c is '.' or '-' or '_')) return false;
        host = s;
        return true;
    }
}
