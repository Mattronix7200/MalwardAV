using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace Malward.NetworkScanner;

public sealed class AdBlockEngine
{
    private readonly ConcurrentDictionary<string, DomainRule> _blockDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DomainRule> _allowDomains = new(StringComparer.OrdinalIgnoreCase);

    private readonly List<PatternRule> _blockPatterns = new();
    private readonly List<PatternRule> _allowPatterns = new();
    private readonly object _lock = new();

    public int DomainRuleCount => _blockDomains.Count + _allowDomains.Count;
    public int PatternRuleCount => _blockPatterns.Count + _allowPatterns.Count;
    public int TotalRules => DomainRuleCount + PatternRuleCount;

    public void Clear()
    {
        lock (_lock)
        {
            _blockDomains.Clear();
            _allowDomains.Clear();
            _blockPatterns.Clear();
            _allowPatterns.Clear();
        }
    }

    public int LoadList(string text, string listName = "")
    {
        if (string.IsNullOrEmpty(text)) return 0;
        int added = 0;
        foreach (var raw in text.Split('\n'))
        {
            var ln = raw.TrimEnd('\r').Trim();
            if (string.IsNullOrEmpty(ln)) continue;
            if (ln[0] == '!' || ln[0] == '#') continue;
            if (ln[0] == '[' && ln.EndsWith("]")) continue;
            if (ln.Contains("##") || ln.Contains("#@#") || ln.Contains("##+js("))
                continue;
            if (ln.Contains("$csp=") || ln.Contains("$redirect="))
                continue;

            if (Regex.IsMatch(ln, @"^(127\.0\.0\.1|0\.0\.0\.0|::1)\s+"))
            {
                var parts = ln.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2)
                {
                    var domain = parts[1].Split('#')[0].Trim();
                    if (IsValidDomain(domain))
                    {
                        _blockDomains[domain] = new DomainRule(domain, false);
                        added++;
                    }
                }
                continue;
            }

            if (TryAddRule(ln)) added++;
        }
        return added;
    }

    private bool TryAddRule(string line)
    {
        bool isException = false;
        if (line.StartsWith("@@"))
        {
            isException = true;
            line = line.Substring(2);
        }

        string pattern = line;
        string mods = "";
        int dollar = line.LastIndexOf('$');
        if (dollar > 0 && !line.Substring(dollar).Contains('/'))
        {
            pattern = line.Substring(0, dollar);
            mods = line.Substring(dollar + 1);
        }

        var modInfo = ParseModifiers(mods);

        if (pattern.StartsWith("||") && (pattern.EndsWith("^") || pattern.EndsWith("^|")))
        {
            var domain = pattern.Substring(2, pattern.IndexOf('^') - 2);
            if (IsValidDomain(domain) && !modInfo.HasComplexFilters)
            {
                var rule = new DomainRule(domain, modInfo.ThirdPartyOnly);
                if (isException) _allowDomains[domain] = rule;
                else              _blockDomains[domain] = rule;
                return true;
            }
        }

        if (!pattern.Contains('/') && !pattern.Contains('*') && !pattern.Contains('|')
            && !pattern.Contains('^') && IsValidDomain(pattern))
        {
            var rule = new DomainRule(pattern, modInfo.ThirdPartyOnly);
            if (isException) _allowDomains[pattern] = rule;
            else              _blockDomains[pattern] = rule;
            return true;
        }

        var pr = new PatternRule(pattern, modInfo);
        if (isException) _allowPatterns.Add(pr);
        else              _blockPatterns.Add(pr);
        return true;
    }

    public bool IsBlocked(string url, string? initiatorHost = null, ResourceType resourceType = ResourceType.Unknown)
    {
        var (host, _, _) = ParseUrl(url);
        if (string.IsNullOrEmpty(host)) return false;

        bool isThirdParty = !string.IsNullOrEmpty(initiatorHost)
            && !IsSameSite(host, initiatorHost);

        if (DomainMatch(_allowDomains, host, isThirdParty)) return false;
        foreach (var pr in _allowPatterns)
            if (pr.Matches(url, host, initiatorHost, isThirdParty, resourceType)) return false;

        if (DomainMatch(_blockDomains, host, isThirdParty)) return true;
        foreach (var pr in _blockPatterns)
            if (pr.Matches(url, host, initiatorHost, isThirdParty, resourceType)) return true;

        return false;
    }

    private static bool DomainMatch(ConcurrentDictionary<string, DomainRule> map, string host, bool isThirdParty)
    {
        if (map.Count == 0) return false;
        var h = host.ToLowerInvariant();
        while (true)
        {
            if (map.TryGetValue(h, out var rule))
            {
                if (!rule.ThirdPartyOnly || isThirdParty) return true;
            }
            int dot = h.IndexOf('.');
            if (dot <= 0 || dot == h.Length - 1) break;
            h = h.Substring(dot + 1);
        }
        return false;
    }

    private static bool IsSameSite(string a, string b)
    {
        var la = a.Split('.');
        var lb = b.Split('.');
        if (la.Length < 2 || lb.Length < 2) return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        return string.Equals(la[^1], lb[^1], StringComparison.OrdinalIgnoreCase)
            && string.Equals(la[^2], lb[^2], StringComparison.OrdinalIgnoreCase);
    }

    private static (string Host, string Scheme, string Path) ParseUrl(string url)
    {
        if (string.IsNullOrEmpty(url)) return ("", "", "");
        if (Uri.TryCreate(url, UriKind.Absolute, out var u))
            return (u.Host, u.Scheme, u.AbsolutePath);

        return (url.Split('/')[0], "", "");
    }

    private static bool IsValidDomain(string s)
        => !string.IsNullOrEmpty(s) && s.Length <= 253 && s.Length > 3
           && s.Contains('.') && !s.Contains(' ')
           && Regex.IsMatch(s, @"^[a-zA-Z0-9._-]+$");

    private static Modifiers ParseModifiers(string mods)
    {
        var r = new Modifiers();
        if (string.IsNullOrEmpty(mods)) return r;
        foreach (var raw in mods.Split(','))
        {
            var t = raw.Trim();
            if (string.IsNullOrEmpty(t)) continue;
            if (t == "third-party")       r.ThirdPartyOnly = true;
            else if (t == "~third-party") r.FirstPartyOnly = true;
            else if (t == "important")    r.Important = true;
            else if (t.StartsWith("domain="))
            {
                foreach (var d in t.Substring(7).Split('|'))
                {
                    var dd = d.Trim();
                    if (string.IsNullOrEmpty(dd)) continue;
                    if (dd.StartsWith("~")) r.ExcludedInitiatorDomains.Add(dd.Substring(1));
                    else r.IncludedInitiatorDomains.Add(dd);
                }
            }
            else if (TypeFromString(t, out var rt, out var negated))
            {
                if (negated) r.ExcludedTypes |= rt;
                else r.IncludedTypes |= rt;
            }
            else
            {
                r.HasComplexFilters = true;
            }
        }
        return r;
    }

    private static bool TypeFromString(string s, out ResourceType type, out bool negated)
    {
        negated = false;
        type = ResourceType.Unknown;
        if (s.StartsWith("~")) { negated = true; s = s.Substring(1); }
        switch (s)
        {
            case "image":          type = ResourceType.Image; return true;
            case "script":         type = ResourceType.Script; return true;
            case "stylesheet":     type = ResourceType.Stylesheet; return true;
            case "xmlhttprequest":
            case "xhr":            type = ResourceType.Xhr; return true;
            case "subdocument":    type = ResourceType.SubFrame; return true;
            case "document":       type = ResourceType.MainFrame; return true;
            case "object":         type = ResourceType.Object; return true;
            case "media":          type = ResourceType.Media; return true;
            case "font":           type = ResourceType.Font; return true;
            case "websocket":      type = ResourceType.WebSocket; return true;
            case "ping":           type = ResourceType.Ping; return true;
            default: return false;
        }
    }

    public enum ResourceType
    {
        Unknown = 0, MainFrame = 1, SubFrame = 2, Script = 4, Stylesheet = 8,
        Image = 16, Font = 32, Media = 64, Object = 128, Xhr = 256,
        WebSocket = 512, Ping = 1024, Other = 2048,
    }

    private readonly struct DomainRule
    {
        public readonly string Domain;
        public readonly bool ThirdPartyOnly;
        public DomainRule(string d, bool tp) { Domain = d; ThirdPartyOnly = tp; }
    }

    private sealed class Modifiers
    {
        public bool ThirdPartyOnly;
        public bool FirstPartyOnly;
        public bool Important;
        public ResourceType IncludedTypes;
        public ResourceType ExcludedTypes;
        public List<string> IncludedInitiatorDomains = new();
        public List<string> ExcludedInitiatorDomains = new();
        public bool HasComplexFilters;
    }

    private sealed class PatternRule
    {
        public readonly string Pattern;
        public readonly Modifiers Mods;
        public readonly Regex? CompiledRegex;

        public PatternRule(string pattern, Modifiers mods)
        {
            Pattern = pattern; Mods = mods;
            try { CompiledRegex = new Regex(AdblockToRegex(pattern), RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50)); }
            catch { CompiledRegex = null; }
        }

        public bool Matches(string url, string host, string? initiatorHost, bool isThirdParty, ResourceType type)
        {
            if (Mods.ThirdPartyOnly && !isThirdParty) return false;
            if (Mods.FirstPartyOnly && isThirdParty)  return false;
            if (Mods.IncludedTypes != ResourceType.Unknown && (Mods.IncludedTypes & type) == 0) return false;
            if (Mods.ExcludedTypes != ResourceType.Unknown && (Mods.ExcludedTypes & type) != 0) return false;
            if (Mods.IncludedInitiatorDomains.Count > 0)
            {
                bool any = false;
                foreach (var d in Mods.IncludedInitiatorDomains)
                    if (initiatorHost != null && initiatorHost.EndsWith(d, StringComparison.OrdinalIgnoreCase)) { any = true; break; }
                if (!any) return false;
            }
            if (Mods.ExcludedInitiatorDomains.Count > 0 && initiatorHost != null)
                foreach (var d in Mods.ExcludedInitiatorDomains)
                    if (initiatorHost.EndsWith(d, StringComparison.OrdinalIgnoreCase)) return false;

            return CompiledRegex?.IsMatch(url) ?? false;
        }

        private static string AdblockToRegex(string p)
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < p.Length; i++)
            {
                char c = p[i];
                if (i == 0 && c == '|' && i + 1 < p.Length && p[i + 1] == '|') { sb.Append(@"^https?:\/\/([^/]+\.)?"); i++; continue; }
                if (i == 0 && c == '|') { sb.Append('^'); continue; }
                if (c == '|' && i == p.Length - 1) { sb.Append('$'); continue; }
                if (c == '^') { sb.Append(@"[/?&=#]"); continue; }
                if (c == '*') { sb.Append(".*"); continue; }
                if (".+?()[]{}\\".IndexOf(c) >= 0) { sb.Append('\\').Append(c); continue; }
                sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
