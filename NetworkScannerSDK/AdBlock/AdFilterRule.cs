using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace Malward.NetworkScanner.AdBlock;

public sealed class AdFilterRule
{
    public bool IsException;
    public Regex Pattern = null!;
    public string Token = "";
    public AdResourceType Types = AdResourceType.All;
    public AdResourceType ExcludedTypes = AdResourceType.None;
    public int ThirdParty;
    public HashSet<string>? DomainsInclude;
    public HashSet<string>? DomainsExclude;
    public bool PopupOnly;
    public bool RedirectOnly;
    public string? Redirect;
    public string Raw = "";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    private static readonly string[] Unsupported =
    {
        "$replace=", "$csp", "$removeparam", "$app=", "$method=",
        "$header=", "$hls=", "$jsonprune=", "$permissions=", "$urltransform",
    };

    public static AdFilterRule? Parse(string line)
    {
        try
        {
            var s = line.Trim();
            if (s.Length == 0) return null;
            foreach (var u in Unsupported)
                if (s.Contains(u, StringComparison.Ordinal)) return null;

            bool exception = false;
            if (s.StartsWith("@@", StringComparison.Ordinal)) { exception = true; s = s[2..]; }

            string pattern = s;
            string? options = null;
            int dollar = FindOptionSeparator(s);
            if (dollar >= 0) { pattern = s[..dollar]; options = s[(dollar + 1)..]; }

            if (pattern.Length == 0) return null;

            var rule = new AdFilterRule { IsException = exception, Raw = line };
            if (!string.IsNullOrEmpty(options) && !rule.ApplyOptions(options)) return null;

            rule.Pattern = BuildRegex(pattern, out var token);
            rule.Token = token;
            return rule;
        }
        catch { return null; }
    }

    private static int FindOptionSeparator(string s)
    {
        if (s.StartsWith("/", StringComparison.Ordinal))
        {
            int close = s.LastIndexOf('/');
            if (close > 0)
                return close + 1 < s.Length && s[close + 1] == '$' ? close + 1 : -1;
        }
        return s.IndexOf('$');
    }

    private bool ApplyOptions(string options)
    {
        foreach (var optRaw in options.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var opt = optRaw.Trim();
            bool neg = opt.StartsWith("~", StringComparison.Ordinal);
            var name = neg ? opt[1..] : opt;

            if (name.StartsWith("redirect=", StringComparison.Ordinal)
                || name.StartsWith("redirect-rule=", StringComparison.Ordinal)
                || name.StartsWith("rewrite=", StringComparison.Ordinal))
            {
                int eq = name.IndexOf('=');
                var res = eq >= 0 && eq + 1 < name.Length ? name[(eq + 1)..].Trim() : "";
                if (res.Length > 0) Redirect = res;
                if (name.StartsWith("redirect-rule=", StringComparison.Ordinal)) RedirectOnly = true;
                continue;
            }

            if (name.StartsWith("domain=", StringComparison.Ordinal))
            {
                foreach (var d in name[7..].Split('|', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (d.StartsWith("~", StringComparison.Ordinal))
                        (DomainsExclude ??= new(StringComparer.OrdinalIgnoreCase)).Add(d[1..]);
                    else
                        (DomainsInclude ??= new(StringComparer.OrdinalIgnoreCase)).Add(d);
                }
                continue;
            }

            var t = name switch
            {
                "script" => AdResourceType.Script,
                "image" => AdResourceType.Image,
                "stylesheet" or "css" => AdResourceType.Stylesheet,
                "xmlhttprequest" or "xhr" => AdResourceType.XmlHttpRequest,
                "font" => AdResourceType.Font,
                "media" => AdResourceType.Media,
                "websocket" => AdResourceType.WebSocket,
                "subdocument" or "frame" => AdResourceType.Document,
                "document" or "doc" => AdResourceType.Document,
                "ping" or "beacon" => AdResourceType.Ping,
                "other" => AdResourceType.Other,
                _ => AdResourceType.None,
            };

            if (t != AdResourceType.None)
            {
                if (neg) ExcludedTypes |= t;
                else
                {
                    if (Types == AdResourceType.All) Types = AdResourceType.None;
                    Types |= t;
                }
                continue;
            }

            switch (name)
            {
                case "third-party":
                case "3p": ThirdParty = neg ? -1 : 1; break;
                case "first-party":
                case "1p": ThirdParty = neg ? 1 : -1; break;

                case "elemhide":
                case "ehide":
                case "generichide":
                case "ghide":
                case "specifichide":
                case "shide":
                case "genericblock":
                    return false;

                case "popup": PopupOnly = true; break;

                case "important":
                case "all":
                case "match-case":
                case "cname":
                    break;

                default: return false;
            }
        }
        return true;
    }

    private static Regex BuildRegex(string pattern, out string token)
    {
        if (pattern.Length > 2 && pattern[0] == '/' && pattern[^1] == '/')
        {
            token = "";
            return new Regex(pattern[1..^1],
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
        }

        var sb = new StringBuilder(pattern.Length + 24);
        int i = 0;
        if (pattern.StartsWith("||", StringComparison.Ordinal))
        {
            sb.Append(@"^[a-z]+://([^/]*\.)?");
            i = 2;
        }
        else if (pattern.StartsWith("|", StringComparison.Ordinal))
        {
            sb.Append('^');
            i = 1;
        }

        int end = pattern.Length;
        bool anchorEnd = pattern.EndsWith("|", StringComparison.Ordinal)
                         && !pattern.EndsWith("\\|", StringComparison.Ordinal);
        if (anchorEnd) end--;

        var tokenBuf = new StringBuilder();
        string bestToken = "";
        void FlushToken()
        {
            if (tokenBuf.Length > bestToken.Length) bestToken = tokenBuf.ToString();
            tokenBuf.Clear();
        }

        for (; i < end; i++)
        {
            char c = pattern[i];
            switch (c)
            {
                case '*': sb.Append(".*"); FlushToken(); break;
                case '^': sb.Append(@"(?:[^a-z0-9._%-]|$)"); FlushToken(); break;
                case '|': sb.Append("\\|"); FlushToken(); break;
                default:
                    if (char.IsLetterOrDigit(c)) { tokenBuf.Append(char.ToLowerInvariant(c)); sb.Append(c); }
                    else { FlushToken(); sb.Append(Regex.Escape(c.ToString())); }
                    break;
            }
        }
        FlushToken();
        if (anchorEnd) sb.Append('$');

        token = bestToken.Length >= 3 ? bestToken : "";
        return new Regex(sb.ToString(),
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    }

    public bool Matches(string url, string requestHost, string? docHost, AdResourceType type)
    {
        if (PopupOnly && type != AdResourceType.Document && type != AdResourceType.All) return false;

        if ((Types & type) == 0 && Types != AdResourceType.All) return false;
        if ((ExcludedTypes & type) != 0) return false;

        if (ThirdParty != 0 && docHost != null)
        {
            bool third = !SameSite(requestHost, docHost);
            if (ThirdParty == 1 && !third) return false;
            if (ThirdParty == -1 && third) return false;
        }

        if (DomainsInclude != null || DomainsExclude != null)
        {
            var h = docHost ?? requestHost;
            if (DomainsExclude != null && DomainMatches(h, DomainsExclude)) return false;
            if (DomainsInclude != null && !DomainMatches(h, DomainsInclude)) return false;
        }

        try { return Pattern.IsMatch(url); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static bool DomainMatches(string host, HashSet<string> set)
    {
        var cur = host;
        while (true)
        {
            if (set.Contains(cur)) return true;
            int dot = cur.IndexOf('.');
            if (dot < 0) return false;
            cur = cur[(dot + 1)..];
        }
    }

    public static bool SameSite(string a, string b) =>
        string.Equals(RegistrableDomain(a), RegistrableDomain(b), StringComparison.OrdinalIgnoreCase);

    private static readonly ConcurrentDictionary<string, string> RegistrableCache = new();

    public static string RegistrableDomain(string host)
    {
        if (RegistrableCache.TryGetValue(host, out var cached)) return cached;
        var result = RegistrableDomainRaw(host);
        if (RegistrableCache.Count > 8000) RegistrableCache.Clear();
        RegistrableCache[host] = result;
        return result;
    }

    private static string RegistrableDomainRaw(string host)
    {
        var parts = host.Split('.');
        if (parts.Length <= 2) return host;
        string last2 = parts[^2] + "." + parts[^1];
        if (TwoLevelTlds.Contains(last2) && parts.Length >= 3)
            return parts[^3] + "." + last2;
        return last2;
    }

    private static readonly HashSet<string> TwoLevelTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.pl", "net.pl", "org.pl", "com.au", "net.au",
        "co.jp", "com.br", "com.tr", "co.in", "com.cn", "com.mx", "co.nz", "co.za",
    };
}
