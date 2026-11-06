using System.Text.RegularExpressions;

namespace Malward.NetworkScanner.AdBlock;

public sealed class AdReplaceRule
{
    public AdFilterRule Matcher { get; private init; } = null!;
    public Regex? Pattern { get; private init; }
    public string Replacement { get; private init; } = "";

    public bool IsException { get; private init; }
    public string Raw { get; private init; } = "";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

    public static bool LooksLikeReplace(string line) => FindOption(line) > 0;

    private static int FindOption(string line)
    {
        int from = 0;
        while (true)
        {
            int i = line.IndexOf("replace", from, StringComparison.OrdinalIgnoreCase);
            if (i <= 0) return -1;
            int after = i + "replace".Length;
            bool okBefore = line[i - 1] is '$' or ',';
            bool okAfter = after >= line.Length || line[after] is '=' or ',';
            if (okBefore && okAfter) return i;
            from = i + 1;
        }
    }

    public static AdReplaceRule? Parse(string line)
    {
        line = line.Trim();
        if (line.Length == 0) return null;
        bool exception = line.StartsWith("@@", StringComparison.Ordinal);

        int at = FindOption(line);
        if (at <= 0) return null;

        int eq = at + "replace".Length;
        int valStart = (eq < line.Length && line[eq] == '=') ? eq + 1 : eq;

        if (valStart >= line.Length || line[valStart] != '/')
        {
            if (!exception) return null;
            var m0 = BuildMatcher(line, at, valStart >= line.Length ? line.Length : valStart);
            return m0 == null ? null : new AdReplaceRule { Matcher = m0, IsException = true, Raw = line };
        }

        int p1 = FindDelim(line, valStart + 1);
        if (p1 < 0) return null;
        int p2 = FindDelim(line, p1 + 1);
        if (p2 < 0) return null;

        var pattern = Unescape(line[(valStart + 1)..p1]);
        var replacement = Unescape(line[(p1 + 1)..p2]);

        int flagsEnd = p2 + 1;
        while (flagsEnd < line.Length && line[flagsEnd] != ',') flagsEnd++;
        var flags = line[(p2 + 1)..flagsEnd];

        var opts = RegexOptions.CultureInvariant;
        foreach (var f in flags)
            switch (f)
            {
                case 'i': opts |= RegexOptions.IgnoreCase; break;
                case 's': opts |= RegexOptions.Singleline; break;
                case 'm': opts |= RegexOptions.Multiline; break;
                case 'g': break;
            }

        Regex re;
        try { re = new Regex(pattern, opts, RegexTimeout); }
        catch { return null; }

        var matcher = BuildMatcher(line, at, flagsEnd);
        if (matcher == null) return null;

        return new AdReplaceRule
        {
            Matcher = matcher,
            Pattern = re,
            Replacement = replacement,
            IsException = exception,
            Raw = line
        };
    }

    private static AdFilterRule? BuildMatcher(string line, int optStart, int optEnd)
    {

        int cut = optStart - 1;
        string rest = optEnd < line.Length ? line[optEnd..] : "";
        if (rest.StartsWith(",", StringComparison.Ordinal)) rest = rest[1..];

        string text;
        if (line[cut] == '$')
            text = rest.Length > 0 ? line[..cut] + "$" + rest : line[..cut];
        else
            text = line[..cut] + (rest.Length > 0 ? "," + rest : "");

        return AdFilterRule.Parse(text);
    }

    private static int FindDelim(string s, int from)
    {
        for (int i = from; i < s.Length; i++)
        {
            if (s[i] == '\\') { i++; continue; }
            if (s[i] == '/') return i;
        }
        return -1;
    }

    private static string Unescape(string s) =>
        s.Replace("\\,", ",").Replace("\\$", "$").Replace("\\/", "/");

    public string Apply(string body)
    {
        if (Pattern == null) return body;
        try { return Pattern.Replace(body, Replacement); }
        catch (RegexMatchTimeoutException)
        {
            Log.Warn("AdBlock", "$replace rule timed out: " + Raw[..Math.Min(80, Raw.Length)]);
            return body;
        }
        catch { return body; }
    }
}
