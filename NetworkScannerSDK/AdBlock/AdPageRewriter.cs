using System.IO.Compression;
using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public sealed class AdCosmeticOptions
{
    public bool Cosmetic = true;
    public bool CosmeticGeneric = true;
    public bool CollapseGaps = true;
    public bool Scriptlets = true;
    public bool YouTube = true;
    public bool Stealth = true;
    public AdPrivacy.Options Privacy = new();
}

public sealed class AdRewriteResult
{
    public bool Changed;
    public string Html = "";
    public int Scriptlets;
    public int ProceduralSelectors;
    public int CosmeticSelectors;
    public bool YouTubeStripped;
}

public static class AdPageRewriter
{
    public const string GenericCssHost = "cosmetic.malward.invalid";
    public const string GenericCssUrl = "https://" + GenericCssHost + "/generic.css";

    public const int MaxBodyBytes = 8 * 1024 * 1024;

    private static readonly string[] CspDirectivesToDrop =
    {
        "script-src", "script-src-elem", "script-src-attr", "default-src",
        "style-src", "style-src-elem", "style-src-attr", "require-trusted-types-for",
        "trusted-types", "sandbox", "report-uri", "report-to",
    };

    public static bool LooksLikeHtml(AdHttpMessage response)
    {
        var ct = response.Get("Content-Type");
        return ct != null && ct.Contains("text/html", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeJson(AdHttpMessage response)
    {
        var ct = response.Get("Content-Type");
        return ct != null
               && (ct.Contains("application/json", StringComparison.OrdinalIgnoreCase)
                   || ct.Contains("text/json", StringComparison.OrdinalIgnoreCase));
    }

    public static string? Decode(byte[] body, string? contentEncoding)
    {
        try
        {
            var enc = contentEncoding?.Trim().ToLowerInvariant();
            byte[] raw;
            if (string.IsNullOrEmpty(enc) || enc == "identity") raw = body;
            else if (enc == "gzip") raw = Inflate(body, s => new GZipStream(s, CompressionMode.Decompress));
            else if (enc == "deflate") raw = Inflate(body, s => new DeflateStream(s, CompressionMode.Decompress));
            else if (enc == "br") raw = Inflate(body, s => new BrotliStream(s, CompressionMode.Decompress));
            else return null;

            return DecodeText(raw);
        }
        catch { return null; }
    }

    private static byte[] Inflate(byte[] body, Func<Stream, Stream> wrap)
    {
        using var input = new MemoryStream(body);
        using var stream = wrap(input);
        using var output = new MemoryStream(body.Length * 4);
        stream.CopyTo(output, 1 << 16);
        return output.ToArray();
    }

    private static string DecodeText(byte[] raw)
    {
        if (raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
            return Encoding.UTF8.GetString(raw, 3, raw.Length - 3);
        return Encoding.UTF8.GetString(raw);
    }

    public static AdRewriteResult Rewrite(string html, string host, AdRuleStore store,
                                          AdCosmeticOptions options)
    {
        var result = new AdRewriteResult { Html = html };

        if (options.YouTube && AdYouTubeFilter.IsYouTubeHost(host))
        {
            var (changed, stripped) = AdYouTubeFilter.StripHtml(result.Html);
            if (changed)
            {
                result.Html = stripped;
                result.Changed = true;
                result.YouTubeStripped = true;
            }
        }

        var flags = store.GetHideFlags(host);
        bool noCosmetic = flags.Contains('e');

        if (options.Scriptlets)
        {
            var specs = store.GetScriptlets(host);
            var procedural = options.Cosmetic && !noCosmetic
                ? store.GetProceduralSelectors(host)
                : new List<string>();

            if (specs.Count > 0 || procedural.Count > 0)
            {
                var inject = AdScriptlet.BuildInjection(specs, procedural);

                if (options.Stealth)
                {
                    var api = AdPrivacy.ApiBlockScript(options.Privacy.BlockPush,
                                                       options.Privacy.BlockGeolocation);
                    if (api.Length > 0)
                        inject = inject.Replace("<script id=\"adblocker-scriptlet\">",
                                                "<script id=\"adblocker-scriptlet\">" + api);
                }

                int top = HeadInsertPos(result.Html);
                var body = result.Html;
                StripMetaCsp(ref body, ref top);
                result.Html = body[..top] + inject + body[top..];
                result.Changed = true;
                result.Scriptlets = specs.Count;
                result.ProceduralSelectors = procedural.Count;
            }
        }

        if (options.Cosmetic && !noCosmetic)
        {
            var (generic, specific) = store.GetHidingCssSplit(host);
            if (!options.CosmeticGeneric || flags.Contains('g')) generic = "";
            if (flags.Contains('s')) specific = "";

            var link = generic.Length > 0
                ? "<link rel=\"stylesheet\" href=\"" + GenericCssUrl + "\">"
                : "";
            var style = specific.Length > 0
                ? "<style id=\"malward-cosmetic\">" + specific + "</style>"
                : "";

            if (link.Length > 0 || style.Length > 0)
            {
                var collapse = options.CollapseGaps && specific.Length > 0
                    ? AdCollapse.Script() : "";
                int idx = result.Html.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) idx = result.Html.IndexOf("<body", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) idx = result.Html.Length;
                result.Html = result.Html[..idx] + link + style + collapse + result.Html[idx..];
                result.Changed = true;

                int selectors = 0;
                foreach (var ch in specific)
                    if (ch is ',' or '{') selectors++;
                result.CosmeticSelectors = selectors;
            }
        }

        return result;
    }

    public static void PrepareRewrittenHeaders(AdHttpMessage response, int length)
    {
        RelaxCsp(response);
        Remove(response, "Content-Encoding");
        Remove(response, "Transfer-Encoding");
        Remove(response, "ETag");
        Remove(response, "Last-Modified");
        Remove(response, "Expires");
        Remove(response, "Cache-Control");
        Remove(response, "Pragma");
        Remove(response, "Content-Length");
        response.Headers.Add(new KeyValuePair<string, string>(
            "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"));
        response.Headers.Add(new KeyValuePair<string, string>("Pragma", "no-cache"));
        response.Headers.Add(new KeyValuePair<string, string>(
            "Content-Length", length.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    public static void Remove(AdHttpMessage message, string name)
        => message.Headers.RemoveAll(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase));

    public static void RelaxCsp(AdHttpMessage response)
    {
        foreach (var name in new[] { "Content-Security-Policy", "Content-Security-Policy-Report-Only" })
        {
            var values = response.Headers
                .Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
                .Select(h => h.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .ToList();
            if (values.Count == 0) continue;

            var policies = new List<string>();
            foreach (var value in values)
            foreach (var policy in value.Split(','))
            {
                var kept = new List<string>();
                foreach (var part in policy.Split(';'))
                {
                    var d = part.Trim();
                    if (d.Length == 0) continue;
                    int sp = d.IndexOf(' ');
                    var directive = (sp < 0 ? d : d[..sp]).ToLowerInvariant();
                    if (Array.IndexOf(CspDirectivesToDrop, directive) >= 0) continue;
                    kept.Add(d);
                }
                if (kept.Count > 0) policies.Add(string.Join("; ", kept));
            }

            Remove(response, name);
            foreach (var p in policies)
                response.Headers.Add(new KeyValuePair<string, string>(name, p));
        }
    }

    public static int StripMetaCsp(ref string html, ref int insertPos)
    {
        int removed = 0, from = 0;
        while (true)
        {
            int m = html.IndexOf("<meta", from, StringComparison.OrdinalIgnoreCase);
            if (m < 0) break;
            int end = html.IndexOf('>', m);
            if (end < 0) break;
            var tag = html[m..(end + 1)];
            if (tag.Contains("content-security-policy", StringComparison.OrdinalIgnoreCase)
                && !tag.Contains("upgrade-insecure-requests", StringComparison.OrdinalIgnoreCase))
            {
                html = html.Remove(m, end - m + 1);
                if (insertPos > m) insertPos = Math.Max(m, insertPos - (end - m + 1));
                removed++;
                from = m;
            }
            else from = end + 1;
        }
        return removed;
    }

    public static int HeadInsertPos(string html)
    {
        int start = 0;
        int h = html.IndexOf("<head", StringComparison.OrdinalIgnoreCase);
        if (h >= 0)
        {
            int gt = html.IndexOf('>', h);
            if (gt >= 0) start = gt + 1;
        }
        else
        {
            int htmlTag = html.IndexOf("<html", StringComparison.OrdinalIgnoreCase);
            if (htmlTag >= 0)
            {
                int gt = html.IndexOf('>', htmlTag);
                if (gt >= 0) start = gt + 1;
            }
        }

        int scanLimit = Math.Min(html.Length, start + 1024);
        int endPos = start;
        int p = start;
        while (p < scanLimit)
        {
            int m = html.IndexOf("<meta", p, scanLimit - p, StringComparison.OrdinalIgnoreCase);
            if (m < 0) break;
            int gt = html.IndexOf('>', m);
            if (gt < 0) break;
            if (html[m..(gt + 1)].Contains("charset", StringComparison.OrdinalIgnoreCase))
                endPos = gt + 1;
            p = gt + 1;
        }
        return endPos;
    }
}
