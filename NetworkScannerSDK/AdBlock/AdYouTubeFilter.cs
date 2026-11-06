using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.NetworkScanner.AdBlock;

public static class AdYouTubeFilter
{
    private static readonly string[] AdKeys =
    {
        "adPlacements", "adSlots", "playerAds", "adBreakHeartbeatParams",
        "adParams", "adServerResponse", "adSlotRenderer", "adSlotAndLayoutMetadata",
        "playerLegacyDesktopWatchAdsRenderer", "promotedSparklesWebRenderer",
        "promotedVideoRenderer", "displayAdRenderer", "inFeedAdLayoutRenderer",
        "instreamVideoAdRenderer", "adDurationRemaining", "importantForAds"
    };

    public static bool IsPlayerJson(string url) =>
        url.Contains("/youtubei/v1/player", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("/youtubei/v1/next", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("/youtubei/v1/browse", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("/youtubei/v1/search", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("/youtubei/v1/reel", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("/youtubei/v1/guide", StringComparison.OrdinalIgnoreCase) ||
        url.Contains("get_watch", StringComparison.OrdinalIgnoreCase);

    public static bool IsYouTubeHost(string host) =>
        host.EndsWith("youtube.com", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("youtube-nocookie.com", StringComparison.OrdinalIgnoreCase);

    public static (bool changed, string content) StripPlayerJson(string json)
    {
        try
        {
            var node = JsonNode.Parse(json);
            if (node == null) return (false, json);

            int removed = Strip(node, 0);
            if (removed == 0) return (false, json);
            return (true, node.ToJsonString(new JsonSerializerOptions { WriteIndented = false }));
        }
        catch
        {
            return (false, json);
        }
    }

    private static readonly string[] TrackingKeys = { "atrUrl", "adBreakServiceUrl" };

    private static readonly string[] AdItemKeys =
    {
        "adSlotRenderer", "displayAdRenderer", "promotedSparklesWebRenderer",
        "promotedSparklesTextSearchRenderer", "promotedVideoRenderer",
        "compactPromotedVideoRenderer", "compactPromotedItemRenderer",
        "inFeedAdLayoutRenderer", "searchPyvRenderer", "adSlotAndLayoutMetadata",
        "bannerPromoRenderer", "statementBannerRenderer", "adsEngagementPanelRenderer",
        "merchandiseShelfRenderer"
    };

    private static bool IsAdItem(JsonNode? node, int depth = 0)
    {
        if (node == null || depth > 2) return false;
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in AdItemKeys)
                    if (obj.ContainsKey(key)) return true;
                foreach (var kv in obj)
                    if (IsAdItem(kv.Value, depth + 1)) return true;
                return false;
            case JsonArray arr:
                foreach (var it in arr)
                    if (IsAdItem(it, depth + 1)) return true;
                return false;
            default:
                return false;
        }
    }

    private static int Strip(JsonNode? node, int depth)
    {
        if (node == null || depth > 24) return 0;
        int n = 0;
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in AdKeys)
                    if (obj.ContainsKey(key) && obj.Remove(key)) n++;
                if (obj["playbackTracking"] is JsonObject pt)
                    foreach (var k in TrackingKeys)
                        if (pt.ContainsKey(k) && pt.Remove(k)) n++;

                foreach (var kv in obj)
                    n += Strip(kv.Value, depth + 1);
                break;
            case JsonArray arr:

                for (int i = arr.Count - 1; i >= 0; i--)
                {
                    if (!IsAdItem(arr[i])) continue;
                    arr.RemoveAt(i);
                    n++;
                }
                for (int i = 0; i < arr.Count; i++)
                    n += Strip(arr[i], depth + 1);
                break;
        }
        return n;
    }

    private static readonly string[] InlineVars =
    {
        "ytInitialPlayerResponse", "ytInitialData", "ytInitialReelWatchSequenceResponse"
    };

    public static (bool changed, string content) StripHtml(string html)
    {
        bool changed = false;
        foreach (var varName in InlineVars)
        {
            int from = 0;
            int idx;
            while ((idx = html.IndexOf(varName, from, StringComparison.Ordinal)) >= 0)
            {

                int p = idx + varName.Length;
                while (p < html.Length && (html[p] is ' ' or '\t' or '"' or '\'' or ']')) p++;
                if (p >= html.Length || html[p] != '=') { from = idx + varName.Length; continue; }
                p++;
                while (p < html.Length && html[p] is ' ' or '\t') p++;
                if (p >= html.Length || html[p] != '{') { from = idx + varName.Length; continue; }

                int end = SkipJsonValue(html, p);
                if (end <= p) { from = idx + varName.Length; continue; }

                var slice = html[p..end];
                string replacement;
                try
                {
                    var node = JsonNode.Parse(slice);
                    if (node == null || Strip(node, 0) == 0) { from = end; continue; }

                    replacement = node.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
                }
                catch
                {
                    from = end;
                    continue;
                }

                html = html[..p] + replacement + html[end..];
                changed = true;
                from = p + replacement.Length;
            }
        }
        return (changed, html);
    }

    private static int SkipJsonValue(string s, int i)
    {
        if (i >= s.Length) return i;
        char c = s[i];
        if (c == '[' || c == '{')
        {
            char open = c, close = c == '[' ? ']' : '}';
            int depth = 0; bool inStr = false; bool esc = false;
            for (; i < s.Length; i++)
            {
                char ch = s[i];
                if (inStr) { if (esc) esc = false; else if (ch == '\\') esc = true; else if (ch == '"') inStr = false; continue; }
                if (ch == '"') inStr = true;
                else if (ch == open) depth++;
                else if (ch == close) { depth--; if (depth == 0) return i + 1; }
            }
            return i;
        }
        if (c == '"')
        {

            bool esc = false;
            for (i++; i < s.Length; i++)
            {
                if (esc) { esc = false; continue; }
                if (s[i] == '\\') esc = true;
                else if (s[i] == '"') return i + 1;
            }
            return i;
        }

        for (; i < s.Length; i++)
            if (s[i] is ',' or '}' or ']') return i;
        return i;
    }
}
