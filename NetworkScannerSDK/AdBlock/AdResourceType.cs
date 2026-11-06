namespace Malward.NetworkScanner.AdBlock;

[Flags]
public enum AdResourceType
{
    None = 0,
    Document = 1 << 0,
    Script = 1 << 1,
    Image = 1 << 2,
    Stylesheet = 1 << 3,
    XmlHttpRequest = 1 << 4,
    Font = 1 << 5,
    Media = 1 << 6,
    WebSocket = 1 << 7,
    Ping = 1 << 8,
    Other = 1 << 9,
    All = ~0,
}

public static class AdResourceTypes
{
    public static AdResourceType FromRequest(string? secFetchDest, string url, string? accept)
        => FromRequest(secFetchDest, url, accept, null, null);

    public static AdResourceType FromRequest(string? secFetchDest, string url, string? accept,
                                             string? upgrade, string? method)
    {
        if (!string.IsNullOrEmpty(upgrade)
            && upgrade.Contains("websocket", StringComparison.OrdinalIgnoreCase))
            return AdResourceType.WebSocket;
        if (url.StartsWith("ws://", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
            return AdResourceType.WebSocket;

        var dest = secFetchDest?.Trim().ToLowerInvariant();
        switch (dest)
        {
            case "websocket": return AdResourceType.WebSocket;
            case "ping":
            case "report": return AdResourceType.Ping;
            case "script": return AdResourceType.Script;
            case "style": return AdResourceType.Stylesheet;
            case "image": return AdResourceType.Image;
            case "font": return AdResourceType.Font;
            case "document":
            case "iframe":
            case "frame": return AdResourceType.Document;
            case "audio":
            case "video": return AdResourceType.Media;
            case "empty": return AdResourceType.XmlHttpRequest;
        }

        if (!string.IsNullOrEmpty(accept))
        {
            var a = accept.ToLowerInvariant();
            if (a.StartsWith("image/")) return AdResourceType.Image;
            if (a.StartsWith("text/css")) return AdResourceType.Stylesheet;
            if (a.Contains("javascript")) return AdResourceType.Script;
        }

        var path = url;
        int q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".js" or ".mjs" => AdResourceType.Script,
            ".css" => AdResourceType.Stylesheet,
            ".png" or ".jpg" or ".jpeg" or ".gif" or ".webp" or ".svg" or ".ico" or ".bmp"
                => AdResourceType.Image,
            ".woff" or ".woff2" or ".ttf" or ".otf" or ".eot" => AdResourceType.Font,
            ".mp4" or ".webm" or ".mp3" or ".m4a" or ".ts" or ".m3u8" => AdResourceType.Media,
            ".html" or ".htm" or "" => AdResourceType.Document,
            _ => AdResourceType.Other,
        };
    }
}
