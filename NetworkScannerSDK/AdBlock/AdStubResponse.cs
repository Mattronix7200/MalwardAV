using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public static class AdStubResponse
{
    public const string AdMarker = "X-Malward-AdBlock: 1\r\n";
    public const string ThreatMarker = "X-Malward-Block: 1\r\n";

    private static readonly byte[] EmptyGif = Convert.FromBase64String(
        "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");

    public static async Task WriteAsync(Stream client, AdResourceType type, string? redirect,
                                        string url, string marker, CancellationToken ct)
    {
        var resource = AdRedirects.Get(redirect) ?? AdRedirects.GuessByUrl(url);
        if (resource != null)
        {
            await SendAsync(client, resource.ContentType, resource.Body, marker, ct);
            return;
        }

        var (contentType, body) = Neutral(type);
        await SendAsync(client, contentType, body, marker, ct);
    }

    public static Task WriteNeutralAsync(Stream client, AdResourceType type, string marker,
                                         CancellationToken ct)
    {
        var (contentType, body) = Neutral(type);
        return SendAsync(client, contentType, body, marker, ct);
    }

    public static async Task<bool> TryWriteSubresourceAsync(Stream client, string rawHeaders, string host,
                                                            string marker, CancellationToken ct)
    {
        var dest = HeaderValue(rawHeaders, "Sec-Fetch-Dest");
        if (dest == null || IsNavigationDest(dest)) return false;

        int lineEnd = rawHeaders.IndexOf('\n');
        var firstLine = (lineEnd < 0 ? rawHeaders : rawHeaders[..lineEnd]).Trim();
        var parts = firstLine.Split(' ');
        var method = parts.Length > 0 ? parts[0] : "GET";
        var target = parts.Length > 1 ? parts[1] : "/";

        var type = AdResourceTypes.FromRequest(dest, "https://" + host + PathOf(target),
                                               HeaderValue(rawHeaders, "Accept"),
                                               HeaderValue(rawHeaders, "Upgrade"), method);
        await WriteNeutralAsync(client, type, marker, ct);
        return true;
    }

    public static bool IsNavigationDest(string dest)
    {
        var d = dest.Trim();
        return d.Length == 0
               || d.Equals("document", StringComparison.OrdinalIgnoreCase)
               || d.Equals("iframe", StringComparison.OrdinalIgnoreCase)
               || d.Equals("frame", StringComparison.OrdinalIgnoreCase);
    }

    public static string? HeaderValue(string headers, string name)
    {
        foreach (var line in headers.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > name.Length && trimmed[name.Length] == ':'
                && trimmed.StartsWith(name, StringComparison.OrdinalIgnoreCase))
                return trimmed[(name.Length + 1)..].Trim();
        }
        return null;
    }

    private static string PathOf(string target)
    {
        int scheme = target.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int slash = target.IndexOf('/', scheme + 3);
            return slash < 0 ? "/" : target[slash..];
        }
        if (target.Length == 0) return "/";
        return target[0] == '/' ? target : "/" + target;
    }

    public static (string ContentType, byte[] Body) Neutral(AdResourceType type) => type switch
    {
        AdResourceType.Image => ("image/gif", EmptyGif),
        AdResourceType.Script => ("application/javascript", Array.Empty<byte>()),
        AdResourceType.Stylesheet => ("text/css", Array.Empty<byte>()),
        AdResourceType.XmlHttpRequest => ("application/json", Encoding.ASCII.GetBytes("{}")),
        AdResourceType.Document => ("text/html; charset=utf-8",
                                    Encoding.UTF8.GetBytes("<!doctype html><title></title>")),
        _ => ("text/plain", Array.Empty<byte>()),
    };

    private static async Task SendAsync(Stream client, string contentType, byte[] body,
                                        string marker, CancellationToken ct)
    {
        var head = "HTTP/1.1 200 OK\r\n"
                   + $"Content-Type: {contentType}\r\n"
                   + $"Content-Length: {body.Length}\r\n"
                   + "Cache-Control: no-store\r\n"
                   + marker
                   + "\r\n";
        await client.WriteAsync(Encoding.ASCII.GetBytes(head), ct);
        if (body.Length > 0) await client.WriteAsync(body, ct);
        await client.FlushAsync(ct);
    }
}
