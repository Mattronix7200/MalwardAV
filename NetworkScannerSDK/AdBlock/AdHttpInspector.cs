using System.Text;

namespace Malward.NetworkScanner.AdBlock;

public sealed class AdHttpInspector
{
    private readonly AdBlockService _adBlock;
    private readonly Action<string, string, AdBlockVerdict>? _onBlocked;
    private readonly Func<string, string?, string, Stream, CancellationToken, Task<bool>>? _pathGuard;
    private readonly Action? _onPageRewritten;

    public AdHttpInspector(AdBlockService adBlock,
                           Action<string, string, AdBlockVerdict>? onBlocked = null,
                           Func<string, string?, string, Stream, CancellationToken, Task<bool>>? pathGuard = null,
                           Action? onPageRewritten = null)
    {
        _adBlock = adBlock;
        _onBlocked = onBlocked;
        _pathGuard = pathGuard;
        _onPageRewritten = onPageRewritten;
    }

    public async Task RunAsync(Stream client, Stream upstream, string host, bool secure,
                               CancellationToken ct, string? firstHead = null)
    {
        var fromClient = new AdHttpReader(client);
        var fromUpstream = new AdHttpReader(upstream);
        string scheme = secure ? "https" : "http";
        var pending = firstHead;

        while (!ct.IsCancellationRequested)
        {
            string? head;
            if (pending != null) { head = pending; pending = null; }
            else head = await fromClient.ReadHeadAsync(ct);
            if (head == null) return;

            var request = AdHttpMessage.ParseRequest(head);
            if (request == null) return;

            string url = BuildUrl(scheme, host, request);
            string? docHost = DocumentHost(request);
            var type = AdResourceTypes.FromRequest(request.Get("Sec-Fetch-Dest"), url,
                request.Get("Accept"), request.Get("Upgrade"), request.Method);

            if (HostOnly(host).Equals(AdPageRewriter.GenericCssHost, StringComparison.OrdinalIgnoreCase))
            {
                if (!await DrainBodyAsync(fromClient, request, ct)) return;
                await WriteGenericCssAsync(client, ct);
                if (request.WantsClose()) return;
                continue;
            }

            if (_pathGuard != null
                && await _pathGuard(HostOnly(host), PathOf(request), head, client, ct)) return;

            var verdict = _adBlock.Decide(url, HostOnly(host), docHost, type);
            if (verdict.Blocked)
            {
                if (!await DrainBodyAsync(fromClient, request, ct)) return;
                _onBlocked?.Invoke(HostOnly(host), url, verdict);
                await WriteStubAsync(client, type, verdict.Redirect, url, ct);
                if (request.WantsClose()) return;
                continue;
            }

            ApplyRequestPrivacy(request, HostOnly(host), docHost);
            LimitAcceptEncoding(request);

            await upstream.WriteAsync(request.Serialize(), ct);
            if (!await ForwardBodyAsync(fromClient, upstream, request, ct)) return;
            await upstream.FlushAsync(ct);

            var responseHead = await fromUpstream.ReadHeadAsync(ct);
            if (responseHead == null) return;

            var response = AdHttpMessage.ParseResponse(responseHead);
            if (response == null) return;

            bool noBody = response.StatusCode is 204 or 304
                          || (response.StatusCode >= 100 && response.StatusCode < 200)
                          || request.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase);

            if (!noBody && response.StatusCode is >= 200 and < 300
                && WantsRewrite(request, response, url, HostOnly(host), docHost, type))
            {
                var handled = await RewriteBodyAsync(fromUpstream, client, request, response,
                                                     url, HostOnly(host), docHost, type, ct);
                if (handled == RewriteOutcome.Failed) return;
                if (handled == RewriteOutcome.Done)
                {
                    await client.FlushAsync(ct);
                    if (response.WantsClose() || request.WantsClose()) return;
                    continue;
                }
            }

            await client.WriteAsync(response.Serialize(), ct);

            if (response.StatusCode == 101)
            {
                await PumpBothAsync(fromClient, client, fromUpstream, upstream, ct);
                return;
            }

            if (!noBody)
            {
                if (response.IsChunked())
                {
                    if (!await fromUpstream.CopyChunkedAsync(client, ct)) return;
                }
                else
                {
                    long len = response.ContentLength();
                    if (len >= 0)
                    {
                        if (!await fromUpstream.CopyExactAsync(client, len, ct)) return;
                    }
                    else
                    {
                        await fromUpstream.CopyRestAsync(client, ct);
                        return;
                    }
                }
            }

            await client.FlushAsync(ct);
            if (response.WantsClose() || request.WantsClose()) return;
        }
    }

    private enum RewriteOutcome { Done, Passthrough, Failed }

    private bool WantsRewrite(AdHttpMessage request, AdHttpMessage response, string url,
                              string host, string? docHost, AdResourceType type)
    {
        var o = _adBlock.Cosmetics;
        if (_adBlock.Store is not { IsLoaded: true }) return false;
        if (AdCaptcha.IsChallenge(url, host)) return false;

        if (AdPageRewriter.LooksLikeHtml(response))
        {
            if (!o.Cosmetic && !o.Scriptlets && !o.YouTube) return false;
            var dest = request.Get("Sec-Fetch-Dest");
            if (dest != null && dest is not ("document" or "iframe" or "frame" or "empty"))
                return false;
            return true;
        }

        if (o.YouTube && AdYouTubeFilter.IsYouTubeHost(host) && AdYouTubeFilter.IsPlayerJson(url))
            return true;

        return _adBlock.ReplaceRulesFor(url, host, docHost, type).Count > 0;
    }

    private async Task<RewriteOutcome> RewriteBodyAsync(AdHttpReader fromUpstream, Stream client,
        AdHttpMessage request, AdHttpMessage response, string url, string host, string? docHost,
        AdResourceType type, CancellationToken ct)
    {
        long declared = response.ContentLength();
        if (declared > AdPageRewriter.MaxBodyBytes) return RewriteOutcome.Passthrough;
        if (!response.IsChunked() && declared < 0) return RewriteOutcome.Passthrough;

        using var buffer = new MemoryStream(declared > 0 ? (int)declared : 64 * 1024);
        if (response.IsChunked())
        {
            using var framed = new MemoryStream();
            var copied = await fromUpstream.CopyChunkedAsync(framed, AdPageRewriter.MaxBodyBytes, ct);
            if (copied == ChunkedCopyResult.Failed) return RewriteOutcome.Failed;
            if (copied == ChunkedCopyResult.Overflow)
            {
                await client.WriteAsync(response.Serialize(), ct);
                framed.Position = 0;
                await framed.CopyToAsync(client, ct);
                if (!await fromUpstream.CopyChunkedAsync(client, ct)) return RewriteOutcome.Failed;
                await client.FlushAsync(ct);
                return RewriteOutcome.Done;
            }
            if (!Unchunk(framed.ToArray(), buffer)) return RewriteOutcome.Failed;
        }
        else if (!await fromUpstream.CopyExactAsync(buffer, declared, ct))
        {
            return RewriteOutcome.Failed;
        }

        var raw = buffer.ToArray();
        var text = AdPageRewriter.Decode(raw, response.Get("Content-Encoding"));
        if (text == null)
        {
            await SendBufferedAsync(client, response, raw, ct);
            return RewriteOutcome.Done;
        }

        bool changed = false;

        foreach (var rule in _adBlock.ReplaceRulesFor(url, host, docHost, type))
        {
            var replaced = rule.Apply(text);
            if (!ReferenceEquals(replaced, text) && replaced != text) { text = replaced; changed = true; }
        }

        if (_adBlock.Cosmetics.YouTube && AdYouTubeFilter.IsYouTubeHost(host)
            && AdPageRewriter.LooksLikeJson(response) && AdYouTubeFilter.IsPlayerJson(url))
        {
            var (ytChanged, ytJson) = AdYouTubeFilter.StripPlayerJson(text);
            if (ytChanged) { text = ytJson; changed = true; }
        }

        if (AdPageRewriter.LooksLikeHtml(response) && LooksLikeDocument(text))
        {
            var result = AdPageRewriter.Rewrite(text, host, _adBlock.Store!, _adBlock.Cosmetics);
            if (result.Changed)
            {
                text = result.Html;
                changed = true;
                Interlocked.Add(ref _adBlock.CosmeticInjections, 1);
                _onPageRewritten?.Invoke();
            }
        }

        if (!changed)
        {
            await SendBufferedAsync(client, response, raw, ct);
            return RewriteOutcome.Done;
        }

        var bytes = Encoding.UTF8.GetBytes(text);
        AdPageRewriter.PrepareRewrittenHeaders(response, bytes.Length);
        await client.WriteAsync(response.Serialize(), ct);
        await client.WriteAsync(bytes, ct);
        return RewriteOutcome.Done;
    }

    private static async Task SendBufferedAsync(Stream client, AdHttpMessage response, byte[] body,
                                                CancellationToken ct)
    {
        AdPageRewriter.Remove(response, "Transfer-Encoding");
        AdPageRewriter.Remove(response, "Content-Length");
        response.Headers.Add(new KeyValuePair<string, string>(
            "Content-Length", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)));

        await client.WriteAsync(response.Serialize(), ct);
        if (body.Length > 0) await client.WriteAsync(body, ct);
        await client.FlushAsync(ct);
    }

    private static bool LooksLikeDocument(string text)
    {
        var head = text.Length > 2048 ? text[..2048] : text;
        return head.Contains("<html", StringComparison.OrdinalIgnoreCase)
               || head.Contains("<head", StringComparison.OrdinalIgnoreCase)
               || head.Contains("<!doctype", StringComparison.OrdinalIgnoreCase);
    }

    private static bool Unchunk(byte[] framed, Stream target)
    {
        int i = 0;
        while (i < framed.Length)
        {
            int eol = Array.IndexOf(framed, (byte)'\n', i);
            if (eol < 0) return false;
            var sizeText = Encoding.ASCII.GetString(framed, i, eol - i).Split(';')[0].Trim();
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out int size))
                return false;
            i = eol + 1;
            if (size == 0) return true;
            if (i + size > framed.Length) return false;
            target.Write(framed, i, size);
            i += size;
            while (i < framed.Length && (framed[i] == (byte)'\r' || framed[i] == (byte)'\n')) i++;
        }
        return true;
    }

    private void ApplyRequestPrivacy(AdHttpMessage request, string host, string? docHost)
    {
        var o = _adBlock.Cosmetics;
        if (!o.Stealth) return;
        var p = o.Privacy;

        var exemptions = _adBlock.Store?.GetStealthExemptions(docHost ?? host);
        bool exemptAll = exemptions != null && exemptions.Contains("*");
        if (exemptAll) return;

        if (p.StripXClientData) AdPageRewriter.Remove(request, "X-Client-Data");

        if (p.DoNotTrack)
        {
            AdPageRewriter.Remove(request, "DNT");
            AdPageRewriter.Remove(request, "Sec-GPC");
            request.Headers.Add(new KeyValuePair<string, string>("DNT", "1"));
            request.Headers.Add(new KeyValuePair<string, string>("Sec-GPC", "1"));
        }

        if (p.HideSearchQueries)
        {
            var referer = request.Get("Referer");
            var trimmed = referer == null ? null : AdPrivacy.TrimSearchReferer(referer);
            if (trimmed != null)
            {
                AdPageRewriter.Remove(request, "Referer");
                if (trimmed.Length > 0)
                    request.Headers.Add(new KeyValuePair<string, string>("Referer", trimmed));
            }
        }

        if (p.StripUrlParams)
        {
            var cleaned = AdPrivacy.StripTrackingParams(request.Target);
            if (cleaned != null && cleaned != request.Target)
            {
                request.Target = cleaned;
                request.StartLine = $"{request.Method} {request.Target} {request.Version}";
            }
        }
    }

    public async Task ServeGenericCssAsync(Stream client, CancellationToken ct)
    {
        var reader = new AdHttpReader(client);
        while (!ct.IsCancellationRequested)
        {
            var head = await reader.ReadHeadAsync(ct);
            if (head == null) return;
            var request = AdHttpMessage.ParseRequest(head);
            if (request == null) return;
            if (!await DrainBodyAsync(reader, request, ct)) return;
            await WriteGenericCssAsync(client, ct);
            if (request.WantsClose()) return;
        }
    }

    private static void LimitAcceptEncoding(AdHttpMessage request)
    {
        var value = request.Get("Accept-Encoding");
        if (value == null) return;

        var kept = new List<string>();
        foreach (var raw in value.Split(','))
        {
            var token = raw.Trim();
            if (token.Length == 0) continue;
            var name = token.Split(';')[0].Trim().ToLowerInvariant();
            if (name is "gzip" or "deflate" or "br" or "identity" or "*") kept.Add(token);
        }
        if (kept.Count == value.Split(',').Length) return;

        AdPageRewriter.Remove(request, "Accept-Encoding");
        request.Headers.Add(new KeyValuePair<string, string>(
            "Accept-Encoding", kept.Count > 0 ? string.Join(", ", kept) : "gzip, deflate, br"));
    }

    private async Task WriteGenericCssAsync(Stream client, CancellationToken ct)
    {
        var css = Encoding.UTF8.GetBytes(_adBlock.GenericCss);
        var header = "HTTP/1.1 200 OK\r\n"
                     + "Content-Type: text/css; charset=utf-8\r\n"
                     + $"Content-Length: {css.Length}\r\n"
                     + "Cache-Control: max-age=3600\r\n"
                     + "X-Malward-AdBlock: generic\r\n"
                     + "\r\n";
        await client.WriteAsync(Encoding.ASCII.GetBytes(header), ct);
        if (css.Length > 0) await client.WriteAsync(css, ct);
        await client.FlushAsync(ct);
    }

    private static string HostOnly(string hostPort)
    {
        int colon = hostPort.LastIndexOf(':');
        return colon > 0 ? hostPort[..colon] : hostPort;
    }

    private static string PathOf(AdHttpMessage request)
    {
        var target = request.Target;
        int scheme = target.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0)
        {
            int slash = target.IndexOf('/', scheme + 3);
            return slash < 0 ? "/" : target[slash..];
        }
        if (target.Length == 0) return "/";
        return target[0] == '/' ? target : "/" + target;
    }

    private static string BuildUrl(string scheme, string host, AdHttpMessage request)
    {
        var target = request.Target;
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return target;
        var authority = request.Get("Host") ?? host;
        if (!target.StartsWith("/", StringComparison.Ordinal)) target = "/" + target;
        return scheme + "://" + authority + target;
    }

    private static string? DocumentHost(AdHttpMessage request)
    {
        foreach (var name in new[] { "Referer", "Origin" })
        {
            var v = request.Get(name);
            if (string.IsNullOrEmpty(v)) continue;
            if (Uri.TryCreate(v, UriKind.Absolute, out var u)) return u.Host;
        }
        return null;
    }

    private static async Task<bool> DrainBodyAsync(AdHttpReader reader, AdHttpMessage request,
                                                   CancellationToken ct)
    {
        if (request.IsChunked()) return await reader.CopyChunkedAsync(null, ct);
        long len = request.ContentLength();
        if (len > 0) return await reader.CopyExactAsync(null, len, ct);
        return true;
    }

    private static async Task<bool> ForwardBodyAsync(AdHttpReader reader, Stream target,
                                                     AdHttpMessage request, CancellationToken ct)
    {
        if (request.IsChunked()) return await reader.CopyChunkedAsync(target, ct);
        long len = request.ContentLength();
        if (len > 0) return await reader.CopyExactAsync(target, len, ct);
        return true;
    }

    private static Task WriteStubAsync(Stream client, AdResourceType type, string? redirect,
                                       string url, CancellationToken ct)
        => AdStubResponse.WriteAsync(client, type, redirect, url, AdStubResponse.AdMarker, ct);

    private static async Task PumpBothAsync(AdHttpReader clientReader, Stream client,
                                            AdHttpReader upstreamReader, Stream upstream,
                                            CancellationToken ct)
    {
        using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var one = Pump(clientReader, upstream, done);
        var two = Pump(upstreamReader, client, done);
        await Task.WhenAny(one, two);
        done.Cancel();
        try { await Task.WhenAll(one, two); } catch { }

        static async Task Pump(AdHttpReader from, Stream to, CancellationTokenSource stop)
        {
            try { await from.CopyRestAsync(to, stop.Token); }
            catch { }
            finally { stop.Cancel(); }
        }
    }
}
