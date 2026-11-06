using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Malward.NetworkScanner.AdBlock;

namespace Malward.NetworkScanner;

public sealed class UrlFilterProxy : IDisposable
{
    public const int DefaultPort = 8119;
    public const int FallbackPort = 18119;

    private readonly LeafCertCache _leaves;
    private readonly ActivityReporter _activity;
    private readonly BlockPageServer? _blockPage;
    private readonly Func<string, string?, bool, CancellationToken, Task<(bool Blocked, string? Detection, string? Source)>> _verdict;
    private readonly Func<string, string?, (bool Blocked, string? Detection, string? Source)> _pathVerdict;

    // When set, every inspected session writes what the browser was given to this directory.
    public static string? CaptureDirectory;
    private readonly Func<string, bool> _hasPathRules;
    private AdBlockService? _adBlock;
    private AdHttpInspector? _inspector;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activePort;

    public int ActivePort => _activePort;
    public bool IsRunning => _listener != null;

    public UrlFilterProxy(LeafCertCache leaves, ActivityReporter activity, BlockPageServer? blockPage,
        Func<string, string?, bool, CancellationToken, Task<(bool Blocked, string? Detection, string? Source)>> verdict,
        Func<string, bool>? hasPathRules = null,
        Func<string, string?, (bool Blocked, string? Detection, string? Source)>? pathVerdict = null)
    {
        _leaves = leaves;
        _activity = activity;
        _blockPage = blockPage;
        _verdict = verdict;
        _hasPathRules = hasPathRules ?? (_ => false);
        _pathVerdict = pathVerdict ?? ((_, _) => (false, null, null));
    }

    public void AttachAdBlock(AdBlockService? adBlock)
    {
        _adBlock = adBlock;
        _inspector = adBlock == null ? null : new AdHttpInspector(adBlock, ReportAd, GuardPathAsync, NotePageInspected);
    }

    public bool Start(int port = DefaultPort)
    {
        Stop();
        _listener = BindPreferred(port) ?? TryBind(FallbackPort);
        if (_listener == null)
        {
            Log.Error("HttpFilter", $"Failed to open 127.0.0.1:{port} and {FallbackPort} "
                                    + "— address filtering stays on the DNS layer only.");
            return false;
        }

        _cts = new CancellationTokenSource();
        _ = AcceptLoop(_cts.Token);
        Log.Info("HttpFilter", $"Address filter active on 127.0.0.1:{_activePort}");
        return true;
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
        try { _cts?.Dispose(); } catch { }
        _cts = null;
    }

    public void Dispose() => Stop();

    private TcpListener? BindPreferred(int port)
    {
        var deadline = DateTime.UtcNow.AddSeconds(8);
        bool waited = false;
        while (true)
        {
            var listener = TryBind(port, quiet: DateTime.UtcNow < deadline);
            if (listener != null)
            {
                if (waited)
                    Log.Info("HttpFilter", $"Port {port} was still held by the previous instance "
                                           + "and has now been taken over.");
                return listener;
            }
            if (DateTime.UtcNow >= deadline) return null;
            waited = true;
            Thread.Sleep(400);
        }
    }

    private TcpListener? TryBind(int port, bool quiet = false)
    {
        try
        {
            var l = new TcpListener(IPAddress.Loopback, port);
            l.Start(backlog: 200);
            _activePort = port;
            return l;
        }
        catch (Exception ex)
        {
            if (!quiet) Log.Warn("HttpFilter", $"Bind 127.0.0.1:{port} failed: {ex.Message}");
            return null;
        }
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        var listener = _listener!;
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch { continue; }
            _ = Task.Run(() => HandleClient(client, ct), ct);
        }
    }

    private async Task HandleClient(TcpClient client, CancellationToken ct)
    {
        try
        {
            client.NoDelay = true;
            client.ReceiveTimeout = 60_000;
            client.SendTimeout = 60_000;
            using var stream = client.GetStream();

            var reader = new AdHttpReader(stream);
            var head = await reader.ReadHeadAsync(ct);
            if (string.IsNullOrEmpty(head)) return;

            int firstBreak = head.IndexOf("\r\n", StringComparison.Ordinal);
            var firstLine = firstBreak < 0 ? head.Trim() : head[..firstBreak];
            var headers = firstBreak < 0 ? "" : head[(firstBreak + 2)..];

            var parts = firstLine.Split(' ');
            if (parts.Length < 3) return;

            if (parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                await HandleConnect(stream, parts[1], ct);
            else
                await HandlePlain(stream, reader, head, firstLine, parts[1], headers, ct);
        }
        catch (Exception ex) { Log.Debug("HttpFilter", $"client error: {ex.Message}"); }
        finally { try { client.Close(); } catch { } }
    }

    private async Task HandleConnect(NetworkStream stream, string target, CancellationToken ct)
    {
        var hostPort = target.Split(':', 2);
        string host = hostPort[0];
        int port = hostPort.Length == 2 && int.TryParse(hostPort[1], out var p) ? p : 443;

        if (_inspector != null
            && host.Equals(AdPageRewriter.GenericCssHost, StringComparison.OrdinalIgnoreCase))
        {
            await stream.WriteAsync(Established, ct);
            await ServeCosmeticCssAsync(stream, host, ct);
            return;
        }

        bool pathRules = _hasPathRules(host);
        bool willInspect = port == 443 && _inspector != null && !RecentlyFailed(host)
                           && (_adBlock?.ShouldInspect(host) == true
                               || (pathRules && _adBlock?.CanInspectForThreats(host) == true));

        var (blocked, detection, source) = await _verdict(host, null, willInspect, ct);
        if (!blocked)
        {
            await stream.WriteAsync(Established, ct);
            if (willInspect)
            {
                await InspectTlsAsync(stream, host, port, ct);
                return;
            }
            await TunnelAsync(stream, host, port, ct);
            return;
        }

        Report(host, detection, source);

        var leaf = _leaves.GetOrCreate(host);
        if (leaf == null)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nX-Malward-Block: 1\r\n"
                + "Connection: close\r\n\r\n"), ct);
            return;
        }

        await stream.WriteAsync(Established, ct);

        SslStream? ssl = null;
        try
        {
            ssl = new SslStream(stream, leaveInnerStreamOpen: true);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                AllowRenegotiation = false,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, ct);

            var (firstLine, headers) = await ReadHeaderAsync(ssl, ct);
            await WriteBlockResponseAsync(ssl, host, detection, source, firstLine, headers, ct);
        }
        catch (AuthenticationException) { }
        catch (Exception ex) { Log.Debug("HttpFilter", $"block page for {host}: {ex.Message}"); }
        finally { try { ssl?.Dispose(); } catch { } }
    }

    private async Task HandlePlain(NetworkStream stream, AdHttpReader reader, string head,
                                   string firstLine, string target, string headers,
                                   CancellationToken ct)
    {
        string host = HostOf(target, headers);
        if (host.Length == 0) return;

        var (blocked, detection, source) = await _verdict(host, PathOf(target), false, ct);
        if (blocked)
        {
            Report(host, detection, source);
            await WriteBlockResponseAsync(stream, host, detection, source, firstLine, headers, ct);
            return;
        }

        int port = 80;
        var colon = host.LastIndexOf(':');
        if (colon > 0 && int.TryParse(host[(colon + 1)..], out var custom)) { port = custom; host = host[..colon]; }

        using var upstream = new TcpClient { NoDelay = true };
        try { await upstream.ConnectAsync(host, port, ct); }
        catch (Exception ex) { Log.Debug("HttpFilter", $"upstream {host}:{port}: {ex.Message}"); return; }

        var upstreamStream = upstream.GetStream();

        if (_inspector != null && _adBlock?.ShouldInspect(host) == true)
        {
            try { await _inspector.RunAsync(stream, upstreamStream, host, secure: false, ct, head); }
            catch (Exception ex) { Log.Debug("HttpFilter", $"inspection of {host}: {ex.Message}"); }
            return;
        }

        await upstreamStream.WriteAsync(Encoding.ASCII.GetBytes(head), ct);
        await reader.DrainBufferedAsync(upstreamStream, ct);
        await PumpBothAsync(stream, upstreamStream, ct);
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime>
        InspectionFailures = new(StringComparer.OrdinalIgnoreCase);

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int>
        HandshakeRefusals = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan InspectionCooldown = TimeSpan.FromMinutes(10);

    private const int RefusalsBeforeBackingOff = 3;

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

    private static bool RecentlyFailed(string host)
    {
        if (!InspectionFailures.TryGetValue(host, out var when)) return false;
        if (DateTime.UtcNow - when < InspectionCooldown) return true;
        InspectionFailures.TryRemove(host, out _);
        HandshakeRefusals.TryRemove(host, out _);
        return false;
    }

    private static void NoteInspectionFailure(string host)
    {
        if (InspectionFailures.Count > 4000) InspectionFailures.Clear();
        InspectionFailures[host] = DateTime.UtcNow;
    }

    private static void NoteHandshakeAccepted(string host)
    {
        HandshakeRefusals.TryRemove(host, out _);
    }

    private static void NoteHandshakeRefused(string host, string reason)
    {
        if (HandshakeRefusals.Count > 4000) HandshakeRefusals.Clear();
        int n = HandshakeRefusals.AddOrUpdate(host, 1, (_, prev) => prev + 1);

        if (n < RefusalsBeforeBackingOff)
        {
            Log.Debug("HttpFilter", $"{host}: client rejected our certificate ({reason}), "
                                  + $"attempt {n} of {RefusalsBeforeBackingOff}.");
            return;
        }

        NoteInspectionFailure(host);
        Log.Info("HttpFilter", $"{host} will not accept the Malward certificate ({reason}) — "
                             + $"content filtering is off for this site for "
                             + $"{InspectionCooldown.TotalMinutes:F0} min. Address and DNS blocking "
                             + "keep working. In Firefox this means the certificate policy has not "
                             + "been picked up yet; restart the browser.");
    }

    private async Task ServeCosmeticCssAsync(NetworkStream client, string host, CancellationToken ct)
    {
        var leaf = _leaves.GetOrCreate(host);
        if (leaf == null) return;

        SslStream? ssl = null;
        try
        {
            ssl = new SslStream(client, leaveInnerStreamOpen: true);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                AllowRenegotiation = false,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, ct);

            await _inspector!.ServeGenericCssAsync(ssl, ct);
        }
        catch (Exception ex) { Log.Debug("HttpFilter", $"generic stylesheet: {ex.Message}"); }
        finally { try { ssl?.Dispose(); } catch { } }
    }

    private async Task InspectTlsAsync(NetworkStream client, string host, int port,
                                       CancellationToken ct)
    {
        var leaf = _leaves.GetOrCreate(host);
        if (leaf == null) { await TunnelAsync(client, host, port, ct); return; }

        TcpClient? upstream = null;
        SslStream? outer = null;
        try
        {
            upstream = new TcpClient { NoDelay = true };
            await upstream.ConnectAsync(host, port, ct);

            outer = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false);
            await outer.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, ct);
        }
        catch (Exception ex)
        {
            try { outer?.Dispose(); } catch { }
            try { upstream?.Dispose(); } catch { }
            NoteInspectionFailure(host);
            Log.Debug("HttpFilter",
                $"{host} refused inspection ({ex.Message}) — falling back to a plain tunnel.");
            await TunnelAsync(client, host, port, ct);
            return;
        }

        SslStream? inner = null;
        try
        {
            inner = new SslStream(client, leaveInnerStreamOpen: true);
            await inner.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                AllowRenegotiation = false,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, ct);
        }
        catch (Exception ex)
        {
            NoteHandshakeRefused(host, ex.Message);
            try { inner?.Dispose(); } catch { }
            try { outer.Dispose(); } catch { }
            try { upstream.Dispose(); } catch { }
            return;
        }

        NoteHandshakeAccepted(host);

        Stream toClient = CaptureDirectory == null
            ? inner
            : new CaptureStream(inner, host, CaptureDirectory);

        try
        {
            await _inspector!.RunAsync(toClient, outer, host, secure: true, ct);
        }
        catch (Exception ex)
        {
            Log.Debug("HttpFilter", $"session with {host} ended: {ex.Message}");
        }
        finally
        {
            try { if (!ReferenceEquals(toClient, inner)) toClient.Dispose(); } catch { }
            try { inner.Dispose(); } catch { }
            try { outer.Dispose(); } catch { }
            try { upstream.Dispose(); } catch { }
        }
    }

    private async Task<bool> GuardPathAsync(string host, string? path, string head,
                                            Stream client, CancellationToken ct)
    {
        var (blocked, detection, source) = _pathVerdict(host, path);
        if (!blocked) return false;

        Report(host, detection, source);
        int firstBreak = head.IndexOf("\r\n", StringComparison.Ordinal);
        var firstLine = firstBreak < 0 ? head.Trim() : head[..firstBreak];
        var headers = firstBreak < 0 ? "" : head[(firstBreak + 2)..];
        await WriteBlockResponseAsync(client, host, detection, source, firstLine, headers, ct);
        return true;
    }

    private long _adsBlocked;
    private long _pagesInspected;
    private DateTime _lastAdSummaryUtc = DateTime.UtcNow;

    private static readonly TimeSpan AdSummaryEvery = TimeSpan.FromMinutes(5);

    private void ReportAd(string host, string url, AdBlockVerdict verdict)
    {
        try
        {
            _activity.ReportBlock(host, detection: verdict.Detection, source: "adblock",
                                  process: null, list: verdict.List);
        }
        catch { }
        try { _blockPage?.NoteBlocked(host, verdict.Detection, "adblock"); } catch { }

        long n = Interlocked.Increment(ref _adsBlocked);
        if (n <= 20)
            Log.Info("AdBlock", $"BLOCK {Trim(url)} ({verdict.Detection}, rule {Trim(verdict.Rule, 90)})");
        else
            Log.Debug("AdBlock", $"BLOCK {Trim(url)} ({verdict.Detection}, rule {Trim(verdict.Rule, 90)})");

        MaybeLogAdSummary();
    }

    public void NotePageInspected() => Interlocked.Increment(ref _pagesInspected);

    private void MaybeLogAdSummary()
    {
        var now = DateTime.UtcNow;
        if (now - _lastAdSummaryUtc < AdSummaryEvery) return;
        _lastAdSummaryUtc = now;
        Log.Info("AdBlock", $"So far this run: {Interlocked.Read(ref _adsBlocked)} requests blocked by "
                          + $"the filter lists, {Interlocked.Read(ref _pagesInspected)} pages rewritten "
                          + "with hiding rules.");
    }

    private static string Trim(string s, int max = 140) =>
        string.IsNullOrEmpty(s) ? "-" : (s.Length <= max ? s : s[..max] + "…");

    private async Task TunnelAsync(NetworkStream client, string host, int port, CancellationToken ct)
    {
        using var upstream = new TcpClient { NoDelay = true };
        try { await upstream.ConnectAsync(host, port, ct); }
        catch (Exception ex) { Log.Debug("HttpFilter", $"tunnel {host}:{port}: {ex.Message}"); return; }

        await PumpBothAsync(client, upstream.GetStream(), ct);
    }

    private static async Task PumpBothAsync(Stream a, Stream b, CancellationToken ct)
    {
        using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var one = Copy(a, b, done);
        var two = Copy(b, a, done);
        await Task.WhenAny(one, two);
        done.Cancel();
        try { await Task.WhenAll(one, two); } catch { }

        static async Task Copy(Stream from, Stream to, CancellationTokenSource stop)
        {
            var buffer = new byte[32 * 1024];
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    int read = await from.ReadAsync(buffer, stop.Token);
                    if (read <= 0) break;
                    await to.WriteAsync(buffer.AsMemory(0, read), stop.Token);
                }
            }
            catch { }
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime>
        LastAlertPerHost = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan AlertRepeatAfter = TimeSpan.FromMinutes(1);

    private void Report(string host, string? detection, string? source)
    {
        string name = detection ?? "Phishing.Url";
        try { _activity.ReportBlock(host, detection: name, source: source ?? "cloud", process: null); } catch { }
        try { _blockPage?.NoteBlocked(host, name, source ?? "cloud"); } catch { }

        var now = DateTime.UtcNow;
        if (LastAlertPerHost.Count > 4000) LastAlertPerHost.Clear();
        bool loud = !LastAlertPerHost.TryGetValue(host, out var last) || now - last > AlertRepeatAfter;
        LastAlertPerHost[host] = loud ? now : last;

        if (loud) Log.Alert("HttpFilter", $"BLOCK {host} ({name})");
        else Log.Debug("HttpFilter", $"BLOCK {host} ({name})");
    }

    private static async Task WriteBlockResponseAsync(Stream stream, string host, string? detection,
                                                      string? source, string firstLine,
                                                      string headers, CancellationToken ct)
    {
        if (await AdStubResponse.TryWriteSubresourceAsync(stream, firstLine + "\n" + headers,
                                                          host, AdStubResponse.ThreatMarker, ct)) return;

        if (!BlockPageServer.AcceptsHtml(headers))
        {
            var text = Encoding.UTF8.GetBytes(BlockPageServer.BuildShortBlockMessage(host, detection));
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + $"Content-Length: {text.Length}\r\n"
                + "Cache-Control: no-store\r\nX-Malward-Block: 1\r\nConnection: close\r\n\r\n"), ct);
            await stream.WriteAsync(text, ct);
            await stream.FlushAsync(ct);
            return;
        }

        var body = Encoding.UTF8.GetBytes(BlockPageRenderer.Render(host, detection, source));
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
            + $"Content-Length: {body.Length}\r\n"
            + "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
            + "Pragma: no-cache\r\nExpires: 0\r\nX-Malward-Block: 1\r\nConnection: close\r\n\r\n"), ct);
        await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    public static string HostOf(string target, string headers)
    {
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            int start = target.IndexOf("//", StringComparison.Ordinal) + 2;
            int end = target.IndexOfAny(new[] { '/', '?', '#' }, start);
            var authority = end < 0 ? target[start..] : target[start..end];
            int at = authority.LastIndexOf('@');
            if (at >= 0) authority = authority[(at + 1)..];
            return authority;
        }

        foreach (var line in headers.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                return trimmed[5..].Trim();
        }
        return "";
    }

    private static readonly byte[] Established =
        Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");

    private static async Task<(string FirstLine, string Headers)> ReadHeaderAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[16 * 1024];
        int filled = 0;
        while (filled < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(filled, buffer.Length - filled), ct);
            if (read <= 0) break;
            filled += read;
            var seen = Encoding.ASCII.GetString(buffer, 0, filled);
            int end = seen.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end < 0) continue;

            var head = seen[..(end + 2)];
            int firstBreak = head.IndexOf("\r\n", StringComparison.Ordinal);
            return firstBreak < 0 ? (head.Trim(), "") : (head[..firstBreak], head[(firstBreak + 2)..]);
        }
        return ("", "");
    }
}
