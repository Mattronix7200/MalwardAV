using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Malward.NetworkScanner;

public sealed class HttpAdBlockProxy : IDisposable
{
    public const int DefaultPort = 8118;

    private readonly AdBlockEngine _engine;
    private readonly LeafCertCache _leaves;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activePort;

    public int ActivePort => _activePort;
    public bool IsRunning => _listener != null;

    public HttpAdBlockProxy(AdBlockEngine engine, LeafCertCache leaves)
    {
        _engine = engine;
        _leaves = leaves;
    }

    public bool Start(int port = DefaultPort)
    {
        Stop();
        try
        {
            _listener = new TcpListener(IPAddress.Loopback, port);
            _listener.Start(backlog: 200);
            _activePort = port;
        }
        catch (Exception ex)
        {
            Log.Warn("Proxy", $"Bind 127.0.0.1:{port} failed: {ex.Message}");
            _listener = null;
            return false;
        }
        _cts = new CancellationTokenSource();
        _ = AcceptLoop(_cts.Token);
        Log.Info("Proxy", $"HTTP/HTTPS adblock proxy aktywne na 127.0.0.1:{_activePort}");
        return true;
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
        _cts?.Dispose();
        _cts = null;
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        var l = _listener!;
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await l.AcceptTcpClientAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch { continue; }
            _ = Task.Run(() => HandleClient(client, ct));
        }
    }

    private async Task HandleClient(TcpClient client, CancellationToken ct)
    {
        try
        {
            client.ReceiveTimeout = 30_000;
            client.SendTimeout = 30_000;
            using var ns = client.GetStream();

            var (firstLine, headers) = await ReadRequestHeader(ns, ct);
            if (string.IsNullOrEmpty(firstLine)) return;

            var parts = firstLine.Split(' ');
            if (parts.Length < 3) return;
            string method = parts[0];
            string target = parts[1];

            if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                await HandleConnect(ns, target, ct);
            }
            else
            {
                await HandlePlainHttp(ns, method, target, firstLine, headers, ct);
            }
        }
        catch (Exception ex) { Log.Debug("Proxy", $"client error: {ex.Message}"); }
        finally { try { client.Close(); } catch { } }
    }

    private async Task HandleConnect(NetworkStream clientNs, string target, CancellationToken ct)
    {
        var hostPort = target.Split(':', 2);
        string host = hostPort[0];
        int port = hostPort.Length == 2 && int.TryParse(hostPort[1], out var p) ? p : 443;

        await clientNs.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct);

        var leafCert = _leaves.GetOrCreate(host);
        if (leafCert == null)
        {
            await TunnelToUpstream(clientNs, host, port, ct);
            return;
        }

        SslStream? clientSsl = null;
        try
        {
            clientSsl = new SslStream(clientNs, leaveInnerStreamOpen: true);
            await clientSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leafCert,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                AllowRenegotiation = false,
            });
        }
        catch (AuthenticationException)
        {
            try { clientSsl?.Dispose(); } catch { }
            return;
        }

        TcpClient? upstream = null;
        SslStream? upSsl = null;
        try
        {
            upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, ct);
            upSsl = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (s, c, ch, e) => true);
            await upSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (s, c, ch, e) => true,
            });
        }
        catch (Exception ex)
        {
            Log.Debug("Proxy", $"upstream {host}:{port} failed: {ex.Message}");
            try { upstream?.Close(); } catch { }
            try { clientSsl.Dispose(); } catch { }
            return;
        }

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var (reqFirst, reqHeaders) = await ReadRequestHeader(clientSsl, ct);
                if (string.IsNullOrEmpty(reqFirst)) break;

                var rParts = reqFirst.Split(' ');
                if (rParts.Length < 3) break;
                string path = rParts[1];
                string url = $"https://{host}{path}";
                string? initiator = ExtractInitiator(reqHeaders);

                if (_engine.IsBlocked(url, initiator))
                {
                    var body = "";
                    var resp = Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nX-Malward-Block: 1\r\nConnection: keep-alive\r\n\r\n");
                    await clientSsl.WriteAsync(resp, ct);

                    int cl = GetContentLength(reqHeaders);
                    if (cl > 0) await DrainBytes(clientSsl, cl, ct);
                    continue;
                }

                var requestBytes = Encoding.ASCII.GetBytes(reqFirst + "\r\n" + reqHeaders + "\r\n");
                await upSsl.WriteAsync(requestBytes, ct);
                int reqCL = GetContentLength(reqHeaders);
                if (reqCL > 0) await CopyBytes(clientSsl, upSsl, reqCL, ct);

                await CopyHttpResponse(upSsl, clientSsl, ct);
            }
        }
        catch (Exception ex) { Log.Debug("Proxy", $"mitm relay: {ex.Message}"); }
        finally
        {
            try { upSsl?.Dispose(); } catch { }
            try { upstream?.Close(); } catch { }
            try { clientSsl.Dispose(); } catch { }
        }
    }

    private async Task HandlePlainHttp(NetworkStream clientNs, string method, string fullUrl,
        string firstLine, string headers, CancellationToken ct)
    {
        if (!Uri.TryCreate(fullUrl, UriKind.Absolute, out var u)) return;
        string host = u.Host;
        int port = u.IsDefaultPort ? 80 : u.Port;
        string url = u.ToString();
        string? initiator = ExtractInitiator(headers);

        if (_engine.IsBlocked(url, initiator))
        {
            await clientNs.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nX-Malward-Block: 1\r\nConnection: close\r\n\r\n"), ct);
            return;
        }

        try
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, ct);
            var ups = upstream.GetStream();

            string newFirstLine = $"{method} {u.PathAndQuery} HTTP/1.1";
            var headerBytes = Encoding.ASCII.GetBytes(newFirstLine + "\r\n" + headers + "\r\n");
            await ups.WriteAsync(headerBytes, ct);
            int reqCL = GetContentLength(headers);
            if (reqCL > 0) await CopyBytes(clientNs, ups, reqCL, ct);

            await CopyHttpResponse(ups, clientNs, ct);
        }
        catch (Exception ex) { Log.Debug("Proxy", $"plain http upstream: {ex.Message}"); }
    }

    private async Task TunnelToUpstream(NetworkStream clientNs, string host, int port, CancellationToken ct)
    {
        try
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, ct);
            var ups = upstream.GetStream();
            var t1 = clientNs.CopyToAsync(ups, ct);
            var t2 = ups.CopyToAsync(clientNs, ct);
            await Task.WhenAny(t1, t2);
        }
        catch { }
    }

    private static async Task<(string firstLine, string headers)> ReadRequestHeader(Stream s, CancellationToken ct)
    {
        var buf = new byte[8192];
        int total = 0;
        int headersEnd = -1;
        while (total < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(total, buf.Length - total), ct);
            if (n <= 0) break;
            total += n;
            for (int i = 3; i < total; i++)
                if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n')
                { headersEnd = i + 1; break; }
            if (headersEnd > 0) break;
        }
        if (headersEnd <= 0) return ("", "");
        var all = Encoding.ASCII.GetString(buf, 0, headersEnd);
        int firstEol = all.IndexOf("\r\n", StringComparison.Ordinal);
        if (firstEol <= 0) return ("", "");
        return (all.Substring(0, firstEol), all.Substring(firstEol + 2, headersEnd - firstEol - 2 - 2).TrimEnd('\r', '\n'));
    }

    private static int GetContentLength(string headers)
    {
        foreach (var line in headers.Split("\r\n"))
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                if (int.TryParse(line.Substring(15).Trim(), out var n)) return n;
        return 0;
    }

    private static string? ExtractInitiator(string headers)
    {
        foreach (var line in headers.Split("\r\n"))
        {
            if (line.StartsWith("Referer:", StringComparison.OrdinalIgnoreCase))
            {
                var v = line.Substring(8).Trim();
                if (Uri.TryCreate(v, UriKind.Absolute, out var u)) return u.Host;
            }
        }
        return null;
    }

    private static async Task DrainBytes(Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[16384];
        while (n > 0)
        {
            int read = await s.ReadAsync(buf.AsMemory(0, Math.Min(n, buf.Length)), ct);
            if (read <= 0) break;
            n -= read;
        }
    }

    private static async Task CopyBytes(Stream src, Stream dst, int n, CancellationToken ct)
    {
        var buf = new byte[16384];
        while (n > 0)
        {
            int read = await src.ReadAsync(buf.AsMemory(0, Math.Min(n, buf.Length)), ct);
            if (read <= 0) break;
            await dst.WriteAsync(buf.AsMemory(0, read), ct);
            n -= read;
        }
    }

    private static async Task CopyHttpResponse(Stream src, Stream dst, CancellationToken ct)
    {
        var buf = new byte[32768];
        while (!ct.IsCancellationRequested)
        {
            int read = await src.ReadAsync(buf, ct);
            if (read <= 0) break;
            await dst.WriteAsync(buf.AsMemory(0, read), ct);
        }
    }

    public void Dispose() => Stop();
}
