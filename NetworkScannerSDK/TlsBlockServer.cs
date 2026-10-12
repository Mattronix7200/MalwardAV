using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Malward.NetworkScanner;

public sealed class TlsBlockServer : IDisposable
{
    public const int DefaultPort = 443;
    public const int FallbackPort = 8443;

    private readonly LeafCertCache _leaves;
    private readonly Func<string, (string? Detection, string? Source)> _lookup;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activePort;

    public int ActivePort => _activePort;
    public bool IsRunning => _listener != null;

    public TlsBlockServer(LeafCertCache leaves,
        Func<string, (string? Detection, string? Source)> blockInfoLookup)
    {
        _leaves = leaves;
        _lookup = blockInfoLookup;
    }

    public void Start()
    {
        Stop();
        _listener = TryBind(DefaultPort) ?? TryBind(FallbackPort);
        if (_listener == null)
        {
            Log.Warn("TlsBlock",
                $"Failed to open HTTPS port ({DefaultPort} or {FallbackPort}). " +
                "HTTPS block page unavailable — the browser will show its own error.");
            return;
        }
        _cts = new CancellationTokenSource();
        _ = AcceptLoop(_cts.Token);
        Log.Info("TlsBlock", $"HTTPS block page active on 127.0.0.1:{_activePort}");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        _listener = null;
        _cts?.Dispose();
        _cts = null;
    }

    private TcpListener? TryBind(int port)
    {
        try
        {
            var l = new TcpListener(IPAddress.Loopback, port);
            l.Start();
            _activePort = port;
            return l;
        }
        catch (Exception ex)
        {
            Log.Debug("TlsBlock", $"Bind 127.0.0.1:{port}: {ex.Message}");
            return null;
        }
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
            catch (Exception ex) { Log.Debug("TlsBlock", $"accept: {ex.Message}"); continue; }
            _ = Task.Run(() => Handle(client));
        }
    }

    private async Task Handle(TcpClient client)
    {
        SslStream? ssl = null;
        string? sniHost = null;
        try
        {
            client.ReceiveTimeout = 5000;
            client.SendTimeout = 5000;
            ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);

            var options = new SslServerAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificateRequired = false,
                AllowRenegotiation = false,
                ServerCertificateSelectionCallback = (sender, name) =>
                {
                    sniHost = name ?? "unknown";
                    var leaf = _leaves.GetOrCreate(sniHost);
                    if (leaf == null)
                    {
                        Log.Warn("TlsBlock", $"No leaf cert for {sniHost} — root CA not loaded or Generate failed.");
                    }
                    return leaf!;
                },
            };
            await ssl.AuthenticateAsServerAsync(options);

            var headers = await ReadHeadersAsync(ssl);
            string host = sniHost ?? ExtractHostFromHeaders(headers) ?? "?";
            string path = ExtractRequestPath(headers);

            string html;
            {
                var (det, src) = _lookup(host);

                if (!BlockPageServer.AcceptsHtml(headers))
                {
                    var msg = BlockPageServer.BuildShortBlockMessage(host, det);
                    var pBytes = Encoding.UTF8.GetBytes(msg);
                    var pHead = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\n" +
                        "Content-Type: text/plain; charset=utf-8\r\n" +
                        $"Content-Length: {pBytes.Length}\r\n" +
                        "Cache-Control: no-store\r\nX-Malward-Block: 1\r\nConnection: close\r\n\r\n");
                    await ssl.WriteAsync(pHead);
                    await ssl.WriteAsync(pBytes);
                    await ssl.FlushAsync();
                    return;
                }
                html = BlockPageRenderer.Render(host, det, src);
            }
            byte[] body = Encoding.UTF8.GetBytes(html);

            var head = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html; charset=utf-8\r\n" +
                $"Content-Length: {body.Length}\r\n" +
                "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n" +
                "Pragma: no-cache\r\n" +
                "Expires: 0\r\n" +
                "Clear-Site-Data: \"cache\", \"cookies\", \"storage\"\r\n" +
                "X-Malward-Block: 1\r\n" +
                "Connection: close\r\n\r\n");
            await ssl.WriteAsync(head);
            await ssl.WriteAsync(body);
            await ssl.FlushAsync();
        }
        catch (AuthenticationException ex)
        {
            Log.Debug("TlsBlock", $"TLS reject for {sniHost ?? "?"}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Log.Debug("TlsBlock", $"handler error: {ex.Message}");
        }
        finally
        {
            try { ssl?.Dispose(); } catch { }
            try { client.Close(); } catch { }
        }
    }

    private static async Task<string> ReadHeadersAsync(SslStream ssl)
    {
        var buf = new byte[8192];
        int total = 0;
        while (total < buf.Length)
        {
            int n = await ssl.ReadAsync(buf.AsMemory(total, buf.Length - total));
            if (n <= 0) break;
            total += n;
            for (int i = 3; i < total; i++)
                if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n')
                    return Encoding.ASCII.GetString(buf, 0, i + 1);
        }
        return Encoding.ASCII.GetString(buf, 0, total);
    }

    private static string ExtractRequestPath(string headers)
    {
        int eol = headers.IndexOf("\r\n", StringComparison.Ordinal);
        var first = eol > 0 ? headers[..eol] : headers;
        var parts = first.Split(' ');
        return parts.Length >= 2 ? parts[1] : "/";
    }

    private static string? ExtractHostFromHeaders(string headers)
    {
        foreach (var line in headers.Split("\r\n"))
        {
            if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                var v = line[5..].Trim().Split(':', 2)[0].Trim().ToLowerInvariant();
                if (!string.IsNullOrEmpty(v)) return v;
            }
        }
        return null;
    }

    public void Dispose() => Stop();
}
