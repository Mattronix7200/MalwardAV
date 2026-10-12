using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Malward.NetworkScanner;

public sealed class BlockPageServer : IDisposable
{
    public const int DefaultPort = 80;
    public const int FallbackPort = 8080;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _activePort;

    private readonly ConcurrentDictionary<string, (DateTime When, string? Detection, string? Source)> _recent =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan RecentTtl = TimeSpan.FromMinutes(30);

    public int ActivePort => _activePort;
    public bool IsRunning => _listener != null;

    public void Start()
    {
        Stop();
        _listener = TryBind(DefaultPort) ?? TryBind(FallbackPort);
        if (_listener == null)
        {
            Log.Warn("BlockPage",
                $"Failed to open HTTP port ({DefaultPort} or {FallbackPort}). " +
                "The browser will show a generic error instead of the block page.");
            return;
        }
        _cts = new CancellationTokenSource();
        _ = AcceptLoop(_cts.Token);
        Log.Info("BlockPage", $"Block page active on 127.0.0.1:{_activePort}");
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
            Log.Debug("BlockPage", $"Bind 127.0.0.1:{port} failed: {ex.Message}");
            return null;
        }
    }

    public void NoteBlocked(string domain, string? detection, string? source)
    {
        if (string.IsNullOrEmpty(domain)) return;
        _recent[domain] = (DateTime.UtcNow, detection, source);

        if (_recent.Count > 2048)
        {
            var cutoff = DateTime.UtcNow - RecentTtl;
            foreach (var kv in _recent)
                if (kv.Value.When < cutoff) _recent.TryRemove(kv.Key, out _);
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
            catch (Exception ex) { Log.Debug("BlockPage", $"accept: {ex.Message}"); continue; }
            _ = Task.Run(() => HandleClient(client));
        }
    }

    private async Task HandleClient(TcpClient client)
    {
        try
        {
            client.ReceiveTimeout = 3000;
            client.SendTimeout = 3000;
            using var ns = client.GetStream();

            var buf = new byte[8192];
            int total = 0;
            int headersEnd = -1;
            while (total < buf.Length)
            {
                int n = await ns.ReadAsync(buf.AsMemory(total, buf.Length - total));
                if (n <= 0) break;
                total += n;
                headersEnd = FindHeaderEnd(buf, total);
                if (headersEnd >= 0) break;
            }
            if (headersEnd < 0) return;

            var raw = Encoding.ASCII.GetString(buf, 0, headersEnd);
            string host = ExtractHost(raw) ?? "?";

            string? det = null; string? src = null;
            if (_recent.TryGetValue(host, out var info) && DateTime.UtcNow - info.When < RecentTtl)
            {
                det = info.Detection;
                src = info.Source;
            }

            if (!AcceptsHtml(raw))
            {
                var msg = BuildShortBlockMessage(host, det);
                var pBytes = Encoding.UTF8.GetBytes(msg);
                var pResp =
                    "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/plain; charset=utf-8\r\n" +
                    $"Content-Length: {pBytes.Length}\r\n" +
                    "Cache-Control: no-store\r\n" +
                    "X-Malward-Block: 1\r\n" +
                    "Connection: close\r\n\r\n";
                await ns.WriteAsync(Encoding.ASCII.GetBytes(pResp));
                await ns.WriteAsync(pBytes);
                await ns.FlushAsync();
                return;
            }

            var html = BlockPageRenderer.Render(host, det, src);
            var bytes = Encoding.UTF8.GetBytes(html);

            var resp =
                "HTTP/1.1 200 OK\r\n" +
                $"Content-Type: text/html; charset=utf-8\r\n" +
                $"Content-Length: {bytes.Length}\r\n" +
                "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n" +
                "Pragma: no-cache\r\n" +
                "Expires: 0\r\n" +
                "Clear-Site-Data: \"cache\", \"cookies\", \"storage\"\r\n" +
                "X-Malward-Block: 1\r\n" +
                "Connection: close\r\n\r\n";
            var headerBytes = Encoding.ASCII.GetBytes(resp);
            await ns.WriteAsync(headerBytes);
            await ns.WriteAsync(bytes);
            await ns.FlushAsync();
        }
        catch { }
        finally { try { client.Close(); } catch { } }
    }

    public static bool AcceptsHtml(string rawHeaders)
    {
        foreach (var line in rawHeaders.Split("\r\n"))
        {
            if (line.StartsWith("Accept:", StringComparison.OrdinalIgnoreCase))
                return line.Contains("text/html", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    public static string BuildShortBlockMessage(string host, string? detection)
    {
        var det = string.IsNullOrEmpty(detection)
            ? DnsProxy.BuildDetectionName(host ?? "")
            : detection!;
        return
            $"Polaczenie przerwane przez Malward(R) Community Edition.\n" +
            $"Wykryto zagrozenie: {det}\n" +
            $"Adres: {host}\n" +
            $"Strona zostala zablokowana jako szkodliwa lub niezaufana.\n";
    }

    private static int FindHeaderEnd(byte[] b, int len)
    {
        for (int i = 3; i < len; i++)
            if (b[i - 3] == '\r' && b[i - 2] == '\n' && b[i - 1] == '\r' && b[i] == '\n') return i + 1;
        return -1;
    }

    private static string? ExtractHost(string headers)
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

    private static string ExtractPath(string headers)
    {
        int eol = headers.IndexOf("\r\n", StringComparison.Ordinal);
        var first = eol > 0 ? headers[..eol] : headers;
        var parts = first.Split(' ');
        return parts.Length >= 2 ? parts[1] : "/";
    }

    public static string ExtractQueryParamPublic(string path, string name) => ExtractQueryParam(path, name);

    public static bool AddDomainToExclusionsPublic(string domain) => AddDomainToExclusions(domain);

    private static string ExtractQueryParam(string path, string name)
    {
        int q = path.IndexOf('?');
        if (q < 0) return "";
        var qs = path[(q + 1)..];
        foreach (var kv in qs.Split('&'))
        {
            int eq = kv.IndexOf('=');
            if (eq < 0) continue;
            if (kv[..eq].Equals(name, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(kv[(eq + 1)..]);
        }
        return "";
    }

    private static readonly object _exclusionsLock = new();

    private static bool AddDomainToExclusions(string domain)
    {
        string? d = null;
        try
        {
            d = (domain ?? "").Trim().TrimStart('.').TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrEmpty(d) || !d.Contains('.'))
            {
                Log.Warn("BlockPage", $"AddDomainToExclusions: rejecting empty/invalid host '{domain}'");
                return false;
            }
            NetworkConfig.SessionExclusions[d] = 1;
        }
        catch (Exception ex)
        {
            Log.Warn("BlockPage", $"AddDomainToExclusions normalize/session failed: {ex.Message}");
            return false;
        }

        lock (_exclusionsLock)
        {
            try
            {
                var path = NetworkConfig.DefaultPath;
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);

                System.Text.Json.Nodes.JsonObject root;
                if (File.Exists(path))
                {
                    string raw;
                    try { raw = File.ReadAllText(path); }
                    catch (IOException io)
                    {
                        Log.Warn("BlockPage", $"AddDomainToExclusions: ReadAllText('{path}') failed ({io.Message}). " +
                                              "Session exclusion is live — file entry deferred until service restart.");
                        return true;
                    }
                    root = (System.Text.Json.Nodes.JsonNode.Parse(raw) as System.Text.Json.Nodes.JsonObject)
                           ?? new System.Text.Json.Nodes.JsonObject();
                }
                else
                {
                    root = new System.Text.Json.Nodes.JsonObject();
                }

                var existing = root["exclusions"] as System.Text.Json.Nodes.JsonArray;
                var excl = existing ?? new System.Text.Json.Nodes.JsonArray();

                foreach (var n in excl)
                {
                    var s = n?.GetValue<string>();
                    if (!string.IsNullOrEmpty(s) && string.Equals(s, d, StringComparison.OrdinalIgnoreCase))
                    {
                        Log.Info("BlockPage", $"Domain '{d}' was already in exclusions — session synchronized.");
                        return true;
                    }
                }
                excl.Add(d);
                if (existing == null) root["exclusions"] = excl;

                var tmp = path + ".tmp";
                File.WriteAllText(tmp, root.ToJsonString(
                    new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                if (File.Exists(path))
                {
                    try { File.Replace(tmp, path, destinationBackupFileName: null, ignoreMetadataErrors: true); }
                    catch (IOException)
                    {
                        File.Delete(path);
                        File.Move(tmp, path);
                    }
                }
                else
                {
                    File.Move(tmp, path);
                }

                Log.Info("BlockPage", $"Added '{d}' to exclusions (JSON + session) — active from NOW");
                return true;
            }
            catch (UnauthorizedAccessException ua)
            {
                Log.Warn("BlockPage", $"AddDomainToExclusions: no permission for '{NetworkConfig.DefaultPath}' ({ua.Message}). " +
                                      "Session exclusion IS LIVE — the shield allows the domain, but the entry will not survive a service restart.");
                return true;
            }
            catch (Exception ex)
            {
                Log.Warn("BlockPage", $"AddDomainToExclusions failed: {ex.GetType().Name}: {ex.Message}");
                return false;
            }
        }
    }

    private static async Task WriteResponse(NetworkStream ns, string html)
    {
        var bytes = Encoding.UTF8.GetBytes(html);
        var head =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            $"Content-Length: {bytes.Length}\r\n" +
            "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n" +
            "Pragma: no-cache\r\n" +
            "Expires: 0\r\n" +
            "Clear-Site-Data: \"cache\", \"cookies\", \"storage\"\r\n" +
            "X-Malward-Block: 1\r\n" +
            "Connection: close\r\n\r\n";
        await ns.WriteAsync(Encoding.ASCII.GetBytes(head));
        await ns.WriteAsync(bytes);
        await ns.FlushAsync();
    }

    public (string? Detection, string? Source) LookupBlockInfo(string host)
    {
        if (host != null && _recent.TryGetValue(host, out var info)
            && DateTime.UtcNow - info.When < RecentTtl)
            return (info.Detection, info.Source);
        return (null, null);
    }

#if FALSE
    private static string OBSOLETE_RenderBlockPage(string host, string? detection, string? source)
    {
        string safeHost = Escape(host);
        string srcLabel = source switch
        {
            "live"  => "Wykryto na żywo przez serwer Malward",
            "cloud" => "Skaner w chmurze",
            "local" => "Wykryto przez lokalną bazę reputacji",
            _       => "Wykryto przez osłonę sieciową Malward",
        };
        string detLabel = string.IsNullOrEmpty(detection)
            ? Escape(DnsProxy.BuildDetectionName(safeHost))
            : Escape(detection!);

        var nowLocal = DateTime.Now;
        string ts = nowLocal.ToString("yyyy-MM-dd HH:mm:ss");
        string tsIso = nowLocal.ToString("yyyy-MM-ddTHH:mm:sszzz");

        const string logoSvg =
            "<svg viewBox=\"0 0 24 24\" width=\"34\" height=\"34\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">" +
            "<path d=\"M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z\"/>" +
            "<path d=\"M8 14 L8 9 L12 12 L16 9 L16 14\"/></svg>";

        return $@"<!DOCTYPE html>
<html lang=""pl"">
<head>
<meta charset=""utf-8"">
<title>Malward — strona zablokowana</title>
<meta name=""viewport"" content=""width=device-width, initial-scale=1"">
<style>
  :root {{
    color-scheme: light dark;
    /* Light theme by default; dark is switched in via @media prefers-color-scheme. */
    --bg-grad-from: #f6f8fc;
    --bg-grad-to:   #e9eef5;
    --card-bg:      #ffffff;
    --card-border:  #d6dbe2;
    --text:         #1a2030;
    --text-dim:     #4b5563;
    --text-mute:    #6a7280;
    --note-bg:      rgba(226,59,59,.06);
    --note-border:  rgba(226,59,59,.22);
    --foot-border:  #e2e6ec;
    --brand-fg:     #1a2030;
    --shadow:       0 14px 50px rgba(20,30,50,.12);
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg-grad-from: #1c2330;
      --bg-grad-to:   #0e1116;
      --card-bg:      #161b22;
      --card-border:  #2b333e;
      --text:         #e9ecf0;
      --text-dim:     #cfd5dc;
      --text-mute:    #6a7280;
      --note-bg:      rgba(226,59,59,.08);
      --note-border:  rgba(226,59,59,.25);
      --foot-border:  #2b333e;
      --brand-fg:     #cfd5dc;
      --shadow:       0 12px 50px rgba(0,0,0,.4);
    }}
  }}

  html, body {{ height: 100%; }}
  body {{
    margin: 0; display: flex; align-items: center; justify-content: center;
    background: linear-gradient(160deg, var(--bg-grad-from), var(--bg-grad-to));
    font-family: 'Segoe UI', system-ui, -apple-system, Roboto, Arial, sans-serif;
    color: var(--text);
    padding: 24px;
  }}
  .card {{
    width: 100%; max-width: 660px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 16px;
    box-shadow: var(--shadow);
    overflow: hidden;
  }}
  .head {{
    background: linear-gradient(135deg, #c42b2b, #a31e1e);
    padding: 22px 26px; color: #fff;
    display: flex; align-items: center; gap: 14px;
  }}
  .head .logo {{ color: #fff; flex-shrink: 0; }}
  .head .title {{ flex: 1; }}
  .head h1 {{ margin: 0 0 4px 0; font-size: 22px; font-weight: 700; line-height: 1.2; }}
  .head p  {{ margin: 0; font-size: 13.5px; opacity: .92; }}

  .body {{ padding: 22px 28px 24px; }}
  .row {{ margin-bottom: 14px; }}
  .lbl {{ font-size: 12px; color: var(--text-mute); text-transform: uppercase; letter-spacing: .4px; }}
  .val {{ font-size: 14.5px; font-weight: 600; word-break: break-all; margin-top: 4px; color: var(--text); }}
  .det {{ color: #e23b3b; font-family: 'Segoe UI Mono', Consolas, monospace; font-size: 13.5px; }}

  .note {{
    margin-top: 18px; padding: 12px 14px; border-radius: 10px;
    background: var(--note-bg); border: 1px solid var(--note-border);
    font-size: 13px; color: var(--text-dim); line-height: 1.55;
  }}

  .foot {{
    margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--foot-border);
    font-size: 11.5px; color: var(--text-mute);
    display: flex; justify-content: space-between; align-items: center; gap: 10px;
    flex-wrap: wrap;
  }}
  .brand {{ font-weight: 700; color: var(--brand-fg); display: inline-flex; align-items: center; gap: 6px; }}
  .brand .mini {{ color: var(--brand-fg); }}
  .ts {{ font-family: 'Segoe UI Mono', Consolas, monospace; }}
</style>
</head>
<body>
  <main class=""card"" role=""alert"">
    <div class=""head"">
      <div class=""logo"">{logoSvg}</div>
      <div class=""title"">
        <h1>Strona zablokowana</h1>
        <p>Osłona sieciowa Malward zablokowała dostęp do tej witryny.</p>
      </div>
    </div>
    <div class=""body"">
      <div class=""row"">
        <div class=""lbl"">Adres URL</div>
        <div class=""val"">{safeHost}</div>
      </div>
      <div class=""row"">
        <div class=""lbl"">Detekcja</div>
        <div class=""val det"">{detLabel}</div>
      </div>
      <div class=""row"">
        <div class=""lbl"">Źródło</div>
        <div class=""val"">{Escape(srcLabel)}</div>
      </div>
      <div class=""note"">
        Strona została zaklasyfikowana jako szkodliwa lub niezaufana. Otwarcie jej może
        prowadzić do wyłudzenia danych, pobrania złośliwego pliku albo śledzenia użytkownika.
        Jeśli uważasz, że to fałszywy alarm, dodaj domenę do listy wyjątków w ustawieniach
        osłony sieciowej w aplikacji Malward.
      </div>
      <div class=""foot"">
        <span class=""brand""><span class=""mini"">{logoSvg.Replace("width=\"34\" height=\"34\"", "width=\"14\" height=\"14\"")}</span> Malward Community Edition</span>
        <span>Wygenerowano: <time class=""ts"" datetime=""{Escape(tsIso)}"">{Escape(ts)}</time></span>
      </div>
    </div>
  </main>
</body>
</html>";
    }

    private static string Escape(string s)
        => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
#endif

    public void Dispose() => Stop();
}
