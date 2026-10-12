using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class WebUiServer : IDisposable
{
    private readonly AssetPack _assets;
    private readonly Action<string, string> _onMessage;
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _stop = new();

    private readonly object _queueLock = new();
    private readonly List<(long Seq, string Json)> _queue = new();
    private long _seq;

    private const int MaxQueued = 2000;

    private static readonly string[] LatestWins =
    {
        "\"type\":\"scan.progress\"",
        "\"type\":\"resident.activity.raw\"",
        "\"type\":\"network.activity.raw\"",
    };

    public int Port { get; }
    public string Key { get; }

    public string Url => $"http://127.0.0.1:{Port}/?k={Key}";

    private readonly Func<(string Theme, string Lang, string Edition)>? _stan;

    public WebUiServer(AssetPack assets, Action<string, string> onMessage,
                       int preferredPort = 9099, Func<(string, string, string)>? stan = null)
    {
        _assets = assets;
        _onMessage = onMessage;
        _stan = stan;
        Key = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        Port = ZnajdzPort(preferredPort);
        _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
    }

    private static int ZnajdzPort(int preferowany)
    {
        foreach (var p in Enumerable.Range(preferowany, 20))
        {
            try
            {
                var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, p);
                l.Start(); l.Stop();
                return p;
            }
            catch { }
        }
        return 0;
    }

    public void Start()
    {
        _listener.Start();
        _ = Task.Run(PetlaAsync);
    }

    public void Push(string json)
    {
        lock (_queueLock)
        {
            var typ = TypZastepowalny(json);
            if (typ != null)
            {
                for (int i = _queue.Count - 1; i >= 0; i--)
                {
                    if (!_queue[i].Json.Contains(typ, StringComparison.Ordinal)) continue;
                    _queue.RemoveAt(i);
                    break;
                }
            }

            _queue.Add((++_seq, json));
            if (_queue.Count > MaxQueued) _queue.RemoveRange(0, _queue.Count - MaxQueued);
        }
    }

    private static string? TypZastepowalny(string json)
    {
        foreach (var t in LatestWins)
            if (json.Contains(t, StringComparison.Ordinal)) return t;
        return null;
    }

    private async Task PetlaAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch { break; }
            _ = Task.Run(() => ObsluzAsync(ctx));
        }
    }

    private async Task ObsluzAsync(HttpListenerContext ctx)
    {
        try
        {
            if (!IsAllowed(ctx.Request))
            {
                ctx.Response.StatusCode = 403;
                ctx.Response.Close();
                return;
            }

            var sciezka = ctx.Request.Url?.AbsolutePath ?? "/";
            if (sciezka == "/api/post")      { await PrzyjmijAsync(ctx); return; }
            if (sciezka == "/api/poll")      { await OddajAsync(ctx);    return; }
            if (sciezka == "/api/upload")    { await PrzyjmijPlikAsync(ctx); return; }
            await ServeFileAsync(ctx, sciezka);
        }
        catch
        {
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    }

    private bool IsAllowed(HttpListenerRequest req)
    {
        var host = req.Headers["Host"] ?? "";
        if (!string.Equals(host, $"127.0.0.1:{Port}", StringComparison.Ordinal)) return false;

        var origin = req.Headers["Origin"];
        if (!string.IsNullOrEmpty(origin)
            && !string.Equals(origin, $"http://127.0.0.1:{Port}", StringComparison.Ordinal)) return false;

        var klucz = req.Headers["X-Malward-Key"]
                 ?? req.QueryString["k"]
                 ?? req.Cookies["mw"]?.Value
                 ?? "";
        return PorownajStalym(klucz);
    }

    private bool PorownajStalym(string kandydat)
        => CryptographicOperations.FixedTimeEquals(
               Encoding.ASCII.GetBytes(kandydat.PadRight(Key.Length)[..Key.Length]),
               Encoding.ASCII.GetBytes(Key));

    private async Task PrzyjmijAsync(HttpListenerContext ctx)
    {
        string body;
        using (var r = new System.IO.StreamReader(ctx.Request.InputStream, Encoding.UTF8))
            body = await r.ReadToEndAsync();

        string typ = "";
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("type", out var t)) typ = t.GetString() ?? "";
        }
        catch { }

        if (typ.Length > 0) _onMessage(typ, body);
        ctx.Response.StatusCode = 204;
        ctx.Response.Close();
    }

    public static string UploadDir { get; } = System.IO.Path.Combine(
        Malward.Engine.Util.Paths.AppDataDir, "web-upload");

    private const long MaxUploadBytes = 1024L * 1024 * 1024;

    public static void ClearUploads()
    {
        try
        {
            if (System.IO.Directory.Exists(UploadDir))
                System.IO.Directory.Delete(UploadDir, recursive: true);
        }
        catch { }
    }

    private static string SafeName(string? raw)
    {
        var name = string.IsNullOrWhiteSpace(raw) ? "plik" : Uri.UnescapeDataString(raw);
        name = System.IO.Path.GetFileName(name);
        foreach (var ch in System.IO.Path.GetInvalidFileNameChars())
            name = name.Replace(ch, '_');
        if (name.Length == 0) name = "plik";
        return name.Length > 150 ? name[^150..] : name;
    }

    private async Task PrzyjmijPlikAsync(HttpListenerContext ctx)
    {
        if (!string.Equals(ctx.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = 405;
            ctx.Response.Close();
            return;
        }

        if (ctx.Request.ContentLength64 > MaxUploadBytes)
        {
            await PiszAsync(ctx, "application/json",
                Encoding.UTF8.GetBytes("{\"error\":\"too-large\"}"));
            return;
        }

        var katalog = System.IO.Path.Combine(UploadDir, Guid.NewGuid().ToString("N")[..8]);
        System.IO.Directory.CreateDirectory(katalog);
        var cel = System.IO.Path.Combine(katalog, SafeName(ctx.Request.Headers["X-Malward-Name"]));

        long zapisane = 0;
        try
        {
            using var wy = System.IO.File.Create(cel);
            var bufor = new byte[128 * 1024];
            while (true)
            {
                int n = await ctx.Request.InputStream.ReadAsync(bufor, _stop.Token);
                if (n <= 0) break;
                zapisane += n;
                if (zapisane > MaxUploadBytes) throw new System.IO.IOException("upload too large");
                await wy.WriteAsync(bufor.AsMemory(0, n), _stop.Token);
            }
        }
        catch
        {
            try { System.IO.Directory.Delete(katalog, recursive: true); } catch { }
            await PiszAsync(ctx, "application/json",
                Encoding.UTF8.GetBytes("{\"error\":\"write-failed\"}"));
            return;
        }

        await PiszAsync(ctx, "application/json",
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { path = cel, size = zapisane })));
    }

    private async Task OddajAsync(HttpListenerContext ctx)
    {
        long od = long.TryParse(ctx.Request.QueryString["since"], out var v) ? v : 0;

        if (od <= 0)
        {
            long teraz;
            lock (_queueLock) teraz = _seq;
            await PiszAsync(ctx, "application/json",
                Encoding.UTF8.GetBytes("{\"last\":" + teraz + ",\"items\":[]}"));
            return;
        }

        var koniec = DateTime.UtcNow.AddSeconds(25);

        while (DateTime.UtcNow < koniec && !_stop.IsCancellationRequested)
        {
            List<(long Seq, string Json)> partia;
            lock (_queueLock) partia = _queue.Where(x => x.Seq > od).ToList();
            if (partia.Count > 0)
            {
                var sb = new StringBuilder("{\"last\":").Append(partia[^1].Seq).Append(",\"items\":[");
                for (int i = 0; i < partia.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append(partia[i].Json);
                }
                sb.Append("]}");
                await PiszAsync(ctx, "application/json", Encoding.UTF8.GetBytes(sb.ToString()));
                return;
            }
            await Task.Delay(120);
        }

        long ostatni;
        lock (_queueLock) ostatni = _seq;
        await PiszAsync(ctx, "application/json",
                        Encoding.UTF8.GetBytes($"{{\"last\":{Math.Max(od, ostatni)},\"items\":[]}}"));
    }

    private async Task ServeFileAsync(HttpListenerContext ctx, string sciezka)
    {
        var rel = sciezka.TrimStart('/');
        if (rel.Length == 0) rel = "index.html";
        if (!_assets.TryGet(rel, out var dane))
        {
            ctx.Response.StatusCode = 404;
            ctx.Response.Close();
            return;
        }
        if (rel.Equals("index.html", StringComparison.OrdinalIgnoreCase))
        {
            dane = InjectBridge(dane, _stan?.Invoke() ?? ("auto", "pl", "null"));

            ctx.Response.Headers["Set-Cookie"] = $"mw={Key}; Path=/; HttpOnly; SameSite=Strict";
        }
        await PiszAsync(ctx, AssetPack.ContentTypeFor(rel), dane);
    }

    private static async Task PiszAsync(HttpListenerContext ctx, string typ, byte[] dane)
    {
        ctx.Response.ContentType = typ;
        ctx.Response.ContentLength64 = dane.Length;

        ctx.Response.Headers["Cache-Control"] = "no-store";
        await ctx.Response.OutputStream.WriteAsync(dane);
        ctx.Response.Close();
    }

    private static byte[] InjectBridge(byte[] indexHtml,
                                      (string Theme, string Lang, string Edition) stan)
    {
        const string Marker = "<script src=\"/app.js\"></script>";
        var html = Encoding.UTF8.GetString(indexHtml);
        if (!html.Contains(Marker)) return indexHtml;

        const string BridgeScript = """
<script>

(function () {
  window.__MALWARD_WEB__ = { theme: "@MOTYW@", lang: "@JEZYK@" };
  window.__MALWARD_EDITION__ = @WYDANIE@;
  try { document.documentElement.setAttribute("data-theme", "@MOTYW@"); } catch (e) {}

  document.addEventListener("DOMContentLoaded", function () {
    try { document.body.classList.add("web-ui"); } catch (e) {}
  });
  var q = new URLSearchParams(location.search);
  var k = q.get("k") || "";

  window.__mwEvent = q.get("ev") || "";

  try { history.replaceState(null, "", location.pathname + location.hash); } catch (e) {}
  function naglowki() { return { "Content-Type": "application/json", "X-Malward-Key": k }; }
  window.__mwKey = k;

  window.chrome = window.chrome || {};
  window.chrome.webview = {
    postMessage: function (m) {
      fetch("/api/post", { method: "POST", headers: naglowki(), body: JSON.stringify(m) })
        .catch(function (e) { console.error("post", e); });
    }
  };

  var od = 0, przerwa = 0;
  function pobieraj() {
    fetch("/api/poll?since=" + od, { headers: { "X-Malward-Key": k } })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        od = d.last || od;
        przerwa = 0;
        (d.items || []).forEach(function (env) {
          try { window.malward && window.malward.onEvent(env); }
          catch (e) { console.error("onEvent", e); }
        });
        pobieraj();
      })
      .catch(function () {
        przerwa = Math.min((przerwa || 500) * 2, 10000);
        setTimeout(pobieraj, przerwa);
      });
  }
  pobieraj();
})();
</script>
""";
        var most = BridgeScript.Replace("@MOTYW@", Sanitize(stan.Theme, "auto"))
                       .Replace("@JEZYK@", Sanitize(stan.Lang, "pl"))
                       .Replace("@WYDANIE@", SanitizeJson(stan.Edition));
        return Encoding.UTF8.GetBytes(html.Replace(Marker, most + "\n" + Marker));
    }

    private static string SanitizeJson(string? v)
    {
        if (string.IsNullOrEmpty(v) || v.Length > 512) return "null";
        foreach (var c in v)
        {
            bool ok = char.IsAsciiLetterOrDigit(c) || c is '{' or '}' or '"' or ':' or ','
                      or ' ' or '.' or '-' or '_';
            if (!ok) return "null";
        }
        return v;
    }

    private static string Sanitize(string? v, string domyslna)
    {
        if (string.IsNullOrEmpty(v) || v.Length > 16) return domyslna;
        foreach (var c in v)
            if (!char.IsAsciiLetter(c) && c != '-') return domyslna;
        return v;
    }

    public void Dispose()
    {
        try { _stop.Cancel(); } catch { }
        try { _listener.Stop(); } catch { }
        try { _listener.Close(); } catch { }
        _stop.Dispose();
    }
}
