using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Malward.NetworkScanner.AdBlock;

namespace Malward.NetworkScanner;

public static class Diagnostics
{
    private const int DefaultDiagnosticPort = 18119;

    private sealed class Outcome
    {
        public string Url = "";
        public int Status;
        public string ContentType = "";
        public string Marker = "pass";
        public long Bytes;
        public int Styles, StyleEnds, Scripts, ScriptEnds;
        public string Untouched = "";
        public string? Html;
        public readonly List<string> Faults = new();
    }

    private static string? _dumpDir;

    private sealed class Pipeline
    {
        public UrlFilterProxy Proxy = null!;
        public UrlFilterProxy Bare = null!;
        public AdBlockService? AdBlock;

        public void Stop() { try { Proxy.Stop(); } catch { } try { Bare.Stop(); } catch { } }
    }

    public static async Task<int> RewriteFileAsync(string inPath, string host, string outPath)
    {
        var pipeline = await BuildAsync(0);
        if (pipeline?.AdBlock?.Store == null)
        {
            Console.WriteLine("FAIL the filter lists did not load");
            return 2;
        }

        var before = await File.ReadAllTextAsync(inPath);
        AdRewriteResult result;
        try
        {
            result = AdPageRewriter.Rewrite(before, host, pipeline.AdBlock.Store,
                                            pipeline.AdBlock.Cosmetics);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAIL the rewriter threw {ex.GetType().Name}: {ex.Message}");
            pipeline.Stop();
            return 1;
        }

        pipeline.Stop();
        var after = result.Changed ? result.Html : before;
        await File.WriteAllTextAsync(outPath, after);

        Console.WriteLine($"{host}: {before.Length} -> {after.Length} chars, "
                          + (result.Changed ? "rewritten" : "not rewritten"));
        Console.WriteLine($"written to {outPath}");
        return 0;
    }

    public static async Task<int> CaptureAsync(string captureDir, int port)
    {
        Directory.CreateDirectory(captureDir);
        UrlFilterProxy.CaptureDirectory = captureDir;

        var pipeline = await BuildAsync(port);
        if (pipeline == null) { UrlFilterProxy.CaptureDirectory = null; return 2; }

        Console.WriteLine();
        Console.WriteLine($"Set the browser proxy to 127.0.0.1:{port} for HTTP and HTTPS,");
        Console.WriteLine("then load the page that breaks.");
        Console.WriteLine($"Recording into {captureDir} — press Ctrl+C when the page has loaded.");
        Console.WriteLine();

        using var finished = new ManualResetEventSlim(false);
        ConsoleCancelEventHandler stop = (_, e) => { e.Cancel = true; finished.Set(); };
        Console.CancelKeyPress += stop;

        int seen = 0;
        while (!finished.IsSet)
        {
            await Task.Delay(500);
            int now = Directory.GetFiles(captureDir).Length;
            if (now == seen) continue;
            foreach (var file in Directory.GetFiles(captureDir).Skip(seen))
                Console.WriteLine($"  recorded {Path.GetFileName(file)}");
            seen = now;
        }

        Console.CancelKeyPress -= stop;
        pipeline.Stop();
        UrlFilterProxy.CaptureDirectory = null;

        Console.WriteLine();
        Console.WriteLine(seen == 0
            ? "Nothing arrived — the browser never used this port. Check the proxy setting."
            : $"{seen} session file(s) in {captureDir}");
        return 0;
    }

    // A browser sends many requests down one connection. If a reply leaves the connection a few
    // bytes out of step, the NEXT reply starts inside the previous body and the browser renders
    // the remains of a stylesheet as text. A client that sends "Connection: close" can never see
    // this, which is why every check so far came back clean.
    public static async Task<int> KeepAliveAsync(string url, int port, int requests)
    {
        var pipeline = await BuildAsync(port);
        if (pipeline == null) return 2;

        int bad = 0;
        try
        {
            var target = new Uri(url);
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            client.ReceiveTimeout = 30000;
            client.SendTimeout = 30000;
            Stream stream = client.GetStream();

            var connect = $"CONNECT {target.Host}:443 HTTP/1.1\r\nHost: {target.Host}:443\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(connect));
            if (!(await ReadHeadersAsync(stream)).Contains(" 200"))
            {
                Console.WriteLine("FAIL the tunnel was refused");
                pipeline.Stop();
                return 1;
            }

            var tls = new System.Net.Security.SslStream(stream, false, (_, _, _, _) => true);
            await tls.AuthenticateAsClientAsync(target.Host);
            stream = tls;

            Console.WriteLine($"{requests} requests down one connection to {target.Host}");
            Console.WriteLine();

            for (int i = 1; i <= requests; i++)
            {
                var request = new StringBuilder();
                request.Append($"GET {target.PathAndQuery} HTTP/1.1\r\n");
                request.Append($"Host: {target.Host}\r\n");
                request.Append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n");
                request.Append("Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n");
                request.Append("Accept-Encoding: gzip, deflate, br\r\n");
                request.Append("Sec-Fetch-Dest: document\r\n");
                request.Append("Connection: keep-alive\r\n\r\n");
                await stream.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()));

                var head = await ReadHeadersAsync(stream);
                if (!head.StartsWith("HTTP/1.", StringComparison.Ordinal))
                {
                    var peek = head.Length > 90 ? head[..90] : head;
                    Console.WriteLine($"FAIL request {i}: the reply does not start with a status line");
                    Console.WriteLine($"     got: {peek.Replace("\r", "").Replace("\n", " ")}");
                    bad++;
                    break;
                }

                var declared = Header(head, "Content-Length");
                var chunked = Header(head, "Transfer-Encoding")?.Contains("chunked",
                    StringComparison.OrdinalIgnoreCase) == true;

                long drained;
                if (declared != null
                    && long.TryParse(declared, NumberStyles.Integer, CultureInfo.InvariantCulture,
                                     out long want))
                {
                    drained = await DrainAsync(stream, want);
                    if (drained != want)
                    {
                        Console.WriteLine($"FAIL request {i}: promised {want} bytes, got {drained}");
                        bad++;
                        break;
                    }
                }
                else if (chunked)
                {
                    drained = await DrainChunkedAsync(stream);
                }
                else
                {
                    Console.WriteLine($"FAIL request {i}: neither a length nor chunked framing — "
                                      + "the connection cannot be reused");
                    bad++;
                    break;
                }

                var status = head.Split(' ') is { Length: > 1 } p ? p[1] : "?";
                Console.WriteLine($"OK   request {i}: {status}, {drained} bytes, "
                                  + (chunked ? "chunked" : "declared length"));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAIL {ex.GetType().Name}: {ex.Message}");
            bad++;
        }

        pipeline.Stop();
        Console.WriteLine();
        Console.WriteLine(bad == 0
            ? "the connection stayed in step for every request"
            : "the connection went out of step — this is what breaks the page");
        return bad == 0 ? 0 : 1;
    }

    private static async Task<long> DrainAsync(Stream stream, long count)
    {
        var buffer = new byte[64 * 1024];
        long read = 0;
        while (read < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(0,
                (int)Math.Min(buffer.Length, count - read)));
            if (n <= 0) break;
            read += n;
        }
        return read;
    }

    private static async Task<long> DrainChunkedAsync(Stream stream)
    {
        long total = 0;
        while (true)
        {
            var line = new StringBuilder();
            var one = new byte[1];
            while (true)
            {
                int n = await stream.ReadAsync(one);
                if (n <= 0) return total;
                if (one[0] == (byte)'\n') break;
                if (one[0] != (byte)'\r') line.Append((char)one[0]);
            }

            var sizeText = line.ToString().Split(';')[0].Trim();
            if (!int.TryParse(sizeText, NumberStyles.HexNumber, null, out int size)) return total;
            if (size == 0)
            {
                await ReadHeadersTailAsync(stream);
                return total;
            }
            total += await DrainAsync(stream, size);
            await DrainAsync(stream, 2);
        }
    }

    private static async Task ReadHeadersTailAsync(Stream stream)
    {
        var one = new byte[1];
        int newlines = 0;
        while (newlines < 1)
        {
            int n = await stream.ReadAsync(one);
            if (n <= 0) return;
            if (one[0] == (byte)'\n') newlines++;
        }
    }

    public static async Task<int> RunAsync(string listFile, int port, string? dumpDir = null)
    {
        _dumpDir = dumpDir;
        if (_dumpDir != null) Directory.CreateDirectory(_dumpDir);
        if (!File.Exists(listFile))
        {
            Console.Error.WriteLine($"No such file: {listFile}");
            return 2;
        }

        var urls = File.ReadAllLines(listFile)
                       .Select(l => l.Trim())
                       .Where(l => l.Length > 0 && !l.StartsWith('#'))
                       .ToList();

        var pipeline = await BuildAsync(port);
        if (pipeline == null) return 2;
        var adBlock = pipeline.AdBlock;

        var results = new List<Outcome>();
        foreach (var url in urls)
        {
            var outcome = await AskAsync(url, port + 1, "raw");
            if (outcome.Html != null && adBlock?.Store is { IsLoaded: true })
                CheckRewrite(outcome, adBlock);
            results.Add(outcome);
        }

        pipeline.Stop();

        Report(results);
        return results.Any(r => r.Faults.Count > 0) ? 1 : 0;
    }

    private static async Task<Pipeline?> BuildAsync(int port)
    {
        NetworkConfig config;
        try { config = NetworkConfig.Load(null); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Settings could not be read: {ex.Message}");
            return null;
        }

        var data = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "data");

        var blocklist = new UrlBlocklist(lowMemory: config.LowMemory, deferred: config.IsCloudUrlOnly);
        var urlCache = new UrlBlocklist(Path.Combine(data, "vps-ex03.vdeb"),
                                        lowMemory: true, deferred: false, exclusivePath: true);
        blocklist.MaybeReload();
        urlCache.MaybeReload();
        blocklist.EnsureLoadedInBackground();
        for (int i = 0; i < 400 && !blocklist.IsLoaded; i++) await Task.Delay(50);

        var rootCa = new RootCaManager();
        rootCa.EnsureInstalled();
        if (!rootCa.IsAvailable)
        {
            Console.Error.WriteLine("The root certificate is not available, so HTTPS cannot be inspected.");
            return null;
        }

        AdBlockService? adBlock = null;
        if (config.AdBlockingEnabled)
        {
            adBlock = new AdBlockService();
            adBlock.Cosmetics.Cosmetic = config.AdBlockCosmetic;
            adBlock.Cosmetics.CosmeticGeneric = config.AdBlockCosmeticGeneric;
            adBlock.Cosmetics.Scriptlets = config.AdBlockScriptlets;
            adBlock.Cosmetics.YouTube = config.AdBlockYouTube;
            adBlock.Cosmetics.Stealth = config.AdBlockStealth;
            adBlock.Start(enabled: true, httpFiltering: config.AdBlockHttpFilter && config.HttpFilter);
            for (int i = 0; i < 600 && !adBlock.IsLoaded; i++) await Task.Delay(100);
        }

        var activity = new ActivityReporter();
        var dns = new DnsProxy(config, blocklist, new ServerClient(), activity, null, null, urlCache);
        dns.AttachAdBlock(adBlock);

        var proxy = new UrlFilterProxy(new LeafCertCache(rootCa), activity, null,
            (host, path, inspected, ct) => dns.VerdictForHttpAsync(host, path, inspected, ct),
            host => dns.HasPathRules(host),
            (host, path) => dns.PathVerdict(host, path));
        proxy.AttachAdBlock(adBlock);

        var bare = new UrlFilterProxy(new LeafCertCache(rootCa), activity, null,
            (_, _, _, _) => Task.FromResult((false, (string?)null, (string?)null)));

        if (!proxy.Start(port) || !bare.Start(port + 1))
        {
            Console.Error.WriteLine($"Could not open the diagnostic ports {port} and {port + 1}.");
            return null;
        }

        Console.WriteLine($"address database: {(blocklist.IsLoaded ? "loaded" : "NOT loaded")}   "
                          + $"cloud cache: {(urlCache.IsLoaded ? "loaded" : "NOT loaded")}   "
                          + $"filter lists: {(adBlock?.IsLoaded == true ? "loaded" : "off")}   "
                          + $"port: {port}");
        Console.WriteLine();

        return new Pipeline { Proxy = proxy, Bare = bare, AdBlock = adBlock };
    }

    private static async Task<Outcome> AskAsync(string url, int port, string tag = "")
    {
        var outcome = new Outcome { Url = url };
        try
        {
            var target = new Uri(url);
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            client.ReceiveTimeout = 30000;
            client.SendTimeout = 30000;

            Stream stream = client.GetStream();

            if (target.Scheme == "https")
            {
                var connect = $"CONNECT {target.Host}:443 HTTP/1.1\r\nHost: {target.Host}:443\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(connect));
                var established = await ReadHeadersAsync(stream);
                if (!established.Contains(" 200"))
                {
                    outcome.Faults.Add("the tunnel was refused");
                    return outcome;
                }

                var tls = new System.Net.Security.SslStream(stream, false,
                    (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync(target.Host);
                stream = tls;
            }

            var path = target.PathAndQuery;
            var request = new StringBuilder();
            request.Append($"GET {path} HTTP/1.1\r\n");
            request.Append($"Host: {target.Host}\r\n");
            request.Append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n");
            request.Append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
            request.Append("Accept-Encoding: gzip, deflate, br\r\n");
            request.Append("Sec-Fetch-Dest: document\r\n");
            request.Append("Sec-Fetch-Mode: navigate\r\n");
            request.Append("Connection: close\r\n\r\n");
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()));

            var head = await ReadHeadersAsync(stream);
            Measure(outcome, head);

            using var body = new MemoryStream();
            await stream.CopyToAsync(body);
            var bytes = body.ToArray();
            Judge(outcome, head, bytes);
            Dump(url, tag, head, bytes);
            outcome.Html = Body(head, bytes);
        }
        catch (Exception ex)
        {
            outcome.Faults.Add($"{ex.GetType().Name}: {ex.Message}");
        }
        return outcome;
    }

    private static string? Body(string head, byte[] body)
    {
        var chunked = Header(head, "Transfer-Encoding")?.Contains("chunked",
            StringComparison.OrdinalIgnoreCase) == true;
        var payload = chunked ? Unframe(body) : body;
        return AdPageRewriter.Decode(payload, Header(head, "Content-Encoding"));
    }

    private static void Dump(string url, string tag, string head, byte[] body)
    {
        if (_dumpDir == null || tag.Length == 0) return;
        try
        {
            var name = new string(new Uri(url).Host.Concat(new Uri(url).PathAndQuery).ToArray());
            foreach (var bad in Path.GetInvalidFileNameChars()) name = name.Replace(bad, '_');
            if (name.Length > 80) name = name[..80];

            var chunked = Header(head, "Transfer-Encoding")?.Contains("chunked",
                StringComparison.OrdinalIgnoreCase) == true;
            var payload = chunked ? Unframe(body) : body;
            var text = AdPageRewriter.Decode(payload, Header(head, "Content-Encoding"));
            File.WriteAllText(Path.Combine(_dumpDir, $"{name}.{tag}.html"), text ?? "", Encoding.UTF8);
        }
        catch { }
    }

    private static void CheckRewrite(Outcome outcome, AdBlockService adBlock)
    {
        var before = outcome.Html!;
        var host = new Uri(outcome.Url).Host;

        AdRewriteResult result;
        try { result = AdPageRewriter.Rewrite(before, host, adBlock.Store!, adBlock.Cosmetics); }
        catch (Exception ex)
        {
            outcome.Faults.Add($"the rewriter threw {ex.GetType().Name}");
            return;
        }

        if (!result.Changed) { outcome.Untouched = "not rewritten"; return; }

        var after = result.Html;
        outcome.Untouched = $"+{result.Scriptlets}s +{result.CosmeticSelectors}c";

        int styleBefore = Count(before, "<style") - Count(before, "</style>");
        int styleAfter = Count(after, "<style") - Count(after, "</style>");
        if (styleBefore != styleAfter)
            outcome.Faults.Add($"the rewrite changed the <style> balance {styleBefore} -> {styleAfter}");

        int scriptBefore = Count(before, "<script") - Count(before, "</script>");
        int scriptAfter = Count(after, "<script") - Count(after, "</script>");
        if (scriptBefore != scriptAfter)
            outcome.Faults.Add($"the rewrite changed the <script> balance {scriptBefore} -> {scriptAfter}");

        // Everything the page had must still be there: the rewriter only inserts.
        if (after.Length < before.Length)
            outcome.Faults.Add($"the rewrite lost {before.Length - after.Length} characters");

        var headBefore = before.TrimStart();
        var headAfter = after.TrimStart();
        if (headBefore.StartsWith("<", StringComparison.Ordinal)
            && !headAfter.StartsWith(headBefore[..Math.Min(15, headBefore.Length)], StringComparison.Ordinal))
            outcome.Faults.Add("the rewrite moved the start of the document");
    }

    private static async Task<string> ReadHeadersAsync(Stream stream)
    {
        var buffer = new List<byte>(8192);
        var one = new byte[1];
        while (buffer.Count < 65536)
        {
            int n = await stream.ReadAsync(one);
            if (n <= 0) break;
            buffer.Add(one[0]);
            int c = buffer.Count;
            if (c >= 4 && buffer[c - 4] == 13 && buffer[c - 3] == 10
                       && buffer[c - 2] == 13 && buffer[c - 1] == 10) break;
        }
        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static void Measure(Outcome outcome, string head)
    {
        var lines = head.Split("\r\n");
        var first = lines.Length > 0 ? lines[0].Split(' ') : Array.Empty<string>();
        if (first.Length > 1) int.TryParse(first[1], out outcome.Status);

        outcome.ContentType = Header(head, "Content-Type") ?? "";
        if (Header(head, "X-Malward-AdBlock") != null) outcome.Marker = "ad-blocked";
        if (Header(head, "X-Malward-Block") != null) outcome.Marker = "THREAT-BLOCKED";
    }

    private static void Judge(Outcome outcome, string head, byte[] body)
    {
        outcome.Bytes = body.Length;

        var transfer = Header(head, "Transfer-Encoding");
        var declared = Header(head, "Content-Length");
        bool chunked = transfer != null
                       && transfer.Contains("chunked", StringComparison.OrdinalIgnoreCase);

        // The framing the headers promise has to be the framing the bytes actually use, or the
        // browser throws away whatever it cannot line up -- which is how a page loses the tags
        // around its stylesheet and starts printing CSS as text.
        if (chunked && !LooksChunked(body))
            outcome.Faults.Add("says chunked, body is not framed");

        if (!chunked && declared != null
            && long.TryParse(declared, NumberStyles.Integer, CultureInfo.InvariantCulture, out long want)
            && want != body.Length)
            outcome.Faults.Add($"Content-Length {want} but {body.Length} bytes arrived");

        if (chunked && declared != null)
            outcome.Faults.Add("both Transfer-Encoding and Content-Length");

        if (outcome.ContentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        {
            var payload = chunked ? Unframe(body) : body;
            var text = AdPageRewriter.Decode(payload, Header(head, "Content-Encoding"));
            if (!string.IsNullOrEmpty(text)) JudgeHtml(outcome, text!);
            else if (payload.Length > 0) outcome.Faults.Add("the body could not be decoded");
        }
    }

    private static void JudgeHtml(Outcome outcome, string html)
    {
        outcome.Styles = Count(html, "<style");
        outcome.StyleEnds = Count(html, "</style>");
        if (outcome.Styles != outcome.StyleEnds)
            outcome.Faults.Add($"{outcome.Styles} <style> against {outcome.StyleEnds} </style>");

        outcome.Scripts = Count(html, "<script");
        outcome.ScriptEnds = Count(html, "</script>");
        if (outcome.Scripts != outcome.ScriptEnds)
            outcome.Faults.Add($"{outcome.Scripts} <script> against {outcome.ScriptEnds} </script>");

        var head = html.Length > 4096 ? html[..4096] : html;
        if (!head.Contains("<!doctype", StringComparison.OrdinalIgnoreCase)
            && !head.Contains("<html", StringComparison.OrdinalIgnoreCase))
            outcome.Faults.Add("the document does not start with a document");
    }

    private static byte[] Unframe(byte[] body)
    {
        using var output = new MemoryStream();
        int i = 0;
        while (i < body.Length)
        {
            int eol = Array.IndexOf(body, (byte)'\n', i);
            if (eol < 0) break;
            var sizeText = Encoding.ASCII.GetString(body, i, eol - i).Split(';')[0].Trim();
            if (!int.TryParse(sizeText, NumberStyles.HexNumber, null, out int size)) break;
            i = eol + 1;
            if (size == 0 || i + size > body.Length) break;
            output.Write(body, i, size);
            i += size;
            while (i < body.Length && (body[i] == (byte)'\r' || body[i] == (byte)'\n')) i++;
        }
        return output.Length > 0 ? output.ToArray() : body;
    }

    private static bool LooksChunked(byte[] body)
    {
        int eol = Array.IndexOf(body, (byte)'\n');
        if (eol <= 0 || eol > 20) return false;
        var sizeText = Encoding.ASCII.GetString(body, 0, eol).Split(';')[0].Trim();
        return sizeText.Length > 0
               && int.TryParse(sizeText, NumberStyles.HexNumber, null, out _);
    }

    private static int Count(string haystack, string needle)
    {
        int n = 0, i = 0;
        while ((i = haystack.IndexOf(needle, i, StringComparison.OrdinalIgnoreCase)) >= 0) { n++; i += needle.Length; }
        return n;
    }

    private static string? Header(string head, string name)
    {
        foreach (var line in head.Split("\r\n"))
        {
            if (line.Length > name.Length && line[name.Length] == ':'
                && line.StartsWith(name, StringComparison.OrdinalIgnoreCase))
                return line[(name.Length + 1)..].Trim();
        }
        return null;
    }

    private static void Report(List<Outcome> results)
    {
        Console.WriteLine($"{"address",-40} {"verdict",-14} {"code",4} {"bytes",9} "
                          + $"{"tags",-12} {"injected",-14} what is wrong");
        Console.WriteLine(new string('-', 136));
        foreach (var r in results)
        {
            var host = r.Url.Length > 40 ? r.Url[..40] : r.Url;
            var mine = $"{r.Styles}/{r.StyleEnds} {r.Scripts}/{r.ScriptEnds}";
            Console.WriteLine($"{host,-40} {r.Marker,-14} {r.Status,4} {r.Bytes,9} "
                              + $"{mine,-12} {r.Untouched,-14} "
                              + (r.Faults.Count == 0 ? "" : string.Join("; ", r.Faults)));
        }
        Console.WriteLine(new string('-', 118));
        int broken = results.Count(r => r.Faults.Count > 0);
        Console.WriteLine(broken == 0
            ? $"{results.Count} addresses, none damaged in transit"
            : $"{broken} of {results.Count} addresses come back damaged");
    }

    public static int ParsePort(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] == "--port" && int.TryParse(args[i + 1], out int p)) return p;
        return DefaultDiagnosticPort;
    }
}
