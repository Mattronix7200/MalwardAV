using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Malward.NetworkScanner;

public sealed class DnsProxy : IDisposable
{
    public const int DefaultPort = 53;
    public const int FallbackPort = 5353;

    private readonly NetworkConfig _config;
    private readonly UrlBlocklist _blocklist;
    private readonly ServerClient _server;
    private readonly ActivityReporter _activity;
    private BlockPageServer? _blockPage;
    private readonly LolBinNetworkTracker _lolBin;

    private readonly BotIpBlocklist _botIps;

    private readonly UrlBlocklist? _urlCache;

    private UdpClient? _udp;
    private CancellationTokenSource? _cts;
    private Thread? _loop;
    private int _activePort;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (string Verdict, DateTime ExpireUtc)>
        _verdictCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan VerdictCacheTtl = TimeSpan.FromMinutes(5);

    private const int VerdictCacheCap = 5000;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Task<string>>
        _inflight = new(StringComparer.OrdinalIgnoreCase);

    public int ActivePort => _activePort;
    public bool IsRunning => _udp != null;

    public DnsProxy(NetworkConfig config, UrlBlocklist blocklist, ServerClient server,
                    ActivityReporter activity, BlockPageServer? blockPage = null,
                    BotIpBlocklist? botIps = null, UrlBlocklist? urlCache = null)
    {
        _urlCache = urlCache;
        _config   = config;
        _blocklist = blocklist;
        _server   = server;
        _activity = activity;
        _blockPage = blockPage;
        _lolBin   = new LolBinNetworkTracker(activity);
        _botIps   = botIps ?? new BotIpBlocklist(System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "vps-ex01.vdeb"));
    }

    public void Start()
    {
        Stop();
        _udp = TryBind(DefaultPort) ?? TryBind(FallbackPort);
        if (_udp == null)
        {
            Log.Error("DNS",
                $"Failed to open DNS port ({DefaultPort} or {FallbackPort}). " +
                "Check whether the Windows \"DNS Client\" service (Dnscache) is blocking the port, " +
                "or whether another DNS resolver is already listening. Network shield is NOT active.");
            return;
        }

        _cts = new CancellationTokenSource();
        _loop = new Thread(() => ReceiveLoop(_cts.Token))
        {
            IsBackground = true, Name = "DNS-Recv",
        };
        _loop.Start();
        Log.Info("DNS", $"DNS proxy active on 127.0.0.1:{_activePort}, upstream={_config.UpstreamDns}");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _udp?.Close(); _udp?.Dispose(); } catch { }
        _udp = null;
        try { _loop?.Join(2000); } catch { }
        _loop = null;
        _cts?.Dispose();
        _cts = null;
    }

    private UdpClient? TryBind(int port)
    {
        try
        {
            var ep = new IPEndPoint(IPAddress.Loopback, port);
            var u = new UdpClient(ep);
            _activePort = port;
            return u;
        }
        catch (SocketException ex)
        {
            Log.Warn("DNS", $"Bind 127.0.0.1:{port} failed: {ex.SocketErrorCode} ({ex.Message})");
            return null;
        }
        catch (Exception ex)
        {
            Log.Warn("DNS", $"Bind 127.0.0.1:{port} failed: {ex.Message}");
            return null;
        }
    }

    private async void ReceiveLoop(CancellationToken ct)
    {
        var udp = _udp!;
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult req;
            try
            {
                req = await udp.ReceiveAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                Log.Warn("DNS", $"recv error: {ex.Message}");
                continue;
            }

            _ = Task.Run(() => HandleAsync(udp, req, ct));
        }
    }

    private async Task HandleAsync(UdpClient udp, UdpReceiveResult req, CancellationToken ct)
    {
        try
        {
            _activity.ReportQuery();

            string? domain = ParseQName(req.Buffer);
            if (string.IsNullOrEmpty(domain))
            {
                var nx = BuildNxDomain(req.Buffer);
                if (nx != null) await udp.SendAsync(nx, nx.Length, req.RemoteEndPoint);
                return;
            }

            if (_config.IsExcluded(domain))
            {
                await ForwardAsync(udp, req, domain, null, ct, checkBotIps: false);
                return;
            }

            string? proc = null;
            try { proc = ProcessResolver.ResolveUdpProcess(req.RemoteEndPoint.Port); }
            catch { }

            try { _lolBin.TryReportLolBinQuery(proc, domain); } catch { }

            bool cloudMode = string.Equals(_config.Mode, "local+cloud", StringComparison.OrdinalIgnoreCase);

            bool cloudOnly = _config.IsCloudUrlOnly;

            if (!cloudOnly && _blocklist.IsBlocked(domain, out string? matched))
            {
                string det = BuildDetectionName(domain);
                _activity.ReportBlock(domain, detection: det, source: "local", process: proc);
                _blockPage?.NoteBlocked(domain, det, "local");

                Log.Info("DNS", $"local match: {domain} ← entry '{matched}'  proc={proc ?? "?"}");
                Log.Alert("DNS", $"BLOCK [local] {domain} ({proc ?? "?"})");
                var resp = BuildBlockResponse(req.Buffer);
                if (resp != null) await udp.SendAsync(resp, resp.Length, req.RemoteEndPoint);
                return;
            }

            if (_urlCache != null && _urlCache.IsLoaded && _urlCache.IsBlocked(domain, out string? cached))
            {
                string det = BuildDetectionName(domain);
                _activity.ReportBlock(domain, detection: det, source: "cloud", process: proc);
                _blockPage?.NoteBlocked(domain, det, "cloud");
                Log.Info("DNS", $"cached server verdict: {domain} ← entry '{cached}'  proc={proc ?? "?"}");
                Log.Alert("DNS", $"BLOCK [cloud-cache] {domain} ({proc ?? "?"})");
                var cachedResp = BuildBlockResponse(req.Buffer);
                if (cachedResp != null) await udp.SendAsync(cachedResp, cachedResp.Length, req.RemoteEndPoint);
                return;
            }

            if (cloudMode)
            {
                string verdict = await GetCloudVerdictCachedAsync(domain, ct);
                if (string.Equals(verdict, "malware", StringComparison.OrdinalIgnoreCase))
                {
                    string det = BuildDetectionName(domain);
                    _activity.ReportBlock(domain, detection: det, source: "cloud", process: proc);
                    _blockPage?.NoteBlocked(domain, det, "cloud");
                    Log.Alert("DNS", $"BLOCK [cloud] {domain} ({proc ?? "?"})");
                    var resp = BuildBlockResponse(req.Buffer);
                    if (resp != null) await udp.SendAsync(resp, resp.Length, req.RemoteEndPoint);
                    return;
                }

                if (cloudOnly && verdict == VerdictUnavailable && FallbackDatabaseReady()
                                                              && _blocklist.IsBlocked(domain, out string? fallback))
                {
                    string det = BuildDetectionName(domain);
                    _activity.ReportBlock(domain, detection: det, source: "local", process: proc);
                    _blockPage?.NoteBlocked(domain, det, "local");
                    Log.Info("DNS", $"cloud unavailable, local fallback match: {domain} ← entry '{fallback}'  proc={proc ?? "?"}");
                    Log.Alert("DNS", $"BLOCK [local-fallback] {domain} ({proc ?? "?"})");
                    var resp = BuildBlockResponse(req.Buffer);
                    if (resp != null) await udp.SendAsync(resp, resp.Length, req.RemoteEndPoint);
                    return;
                }
            }

            await ForwardAsync(udp, req, domain, proc, ct);
        }
        catch (Exception ex)
        {
            Log.Warn("DNS", $"handler error: {ex.Message}");
        }
    }

    private const string VerdictUnavailable = "unavailable";
    private static readonly TimeSpan UnavailableTtl = TimeSpan.FromSeconds(30);

    private int _fallbackLoadLogged;

    private bool FallbackDatabaseReady()
    {
        bool ready = _blocklist.EnsureLoadedInBackground();
        if (!ready)
        {
            if (Interlocked.CompareExchange(ref _fallbackLoadLogged, 1, 0) == 0)
                Log.Info("DNS", "Cloud URL lookup unavailable — loading the local URL database in the background; queries are forwarded upstream until it is ready.");
        }
        else if (Interlocked.CompareExchange(ref _fallbackLoadLogged, 0, 1) == 1)
        {
            Log.Info("DNS", "Local URL database ready — cloud-only fallback is now serving lookups.");
        }
        return ready;
    }

    private async Task<string> GetCloudVerdictCachedAsync(string domain, CancellationToken ct)
    {
        var key = domain.ToLowerInvariant();

        if (_verdictCache.TryGetValue(key, out var hit) && DateTime.UtcNow < hit.ExpireUtc)
            return hit.Verdict;

        Task<string> task;
        bool owner = false;
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var existing = _inflight.GetOrAdd(key, _ => { owner = true; return tcs.Task; });
        if (!owner)
        {
            try { return await existing.WaitAsync(TimeSpan.FromSeconds(3), ct); }
            catch { return VerdictUnavailable; }
        }

        try
        {
            using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
            to.CancelAfter(TimeSpan.FromSeconds(2));
            var r = await _server.UrlLookupAsync("http://" + domain, to.Token);

            string verdict = r == null ? VerdictUnavailable : (r.Verdict?.ToLowerInvariant() ?? "unknown");

            _verdictCache[key] = (verdict, DateTime.UtcNow.Add(verdict == VerdictUnavailable ? UnavailableTtl : VerdictCacheTtl));

            if (_verdictCache.Count > VerdictCacheCap) PruneVerdictCache();
            Log.Debug("DNS", $"cloud /url {domain}: verdict={verdict} source={r?.Source ?? "-"}");
            tcs.TrySetResult(verdict);
            return verdict;
        }
        catch (Exception ex)
        {
            Log.Debug("DNS", $"cloud /url {domain} EXCEPTION: {ex.GetType().Name}: {ex.Message}");
            _verdictCache[key] = (VerdictUnavailable, DateTime.UtcNow.Add(UnavailableTtl));
            tcs.TrySetResult(VerdictUnavailable);
            return VerdictUnavailable;
        }
        finally
        {
            _inflight.TryRemove(key, out _);
        }
    }

    private void PruneVerdictCache()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _verdictCache)
            if (now > kv.Value.ExpireUtc)
                _verdictCache.TryRemove(kv);
        int over = _verdictCache.Count - VerdictCacheCap;
        if (over <= 0) return;

        var snapshot = System.Linq.Enumerable.ToArray(_verdictCache);
        Array.Sort(snapshot, (a, b) => a.Value.ExpireUtc.CompareTo(b.Value.ExpireUtc));
        for (int i = 0; i < over && i < snapshot.Length; i++)
            _verdictCache.TryRemove(snapshot[i]);
    }

    internal static string BuildDetectionName(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return "MaliciousURL@000000000000";
        try
        {
            using var sha = System.Security.Cryptography.SHA1.Create();
            var bytes = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(domain.ToLowerInvariant()));
            var sb = new System.Text.StringBuilder(12);
            for (int i = 0; i < 6; i++) sb.Append(bytes[i].ToString("x2"));
            return "MaliciousURL@" + sb.ToString();
        }
        catch { return "MaliciousURL@unknown00000"; }
    }

    private async Task ForwardAsync(UdpClient server, UdpReceiveResult req,
                                    string? domain, string? proc, CancellationToken ct,
                                    bool checkBotIps = true)
    {
        try
        {
            var upstream = _config.UpstreamDns;
            if (string.IsNullOrWhiteSpace(upstream)) upstream = "1.1.1.1";

            using var client = new UdpClient();
            client.Client.ReceiveTimeout = 2000;
            await client.SendAsync(req.Buffer, req.Buffer.Length, upstream, 53);

            var recvTask = client.ReceiveAsync();
            using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
            to.CancelAfter(TimeSpan.FromSeconds(2));

            var done = await Task.WhenAny(recvTask, Task.Delay(2000, to.Token));
            if (done == recvTask)
            {
                var resp = recvTask.Result;

                if (checkBotIps && !_botIps.IsEmpty)
                {
                    foreach (var ip in ExtractARecords(resp.Buffer))
                    {
                        if (!_botIps.Contains(ip)) continue;

                        string dom = domain ?? ip;

                        string det = BuildDetectionName(dom);
                        try { _activity.ReportBlock(dom, detection: det, source: "local", process: proc); } catch { }
                        try { _blockPage?.NoteBlocked(dom, det, "local"); } catch { }
                        Log.Alert("DNS", $"BLOCK [malicious-url→C2ip] {dom} → {ip} ({proc ?? "?"})");
                        var block = BuildBlockResponse(req.Buffer);
                        if (block != null) await server.SendAsync(block, block.Length, req.RemoteEndPoint);
                        return;
                    }
                }

                await server.SendAsync(resp.Buffer, resp.Buffer.Length, req.RemoteEndPoint);
            }
        }
        catch {  }
    }

    private static List<string> ExtractARecords(byte[] buf)
    {
        var ips = new List<string>();
        try
        {
            if (buf.Length < 12) return ips;
            int qd = (buf[4] << 8) | buf[5];
            int an = (buf[6] << 8) | buf[7];
            int pos = 12;
            for (int q = 0; q < qd; q++) { pos = SkipName(buf, pos); pos += 4; if (pos > buf.Length) return ips; }
            for (int a = 0; a < an; a++)
            {
                pos = SkipName(buf, pos);
                if (pos + 10 > buf.Length) return ips;
                int type = (buf[pos] << 8) | buf[pos + 1];
                int rdlen = (buf[pos + 8] << 8) | buf[pos + 9];
                pos += 10;
                if (pos + rdlen > buf.Length) return ips;
                if (type == 1 && rdlen == 4)
                    ips.Add($"{buf[pos]}.{buf[pos + 1]}.{buf[pos + 2]}.{buf[pos + 3]}");
                pos += rdlen;
            }
        }
        catch { }
        return ips;
    }

    private static int SkipName(byte[] buf, int pos)
    {
        while (pos < buf.Length)
        {
            int len = buf[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0) { pos += 2; break; }
            pos += 1 + len;
        }
        return pos;
    }

    private static string? ParseQName(byte[] buf)
    {
        try
        {
            if (buf.Length < 13) return null;
            int pos = 12;
            var sb = new StringBuilder(64);
            int safety = 0;
            while (pos < buf.Length && safety++ < 64)
            {
                int len = buf[pos];
                if (len == 0) break;
                if ((len & 0xC0) == 0xC0)
                {
                    break;
                }
                pos++;
                if (pos + len > buf.Length) return null;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(buf, pos, len));
                pos += len;
                if (sb.Length > 253) return null;
            }
            return sb.Length == 0 ? null : sb.ToString().ToLowerInvariant();
        }
        catch { return null; }
    }

    private static byte[]? BuildBlockResponse(byte[] query)
    {
        try
        {
            if (query.Length < 12) return null;

            int p = 12, safety = 0;
            while (p < query.Length && query[p] != 0 && safety++ < 64)
            {
                int len = query[p];
                if ((len & 0xC0) == 0xC0) { p += 2; goto AfterQName; }
                p += 1 + len;
            }
            p += 1;
        AfterQName:
            if (p + 4 > query.Length) return BuildNxDomain(query);
            int qtype = (query[p] << 8) | query[p + 1];
            int qend = p + 4;

            if (qtype != 1 && qtype != 28) return BuildNxDomain(query);

            int rdataLen = qtype == 1 ? 4 : 16;
            int respLen = qend + 2  + 2  + 2  + 4  + 2  + rdataLen;
            var resp = new byte[respLen];
            Buffer.BlockCopy(query, 0, resp, 0, qend);

            byte rd = (byte)(query[2] & 0x01);
            resp[2] = (byte)(0x80 | rd);
            resp[3] = 0x80;
            resp[6] = 0; resp[7] = 1;
            resp[8] = resp[9] = resp[10] = resp[11] = 0;

            int o = qend;

            resp[o++] = 0xC0; resp[o++] = 0x0C;

            resp[o++] = (byte)(qtype >> 8); resp[o++] = (byte)(qtype & 0xFF);

            resp[o++] = 0x00; resp[o++] = 0x01;

            resp[o++] = 0; resp[o++] = 0; resp[o++] = 0; resp[o++] = 60;

            resp[o++] = (byte)(rdataLen >> 8); resp[o++] = (byte)(rdataLen & 0xFF);

            if (qtype == 1)
            {
                resp[o++] = 127; resp[o++] = 0; resp[o++] = 0; resp[o++] = 1;
            }
            else
            {
                for (int i = 0; i < 15; i++) resp[o++] = 0;
                resp[o++] = 1;
            }
            return resp;
        }
        catch { return null; }
    }

    private static byte[]? BuildNxDomain(byte[] query)
    {
        try
        {
            if (query.Length < 12) return null;

            int qend = 12;
            int safety = 0;
            while (qend < query.Length && query[qend] != 0 && safety++ < 64)
            {
                int len = query[qend];
                if ((len & 0xC0) == 0xC0) { qend += 2; goto AfterQName; }
                qend += 1 + len;
            }
            qend += 1;
        AfterQName:

            qend += 4;
            if (qend > query.Length) qend = query.Length;

            var resp = new byte[qend];
            Buffer.BlockCopy(query, 0, resp, 0, qend);

            byte rd = (byte)(query[2] & 0x01);
            resp[2] = (byte)(0x80 | rd);
            resp[3] = 0x83;

            resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
            return resp;
        }
        catch { return null; }
    }

    public void Dispose() => Stop();
}
