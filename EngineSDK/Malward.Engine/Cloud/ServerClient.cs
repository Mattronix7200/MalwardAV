using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Malward.Engine.Config;

namespace Malward.Engine.Cloud;

public sealed class ServerClient : IDisposable
{
    public sealed record HashResponse(
        [property: JsonPropertyName("verdict")]  string Verdict,
        [property: JsonPropertyName("name")]     string? Name,
        [property: JsonPropertyName("action")]   string? Action,

        [property: JsonPropertyName("source")]   string? Source = null,
        [property: JsonPropertyName("age_days")] int? AgeDays = null);

    public sealed record EngineSummary(
        [property: JsonPropertyName("engine")]      string Engine,
        [property: JsonPropertyName("detected")]    bool Detected,
        [property: JsonPropertyName("name")]        string? Name,
        [property: JsonPropertyName("elapsed_ms")]  long ElapsedMs,
        [property: JsonPropertyName("error")]       string? Error);

    public sealed record ScanResponse(
        [property: JsonPropertyName("verdict")]  string Verdict,
        [property: JsonPropertyName("name")]     string? Name,
        [property: JsonPropertyName("sha256")]   string Sha256,
        [property: JsonPropertyName("engines")]  List<EngineSummary> Engines,

        [property: JsonPropertyName("label")]       string? Label = null,
        [property: JsonPropertyName("vt_detected")] int? VtDetected = null,
        [property: JsonPropertyName("vt_total")]    int? VtTotal = null);

    public sealed record FileMeta(
        [property: JsonPropertyName("sha256")]      string? Sha256,
        [property: JsonPropertyName("size")]        long Size,
        [property: JsonPropertyName("version_ts")]  long VersionTs,
        [property: JsonPropertyName("available")]   bool Available);

    public sealed record Manifest(
        [property: JsonPropertyName("vps")]        FileMeta Vps,
        [property: JsonPropertyName("heur")]       FileMeta Heur,
        [property: JsonPropertyName("whitelist")]  FileMeta Whitelist,
        [property: JsonPropertyName("sandbox")]    FileMeta? Sandbox = null);

    public sealed record DbInfoEntry(
        [property: JsonPropertyName("sha256")]          string? Sha256,
        [property: JsonPropertyName("seq")]             long Seq,
        [property: JsonPropertyName("base_seq")]        long BaseSeq,
        [property: JsonPropertyName("delta_available")] bool DeltaAvailable,
        [property: JsonPropertyName("version")]         string? Version);

    public sealed record DbInfo(
        [property: JsonPropertyName("vps")]       DbInfoEntry? Vps,
        [property: JsonPropertyName("whitelist")] DbInfoEntry? Whitelist);

    public sealed record DeltaResponse(
        [property: JsonPropertyName("mode")]     string Mode,        
        [property: JsonPropertyName("from_seq")] long FromSeq,
        [property: JsonPropertyName("to_seq")]   long ToSeq,
        [property: JsonPropertyName("added")]    List<string>? Added = null,
        [property: JsonPropertyName("removed")]  List<string>? Removed = null);

    private const string CLIENT_ID = "malward-engine";

    private readonly Settings _settings;
    private readonly HttpClient _http;
    private readonly Uri _base;

    private string? _sessionToken;
    private DateTime _sessionExpiresUtc = DateTime.MinValue;
    private readonly SemaphoreSlim _authLock = new(1, 1);

    public ServerClient(Settings settings)
    {
        _settings = settings;
        _base = new Uri($"https://{settings.ServerIp}:{settings.ServerPort}/");

        _http = new HttpClient(NewHandler())
        {
            BaseAddress = _base,

            Timeout = TimeSpan.FromSeconds(Math.Max(30, settings.MaxUploadToCloudSec)),
        };

        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", settings.ClientToken);
    }

    private HttpClientHandler NewHandler() => new()
    {
        ServerCertificateCustomValidationCallback = ValidatePinned,
    };

    private HttpClient UnlimitedClient()
    {
        if (_httpUnlimited != null) return _httpUnlimited;
        lock (_unlimitedLock)
            _httpUnlimited ??= new HttpClient(NewHandler())
            {
                BaseAddress = _base,
                Timeout = Timeout.InfiniteTimeSpan,
            };
        return _httpUnlimited;
    }

    private HttpClient? _httpUnlimited;
    private readonly object _unlimitedLock = new();

    private int _authGeneration;

    /// <summary>Runs a request and, on a 401, gets a new session once and repeats it.</summary>
    /// <remarks>
    /// A session can die while the client still believes in it - the server keeps sessions in
    /// memory, so a restart invalidates every token in circulation, and the cached one on disk
    /// survives a client restart too. Without this the scan kept sending a dead token and read
    /// every answer as "verification failed", which turns bloom hits into unverified detections.
    /// The generation counter stops twenty scanner threads from asking for twenty new tokens.
    /// </remarks>
    private async Task<HttpResponseMessage> SendAuthedAsync(
        Func<Task<HttpResponseMessage>> send, CancellationToken ct)
    {
        await EnsureAuthAsync(ct);
        int generation = Volatile.Read(ref _authGeneration);

        var resp = await send();
        if (resp.StatusCode != System.Net.HttpStatusCode.Unauthorized) return resp;

        resp.Dispose();
        await RefreshAuthAsync(generation, ct);
        return await send();
    }

    private DateTime _authRetryNotBeforeUtc = DateTime.MinValue;
    private static readonly TimeSpan AuthRetryCooldown = TimeSpan.FromSeconds(30);

    private async Task RefreshAuthAsync(int seenGeneration, CancellationToken ct)
    {
        await _authLock.WaitAsync(ct);
        try
        {
            if (Volatile.Read(ref _authGeneration) != seenGeneration) return;
            if (DateTime.UtcNow < _authRetryNotBeforeUtc) return;

            Console.Error.WriteLine("[!] auth: server rejected the session token — asking for a new one");
            _sessionToken = null;
            _sessionExpiresUtc = DateTime.MinValue;
            _http.DefaultRequestHeaders.Authorization = null;
            SessionCache.Clear();

            await AcquireTokenAsync(ct);
            _authRetryNotBeforeUtc = DateTime.MinValue;
            Interlocked.Increment(ref _authGeneration);
        }
        catch (Exception ex)
        {
            _authRetryNotBeforeUtc = DateTime.UtcNow + AuthRetryCooldown;
            Console.Error.WriteLine($"[!] auth refresh failed: {ex.Message}"
                                    + $" — not retrying for {AuthRetryCooldown.TotalSeconds:F0}s");
        }
        finally { _authLock.Release(); }
    }

    public async Task EnsureAuthAsync(CancellationToken ct = default)
    {
        if (_sessionToken != null && DateTime.UtcNow.AddSeconds(60) < _sessionExpiresUtc)
            return;

        await _authLock.WaitAsync(ct);
        try
        {
            if (_sessionToken != null && DateTime.UtcNow.AddSeconds(60) < _sessionExpiresUtc)
                return;
            if (DateTime.UtcNow < _authRetryNotBeforeUtc) return;
            if (!ClientSecrets.HasPsk)
            {
                Console.Error.WriteLine("[!] auth: NO PSK on the client side — set MALWARD_AUTH_PSK or " +
                                        @"create %ProgramData%\Malward\data\client-auth.json with an auth_psk field");
                return;
            }

            var zapisana = SessionCache.Read(PskFingerprint(), _base.ToString());
            if (zapisana is { } z)
            {
                _sessionToken = z.Token;
                _sessionExpiresUtc = z.ExpiresUtc;
                _http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", _sessionToken);
                return;
            }

            await AcquireTokenAsync(ct);
        }
        catch (Exception ex)
        {
            _authRetryNotBeforeUtc = DateTime.UtcNow + AuthRetryCooldown;
            Console.Error.WriteLine($"[!] auth challenge failed: {ex.Message}"
                                    + $" — not retrying for {AuthRetryCooldown.TotalSeconds:F0}s");
        }
        finally { _authLock.Release(); }
    }

    private async Task AcquireTokenAsync(CancellationToken ct)
    {
            long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string msg = $"{CLIENT_ID}|{ts}";
            byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(ClientSecrets.AuthPsk),
                                              Encoding.UTF8.GetBytes(msg));
            string macHex = Convert.ToHexString(mac).ToLowerInvariant();

            var req = new HttpRequestMessage(HttpMethod.Post, "auth/token");
            req.Content = JsonContent.Create(new { client_id = CLIENT_ID, ts, hmac_sha256 = macHex });
            using var resp = await _http.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode)
            {
                string why = await resp.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException(
                    $"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}; serwer odpowiedzial: {why.Trim()}; " +
                    $"PSK klienta fingerprint={PskFingerprint()}, ts={ts}");
            }
            var body = await resp.Content.ReadFromJsonAsync<AuthTokenResp>(cancellationToken: ct)
                ?? throw new InvalidOperationException("auth/token: pusta odpowiedź");
            _sessionToken = body.Token;
            _sessionExpiresUtc = DateTime.UtcNow.AddSeconds(body.ExpiresIn);
            _http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _sessionToken);
            SessionCache.Write(_sessionToken, _sessionExpiresUtc, PskFingerprint(), _base.ToString());
            Console.WriteLine($"[+] auth: session token issued, ttl={body.ExpiresIn}s "
                              + $"(PSK fingerprint {PskFingerprint()})");
    }

    public static string PskFingerprint()
    {
        if (!ClientSecrets.HasPsk) return "BRAK";
        byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(ClientSecrets.AuthPsk));
        return Convert.ToHexString(h)[..8].ToLowerInvariant();
    }

    private sealed record AuthTokenResp(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);

    private bool ValidatePinned(HttpRequestMessage _, X509Certificate2? cert,
                                X509Chain? __, SslPolicyErrors errors)

        => CertPinning.Validate(cert, errors, _settings.ServerCertPinSha256,
                                m => Console.Error.WriteLine("[!] " + m));

    public async Task<HashResponse> HashLookupAsync(string sha256, CancellationToken ct = default)
    {
        using var resp = await SendAuthedAsync(
            () => _http.PostAsJsonAsync("hash", new { sha256 }, ct), ct);
        await ThrowOnErrorAsync(resp, ct);
        return (await resp.Content.ReadFromJsonAsync<HashResponse>(cancellationToken: ct))!;
    }

    public async Task SubmitCleanAsync(string sha256, CancellationToken ct = default)
    {
        try
        {
            using var resp = await SendAuthedAsync(
                () => _http.PostAsJsonAsync("hash/submit-clean", new { sha256 }, ct), ct);
        }
        catch
        {
        }
    }

    public async Task SubmitBadAsync(string sha256, string? imphash, long size,
        string detection, CancellationToken ct = default)
    {
        try
        {
            using var resp = await SendAuthedAsync(
                () => _http.PostAsJsonAsync("hash/submit-bad",
                    new { sha256, imphash, size, detection, source = "behavior" }, ct), ct);
        }
        catch
        {
        }
    }

    public sealed record VirusTotalOptions(bool Enabled, string? ApiKey, int GreaterThan);

    public Task<ScanResponse> ScanFileAsync(string filePath, int scanLevel, CancellationToken ct = default)
        => ScanFileAsync(filePath, scanLevel, null, ct);

    private const int SendStallSeconds = 120;

    private sealed class UploadPulse
    {
        private long _tick = Environment.TickCount64;
        private int _finished;

        public bool UploadFinished => Volatile.Read(ref _finished) != 0;
        public long IdleMs => Environment.TickCount64 - Interlocked.Read(ref _tick);

        public void Beat(long sent, long total)
        {
            Interlocked.Exchange(ref _tick, Environment.TickCount64);
            if (total > 0 && sent >= total) Interlocked.Exchange(ref _finished, 1);
        }
    }

    public async Task<ScanResponse> ScanFileAsync(string filePath, int scanLevel, VirusTotalOptions? vt,
                                                  CancellationToken ct = default,
                                                  Action<long, long>? onProgress = null,
                                                  bool unlimited = false)
    {
        await EnsureAuthAsync(ct);
        int generation = Volatile.Read(ref _authGeneration);
        try
        {
            return await ScanFileCoreAsync(filePath, scanLevel, vt, ct, onProgress, unlimited);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            await RefreshAuthAsync(generation, ct);
            return await ScanFileCoreAsync(filePath, scanLevel, vt, ct, onProgress, unlimited);
        }
    }

    private async Task<ScanResponse> ScanFileCoreAsync(string filePath, int scanLevel,
                                                       VirusTotalOptions? vt, CancellationToken ct,
                                                       Action<long, long>? onProgress, bool unlimited)
    {
        using var content = new MultipartFormDataContent();
        await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        var pulse = new UploadPulse();
        void Report(long sent, long total)
        {
            pulse.Beat(sent, total);
            onProgress?.Invoke(sent, total);
        }

        var fileContent = new StreamContent(new CountingStream(fs, Report));
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", Path.GetFileName(filePath));
        content.Add(new StringContent(scanLevel.ToString()), "scan_level");
        if (vt != null)
        {
            content.Add(new StringContent(vt.Enabled ? "1" : "0"), "vt");
            if (!string.IsNullOrWhiteSpace(vt.ApiKey)) content.Add(new StringContent(vt.ApiKey.Trim()), "vt_key");
            if (vt.GreaterThan >= 0) content.Add(new StringContent(vt.GreaterThan.ToString()), "vt_gt");
        }

        using var req = new HttpRequestMessage(HttpMethod.Post, "scan") { Content = content };
        req.Headers.Authorization = _http.DefaultRequestHeaders.Authorization;

        if (!unlimited)
        {
            var plain = await _http.SendAsync(req, ct);
            await ThrowOnErrorAsync(plain, ct);
            return (await plain.Content.ReadFromJsonAsync<ScanResponse>(cancellationToken: ct))!;
        }

        int verdictBudget = Math.Max(600, _settings.MaxUploadToCloudSec);
        using var watchdog = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var tick = new Timer(_ =>
        {
            long limit = (pulse.UploadFinished ? verdictBudget : SendStallSeconds) * 1000L;
            if (pulse.IdleMs > limit) { try { watchdog.Cancel(); } catch { } }
        }, null, 5000, 5000);

        try
        {
            var resp = await UnlimitedClient().SendAsync(req, watchdog.Token);
            await ThrowOnErrorAsync(resp, watchdog.Token);
            return (await resp.Content.ReadFromJsonAsync<ScanResponse>(
                cancellationToken: watchdog.Token))!;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(pulse.UploadFinished
                ? $"the server did not return a verdict within {verdictBudget} s"
                : $"the upload stalled for {SendStallSeconds} s");
        }
    }

    private static async Task ThrowOnErrorAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        var detail = "";
        try { detail = Readable(await resp.Content.ReadAsStringAsync(ct)); } catch { }

        if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
        {
            TimeSpan? after = null;
            try
            {
                var ra = resp.Headers.RetryAfter;
                if (ra?.Delta is { } d) after = d;
                else if (ra?.Date is { } when) after = when - DateTimeOffset.UtcNow;
            }
            catch { }
            if (after is { TotalSeconds: < 0 }) after = null;

            throw new CloudThrottledException(
                $"cloud HTTP 429{(detail.Length > 0 ? ": " + detail : " (no body — refused by the proxy, not the application)")}",
                after);
        }

        throw new HttpRequestException(
            $"cloud HTTP {(int)resp.StatusCode}{(detail.Length > 0 ? ": " + detail : "")}",
            null, resp.StatusCode);
    }

    public sealed class CloudThrottledException : HttpRequestException
    {
        public TimeSpan? RetryAfter { get; }

        public CloudThrottledException(string message, TimeSpan? retryAfter)
            : base(message, null, System.Net.HttpStatusCode.TooManyRequests)
            => RetryAfter = retryAfter;
    }

    private static string Readable(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "";
        var t = body.Trim();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(t);
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
                && doc.RootElement.TryGetProperty("detail", out var d)
                && d.ValueKind == System.Text.Json.JsonValueKind.String)
                return (d.GetString() ?? "").Trim();
        }
        catch { }
        if (t.StartsWith("<", StringComparison.Ordinal)) return "";   
        return t.Length > 200 ? t[..200] : t;
    }

    private sealed class CountingStream : Stream
    {
        private const long Krok = 1024 * 1024;
        private readonly Stream _source;
        private readonly Action<long, long> _report;
        private readonly long _total;
        private long _sent;
        private long _lastReported;

        public CountingStream(Stream source, Action<long, long> report)
        {
            _source = source;
            _report = report;
            _total = source.CanSeek ? source.Length : 0;
        }

        private void Advance(int n)
        {
            if (n <= 0) return;
            _sent += n;
            if (_sent - _lastReported < Krok && _sent != _total) return;
            _lastReported = _sent;
            try { _report(_sent, _total); } catch { }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = _source.Read(buffer, offset, count);
            Advance(n);
            return n;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            int n = await _source.ReadAsync(buffer.AsMemory(offset, count), ct);
            Advance(n);
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            int n = await _source.ReadAsync(buffer, ct);
            Advance(n);
            return n;
        }

        private void Rewound() { _sent = _source.Position; _lastReported = _sent; }

        public override long Seek(long offset, SeekOrigin origin)
        {
            var p = _source.Seek(offset, origin);
            Rewound();
            return p;
        }

        public override bool CanRead  => true;
        public override bool CanSeek  => _source.CanSeek;
        public override bool CanWrite => false;
        public override long Length   => _source.Length;
        public override long Position
        {
            get => _source.Position;
            set { _source.Position = value; Rewound(); }
        }
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }

    private async Task<T> GetAuthedJsonAsync<T>(string endpoint, CancellationToken ct)
    {
        using var resp = await SendAuthedAsync(() => _http.GetAsync(endpoint, ct), ct);
        await ThrowOnErrorAsync(resp, ct);
        return (await resp.Content.ReadFromJsonAsync<T>(cancellationToken: ct))!;
    }

    public Task<Manifest> GetManifestAsync(CancellationToken ct = default)
        => GetAuthedJsonAsync<Manifest>("update/manifest", ct);

    public Task<DbInfo?> GetDbInfoAsync(CancellationToken ct = default)
        => GetAuthedJsonAsync<DbInfo?>("update/dbinfo", ct);

    public Task<DeltaResponse?> GetDeltaAsync(string db, long since, CancellationToken ct = default)
        => GetAuthedJsonAsync<DeltaResponse?>($"update/{db}/delta?since={since}", ct);

    public Task DownloadAsync(string endpoint, string destPath, CancellationToken ct = default)
        => DownloadAsync(endpoint, destPath, null, ct);

    public async Task DownloadAsync(string endpoint, string destPath,
                                    Action<long, long>? onProgress, CancellationToken ct = default)
    {
        var tmp = destPath + ".tmp";
        var dir = Path.GetDirectoryName(destPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        using (var resp = await SendAuthedAsync(
                   () => _http.GetAsync(endpoint, HttpCompletionOption.ResponseHeadersRead, ct), ct))
        {
            resp.EnsureSuccessStatusCode();
            long total = resp.Content.Headers.ContentLength ?? -1;
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None,
                                                 1 << 20, FileOptions.SequentialScan);
            var buf = new byte[1 << 20];
            long done = 0; int read;
            while ((read = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, read), ct);
                done += read;
                onProgress?.Invoke(done, total);
            }
        }

        if (File.Exists(destPath)) File.Delete(destPath);
        File.Move(tmp, destPath);
    }

    public void Dispose()
    {
        _http.Dispose();
        _httpUnlimited?.Dispose();
    }
}
