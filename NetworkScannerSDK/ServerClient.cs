using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;

namespace Malward.NetworkScanner;

public sealed class ServerClient : IDisposable
{
    private const string ServerIp   = "83.168.95.69";
    private const int    ServerPort = 5000;
    private const string CLIENT_ID  = "malward-netmonitor";

    public sealed record UrlResp(
        [property: JsonPropertyName("verdict")]      string Verdict,
        [property: JsonPropertyName("host")]         string? Host = null,
        [property: JsonPropertyName("source")]       string? Source = null,
        [property: JsonPropertyName("vendor")]       string? Vendor = null,
        [property: JsonPropertyName("error")]        string? Error = null,
        [property: JsonPropertyName("status_code")]  int? StatusCode = null);

    public sealed record FileMeta(
        [property: JsonPropertyName("sha256")]      string? Sha256,
        [property: JsonPropertyName("size")]        long Size,
        [property: JsonPropertyName("version_ts")]  long VersionTs,
        [property: JsonPropertyName("available")]   bool Available);

    public sealed record Manifest(
        [property: JsonPropertyName("vps")]        FileMeta? Vps,
        [property: JsonPropertyName("heur")]       FileMeta? Heur,
        [property: JsonPropertyName("whitelist")]  FileMeta? Whitelist,
        [property: JsonPropertyName("urls")]       FileMeta? Urls);

    private readonly HttpClient _http;
    private readonly Uri _base;

    private string? _sessionToken;
    private DateTime _sessionExpiresUtc = DateTime.MinValue;
    private readonly SemaphoreSlim _authLock = new(1, 1);

    private static readonly string PinFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "netmonitor-pin.txt");
    private string? _pinnedFingerprint;

    public ServerClient()
    {
        _base = new Uri($"https://{ServerIp}:{ServerPort}/");
        try { if (File.Exists(PinFile)) _pinnedFingerprint = File.ReadAllText(PinFile).Trim().ToLowerInvariant(); }
        catch { }

        var handler = new SocketsHttpHandler
        {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (s, c, ch, e) =>
                    ValidatePinned(null!, c as X509Certificate2, ch, e),
            },
            MaxConnectionsPerServer = 32,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),

            ResponseDrainTimeout = TimeSpan.FromSeconds(2),
        };
        _http = new HttpClient(handler) { BaseAddress = _base, Timeout = TimeSpan.FromSeconds(15) };
    }

    private bool ValidatePinned(HttpRequestMessage _, X509Certificate2? cert,
                                X509Chain? __, SslPolicyErrors errors)
    {
        if (cert is null) return false;
        var fp = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        if (string.IsNullOrEmpty(_pinnedFingerprint))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(PinFile)!);
                File.WriteAllText(PinFile, fp);
            }
            catch { }
            _pinnedFingerprint = fp;
            Log.Info("Server", $"Cert pinned (TOFU): {fp}");
            return true;
        }
        if (!string.Equals(_pinnedFingerprint, fp, StringComparison.OrdinalIgnoreCase))
        {
            Log.Error("Server", $"Cert pin mismatch! expected={_pinnedFingerprint} actual={fp}");
            return false;
        }
        return true;
    }

    public async Task EnsureAuthAsync(CancellationToken ct = default)
    {
        if (_sessionToken != null && DateTime.UtcNow.AddSeconds(60) < _sessionExpiresUtc) return;
        await _authLock.WaitAsync(ct);
        try
        {
            if (_sessionToken != null && DateTime.UtcNow.AddSeconds(60) < _sessionExpiresUtc) return;
            long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string msg = $"{CLIENT_ID}|{ts}";
            byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(NetSecrets.AuthPsk),
                                              Encoding.UTF8.GetBytes(msg));
            string macHex = Convert.ToHexString(mac).ToLowerInvariant();

            using var resp = await _http.PostAsJsonAsync("auth/token",
                new { client_id = CLIENT_ID, ts, hmac_sha256 = macHex }, ct);
            resp.EnsureSuccessStatusCode();
            var body = await resp.Content.ReadFromJsonAsync<AuthTokenResp>(cancellationToken: ct)
                ?? throw new InvalidOperationException("auth/token: pusta odpowiedź");
            _sessionToken = body.Token;
            _sessionExpiresUtc = DateTime.UtcNow.AddSeconds(body.ExpiresIn);
            _http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _sessionToken);
            Log.Info("Server", $"Auth OK (ttl={body.ExpiresIn}s)");
        }
        catch (Exception ex)
        {
            Log.Warn("Server", $"Auth challenge failed: {ex.Message}");
        }
        finally { _authLock.Release(); }
    }

    private sealed record AuthTokenResp(
        [property: JsonPropertyName("token")]      string Token,
        [property: JsonPropertyName("expires_in")] int    ExpiresIn);

    public async Task<UrlResp?> UrlLookupAsync(string url, CancellationToken ct = default)
    {
        try
        {
            await EnsureAuthAsync(ct);
            var resp = await _http.PostAsJsonAsync("url", new { url }, ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<UrlResp>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            Log.Debug("Server", $"/url failed: {ex.Message}");
            return null;
        }
    }

    public async Task<UrlResp?> UrlScanAsync(string url, CancellationToken ct = default)
    {
        try
        {
            await EnsureAuthAsync(ct);
            var resp = await _http.PostAsJsonAsync("url/scan", new { url }, ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<UrlResp>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            Log.Debug("Server", $"/url/scan failed: {ex.Message}");
            return null;
        }
    }

    public async Task<Manifest?> GetManifestAsync(CancellationToken ct = default)
    {
        try
        {
            await EnsureAuthAsync(ct);
            var resp = await _http.GetAsync("update/manifest", ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<Manifest>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            Log.Warn("Server", $"manifest failed: {ex.Message}");
            return null;
        }
    }

    public async Task<bool> DownloadUrlsAsync(string destPath, CancellationToken ct = default)
        => await DownloadUrlsAsync(destPath, profile: null, ct);

    public async Task<bool> DownloadUrlsAsync(string destPath, string? profile, CancellationToken ct = default)
        => await DownloadFileAsync(string.IsNullOrEmpty(profile) ? "update/urls" : $"update/urls/{profile}",
                                   destPath, ct);

    public async Task<bool> DownloadUrlCacheAsync(string destPath, CancellationToken ct = default)
        => await DownloadFileAsync("update/urlcache", destPath, ct);

    private async Task<bool> DownloadFileAsync(string endpoint, string destPath, CancellationToken ct)
    {
        try
        {
            await EnsureAuthAsync(ct);
            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
            var tmp = destPath + ".tmp";

            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }

            using (var resp = await _http.GetAsync(endpoint, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                if (!resp.IsSuccessStatusCode) return false;
                await using var src = await resp.Content.ReadAsStreamAsync(ct);
                await using var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None,
                                                     1 << 20, FileOptions.SequentialScan);
                await src.CopyToAsync(dst, 1 << 20, ct);
                await dst.FlushAsync(ct);
            }

            if (File.Exists(destPath))
            {
                try
                {
                    File.Replace(tmp, destPath, destinationBackupFileName: null,
                                 ignoreMetadataErrors: true);
                }
                catch (IOException)
                {
                    File.Delete(destPath);
                    File.Move(tmp, destPath);
                }
            }
            else
            {
                File.Move(tmp, destPath);
            }
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("Server", $"download {endpoint} failed: {ex.Message}");
            return false;
        }
    }

    public void Dispose() => _http.Dispose();
}
