using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json.Nodes;

namespace Malward.AppGUI.Services;

public sealed class UpdateService
{
    private readonly string _engineDir;
    private readonly string _serverIp;
    private readonly int _serverPort;

    private readonly string _certPin;
    private readonly HttpClient _http;

    public sealed record FileMeta(
        [property: JsonPropertyName("sha256")] string? Sha256,
        [property: JsonPropertyName("size")]   long Size,
        [property: JsonPropertyName("available")] bool Available,
        [property: JsonPropertyName("version")] string? Version = null);

    public sealed record Manifest(
        [property: JsonPropertyName("vps")]        FileMeta Vps,
        [property: JsonPropertyName("heur")]       FileMeta Heur,
        [property: JsonPropertyName("whitelist")]  FileMeta Whitelist,
        [property: JsonPropertyName("urls")]       FileMeta? Urls = null,
        [property: JsonPropertyName("urls_profiles")] Dictionary<string, FileMeta>? UrlsProfiles = null,
        [property: JsonPropertyName("ipbase")]     FileMeta? IpBase = null,
        [property: JsonPropertyName("urlcache")]   FileMeta? UrlCache = null,
        [property: JsonPropertyName("byod")]       FileMeta? Byod = null);

    public sealed record ProgressEvent(
        string Phase,
        string Status,
        long Downloaded,
        long Total,
        double OverallPct,
        double SpeedBps,
        int EtaSec,
        string Message,
        string Component = "");

    public sealed record BundleFile(
        [property: JsonPropertyName("name")]       string Name,
        [property: JsonPropertyName("sha256")]     string? Sha256,
        [property: JsonPropertyName("size")]       long Size,
        [property: JsonPropertyName("version_ts")] long VersionTs,
        [property: JsonPropertyName("available")]  bool Available);

    private sealed record BundleManifest(
        [property: JsonPropertyName("files")]      List<BundleFile> Files,
        [property: JsonPropertyName("total_size")] long TotalSize);

    public sealed record ImportResult(int Imported, int UpToDate, long Bytes, string? Error);

    public sealed record DownloadResult(long Bytes, string? Error);

    public sealed record ReportResult(bool Ok, string? Id, string? Error);

    public async Task<ReportResult> ReportFalsePositiveAsync(
        string quarantineBlobPath, string detection, string originalPath, string comment,
        string productVersion, CancellationToken ct = default)
    {
        string? tmpZip = null;
        try
        {
            if (!File.Exists(quarantineBlobPath))
                return new ReportResult(false, null, "Nie znaleziono pliku w kwarantannie.");

            await EnsureAuthAsync(ct);

            tmpZip = Path.Combine(Path.GetTempPath(), "malward-report-" + Guid.NewGuid().ToString("N") + ".zip");
            using (var zip = ZipFile.Open(tmpZip, ZipArchiveMode.Create))
            {
                zip.CreateEntryFromFile(quarantineBlobPath, "sample.quarantine",
                                        CompressionLevel.Optimal);
            }

            using var form = new MultipartFormDataContent();

            await using var zipStream = File.OpenRead(tmpZip);
            var part = new StreamContent(zipStream);
            part.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/zip");
            form.Add(part, "file", Path.GetFileName(quarantineBlobPath) + ".zip");
            form.Add(new StringContent(comment ?? "", Encoding.UTF8), "comment");
            form.Add(new StringContent(detection ?? "", Encoding.UTF8), "detection");
            form.Add(new StringContent(originalPath ?? "", Encoding.UTF8), "original_path");
            form.Add(new StringContent(productVersion ?? "", Encoding.UTF8), "product_version");

            using var zgloszenie = new HttpClient(Malward.Engine.Cloud.CertPinning.Handler(_certPin, Log))
            {
                BaseAddress = _http.BaseAddress,
                Timeout = Timeout.InfiniteTimeSpan,
            };
            using var req = new HttpRequestMessage(HttpMethod.Post, "report/false-positive") { Content = form };
            req.Headers.Authorization = _http.DefaultRequestHeaders.Authorization;
            using var resp = await zgloszenie.SendAsync(req, ct);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return new ReportResult(false, null, "Serwer nie obsługuje zgłoszeń (wymaga nowszej wersji).");
            if (!resp.IsSuccessStatusCode)
                return new ReportResult(false, null, $"Serwer odrzucił zgłoszenie ({(int)resp.StatusCode}).");

            var body = await resp.Content.ReadAsStringAsync(ct);
            string? id = null;
            try { id = JsonNode.Parse(body)?["id"]?.GetValue<string>(); } catch { }
            return new ReportResult(true, id, null);
        }
        catch (OperationCanceledException) { return new ReportResult(false, null, "Anulowano."); }
        catch (Exception ex) { return new ReportResult(false, null, ex.Message); }
        finally
        {
            if (tmpZip != null) { try { File.Delete(tmpZip); } catch { } }
        }
    }

    public async Task<DownloadResult> DownloadBundleAsync(string destZip, Action<ProgressEvent> progress,
                                                          CancellationToken ct = default)
    {
        var tmp = destZip + ".tmp";
        try
        {
            await EnsureAuthAsync(ct);
            Directory.CreateDirectory(Path.GetDirectoryName(destZip)!);
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            progress(new ProgressEvent("bundle", "busy", 0, 0, 0, 0, 0, "Łączę z serwerem…"));

            var resp = await _http.GetAsync("update/bundle.zip", HttpCompletionOption.ResponseHeadersRead, ct);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                resp.Dispose();
                resp = await _http.GetAsync("update/bundle", HttpCompletionOption.ResponseHeadersRead, ct);
            }
            long downloaded = 0, total;
            using (resp)
            {
                resp.EnsureSuccessStatusCode();
                total = resp.Content.Headers.ContentLength ?? 0;
                using var src = await resp.Content.ReadAsStreamAsync(ct);
                using var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024);
                var buf = new byte[64 * 1024];
                var speed = new SpeedWindow();
                var lastReport = DateTimeOffset.UtcNow;
                while (true)
                {
                    int n = await src.ReadAsync(buf, ct);
                    if (n == 0) break;
                    await dst.WriteAsync(buf.AsMemory(0, n), ct);
                    downloaded += n; speed.Add(n);
                    var now = DateTimeOffset.UtcNow;
                    if ((now - lastReport).TotalMilliseconds >= 200)
                    {
                        lastReport = now;
                        double bps = speed.GetBytesPerSec();
                        int eta = bps > 0 && total > downloaded ? (int)((total - downloaded) / bps) : 0;
                        progress(new ProgressEvent("bundle", "busy", downloaded, total,
                            total > 0 ? (double)downloaded / total : 0, bps, eta,
                            $"Pobieram bazę… {FormatBytes(downloaded)}" + (total > 0 ? $" / {FormatBytes(total)}" : "")));
                    }
                }
            }
            File.Move(tmp, destZip, overwrite: true);
            progress(new ProgressEvent("bundle", "ok", downloaded, total, 1.0, 0, 0, $"Pobrano {FormatBytes(downloaded)}."));
            return new DownloadResult(downloaded, null);
        }
        catch (OperationCanceledException) { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } throw; }
        catch (Exception ex)
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            Log($"[bundle] {ex.Message}");
            progress(new ProgressEvent("bundle", "err", 0, 0, 0, 0, 0, ex.Message));
            return new DownloadResult(0, ex.Message);
        }
    }

    public Task<ImportResult> ImportDatabasesAsync(string zipPath, Action<ProgressEvent> progress,
                                                   CancellationToken ct = default)
        => Task.Run(() =>
    {
        try
        {
            if (!File.Exists(zipPath))
                throw new FileNotFoundException("Nie znaleziono pliku ZIP.", zipPath);

            progress(new ProgressEvent("import", "busy", 0, 0, 0, 0, 0, "Otwieram archiwum…"));
            Directory.CreateDirectory(DataDir);

            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "vps.vdeb", "heur.vdeb", "rf-whitelist.vdeb", "vps-ex01.vdeb", "vps-ex02.vdeb",
              "vps-ex03.vdeb", "vps-ex04.vdeb" };
            foreach (var prof in new[] { "low", "low-ads", "medium", "medium-ads", "high", "high-ads" })
                allowed.Add($"urls-{prof}.vdeb");

            using var zip = System.IO.Compression.ZipFile.OpenRead(zipPath);

            string wantedUrls = $"urls-{ResolveUrlProfile()}.vdeb";
            var members = zip.Entries
                .Where(e => !string.IsNullOrEmpty(e.Name) && allowed.Contains(e.Name))
                .Where(e => !e.Name.StartsWith("urls-", StringComparison.OrdinalIgnoreCase)
                            || string.Equals(e.Name, wantedUrls, StringComparison.OrdinalIgnoreCase))
                .ToList();

            long? vpsSeq = null, wlSeq = null; string? vpsVer = null, wlVer = null;
            var metaEntry = zip.Entries.FirstOrDefault(e => string.Equals(e.Name, "bundle.json", StringComparison.OrdinalIgnoreCase));
            if (metaEntry != null)
            {
                try
                {
                    using var ms = metaEntry.Open();
                    using var doc = System.Text.Json.JsonDocument.Parse(ms);
                    if (doc.RootElement.TryGetProperty("dbinfo", out var di))
                    {
                        static (long? Seq, string? Ver) ReadDb(System.Text.Json.JsonElement e)
                        {
                            long? seq = e.TryGetProperty("base_seq", out var bs) && bs.TryGetInt64(out var l) ? l : null;
                            string? ver = e.TryGetProperty("version", out var vv) && vv.ValueKind == System.Text.Json.JsonValueKind.String ? vv.GetString() : null;
                            return (seq, ver);
                        }
                        if (di.TryGetProperty("vps", out var v)) (vpsSeq, vpsVer) = ReadDb(v);
                        if (di.TryGetProperty("whitelist", out var w)) (wlSeq, wlVer) = ReadDb(w);
                    }
                }
                catch (Exception ex) { Log($"[import] bundle.json unreadable: {ex.Message}"); }
            }
            var importedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (members.Count == 0)
                throw new InvalidOperationException(
                    "Archiwum nie zawiera żadnych rozpoznanych baz danych (*.vdeb).");

            long total = members.Sum(e => e.Length);
            int imported = 0, upToDate = 0;
            long bytes = 0;

            foreach (var entry in members)
            {
                ct.ThrowIfCancellationRequested();
                string targetName = entry.Name.StartsWith("urls-", StringComparison.OrdinalIgnoreCase) ? "urls.vdeb" : entry.Name;
                var target = Path.Combine(DataDir, targetName);
                var staging = target + ".part";
                progress(new ProgressEvent("import", "busy", bytes, total,
                    total > 0 ? bytes * 100.0 / total : 0, 0, 0, $"Rozpakowuję {entry.Name}…"));

                System.IO.Compression.ZipFileExtensions.ExtractToFile(entry, staging, overwrite: true);
                try
                {
                    if (File.Exists(target)
                        && string.Equals(Sha256OfFile(target), Sha256OfFile(staging),
                                         StringComparison.OrdinalIgnoreCase))
                    {
                        upToDate++;
                        File.Delete(staging);
                    }
                    else
                    {
                        File.Move(staging, target, overwrite: true);
                        imported++;
                        importedNames.Add(targetName);
                    }
                }
                catch { try { File.Delete(staging); } catch { } throw; }
                bytes += entry.Length;
            }

            var seqStore = LoadSeqStore();
            void Rebase(string db, long? seq)
            {
                if (seq.HasValue) seqStore[db] = seq.Value; else seqStore.Remove(db);
                ClearOverlay(Path.Combine(DataDir, OverlayFileFor(db)));
            }
            if (importedNames.Contains("vps.vdeb")) Rebase("vps", vpsSeq);
            if (importedNames.Contains("rf-whitelist.vdeb")) Rebase("whitelist", wlSeq);
            SaveSeqStore(seqStore);
            if (vpsVer != null || wlVer != null)
            {
                try { DbVersionStore.WriteServerVersions(DbVersionStore.CachePathFor(Path.GetDirectoryName(DataDir)!), vpsVer, wlVer); }
                catch { }
            }

            progress(new ProgressEvent("import", "ok", bytes, total, 100, 0, 0,
                $"Zaimportowano {imported}, bez zmian {upToDate}"));
            return new ImportResult(imported, upToDate, bytes, null);
        }
        catch (Exception ex)
        {
            Log($"[import] {ex.Message}");
            progress(new ProgressEvent("import", "err", 0, 0, 0, 0, 0, ex.Message));
            return new ImportResult(0, 0, 0, ex.Message);
        }
    }, ct);

    private static string Sha256OfFile(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    private static string ComponentKey(string url) =>
        url.Contains("update/vps") ? "vps"
        : url.Contains("update/heur") ? "heur"
        : url.Contains("update/whitelist") ? "whitelist"
        : url.Contains("urls") ? "urls"
        : "";

    public sealed record UpdateSummary(bool AnyChanged, List<string> ChangedFiles);

    private static readonly (string Db, string Vdeb, string Overlay)[] DeltaDbs =
    {
        ("vps",       "vps.vdeb",         "vps-overlay.txt"),
        ("whitelist", "rf-whitelist.vdeb", "rf-whitelist-overlay.txt"),
    };

    private sealed record DbInfoEntry(long Seq, long BaseSeq, bool DeltaAvailable,
        string? Sha256, string? Version);

    private sealed record DeltaResponse(
        [property: JsonPropertyName("mode")]     string Mode,
        [property: JsonPropertyName("from_seq")] long FromSeq,
        [property: JsonPropertyName("to_seq")]   long ToSeq,
        [property: JsonPropertyName("added")]    List<string>? Added = null,
        [property: JsonPropertyName("removed")]  List<string>? Removed = null);

    private enum DeltaOutcome { UpToDate, AppliedDelta, NeedFull }

    private static string DataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data");

    private static string ResolveUrlProfile()
    {
        string lvl = "medium"; bool ads = false;
        try
        {
            var p = Path.Combine(DataDir, "network-settings.json");
            if (File.Exists(p))
            {
                var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(p));
                lvl = node?["sensitivity_profile"]?.GetValue<string>() ?? "medium";
                ads = node?["ad_blocking"]?.GetValue<bool>() ?? false;

                if (lvl.EndsWith("-ads", StringComparison.OrdinalIgnoreCase)) { ads = true; lvl = lvl[..^4]; }
            }
        }
        catch { }
        if (lvl is not ("low" or "medium" or "high")) lvl = "medium";
        return ads ? lvl + "-ads" : lvl;
    }

    private const string DEFAULT_SERVER_IP    = "83.168.95.69";
    private const int    DEFAULT_SERVER_PORT  = 5000;

    private const string CLIENT_ID            = "malward-gui";

    private string? _sessionToken;
    private DateTime _sessionExpiresUtc = DateTime.MinValue;
    private readonly SemaphoreSlim _authLock = new(1, 1);

    private readonly bool _scannerOnly;

    public UpdateService(JsonObject? engineSettings, string engineDir, bool scannerOnly = false)
    {
        _engineDir = engineDir;
        _scannerOnly = scannerOnly;
        _serverIp   = engineSettings?["server_ip"]?.GetValue<string>()   ?? DEFAULT_SERVER_IP;
        _serverPort = engineSettings?["server_port"]?.GetValue<int>()    ?? DEFAULT_SERVER_PORT;

        _certPin    = engineSettings?["server_cert_pin"]?.GetValue<string>()
                      ?? Malward.Engine.Config.Settings.DefaultServerCertPinSha256;

        _http = new HttpClient(Malward.Engine.Cloud.CertPinning.Handler(_certPin, Log))
        {
            BaseAddress = new Uri($"https://{_serverIp}:{_serverPort}/"),
            Timeout = TimeSpan.FromMinutes(15),
        };
    }

    private sealed record AuthTokenResp(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);

    private static void Log(string message)
    {
        System.Diagnostics.Debug.WriteLine($"[update] {message}");
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "update.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
        }
        catch { }
    }

    internal static string PskFingerprint()
    {
        var psk = GuiSecrets.AuthPsk;
        if (psk.Length == 0) return "BRAK";
        byte[] h = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(psk));
        return Convert.ToHexString(h)[..8].ToLowerInvariant();
    }

    private async Task EnsureAuthAsync(CancellationToken ct)
    {
        if (_sessionToken != null && DateTime.UtcNow.AddSeconds(60) < _sessionExpiresUtc)
            return;

        await _authLock.WaitAsync(ct);
        try
        {
            if (_sessionToken != null && DateTime.UtcNow.AddSeconds(60) < _sessionExpiresUtc) return;

            string psk = GuiSecrets.AuthPsk;
            if (psk.Length == 0)
            {
                Log($"[auth] no PSK. Reason: {GuiSecrets.LastDiagnostic}");
                Log($"[auth] process: user={Environment.UserName}, "
                    + $"application directory={AppContext.BaseDirectory}");
                return;
            }

            long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string msg = $"{CLIENT_ID}|{ts}";
            byte[] mac = HMACSHA256.HashData(System.Text.Encoding.UTF8.GetBytes(psk),
                                              System.Text.Encoding.UTF8.GetBytes(msg));
            string macHex = Convert.ToHexString(mac).ToLowerInvariant();

            var req = new HttpRequestMessage(HttpMethod.Post, "auth/token");
            req.Content = JsonContent.Create(new { client_id = CLIENT_ID, ts, hmac_sha256 = macHex });
            using var resp = await _http.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode)
            {
                string why = await resp.Content.ReadAsStringAsync(ct);
                Log($"[auth] HTTP {(int)resp.StatusCode}: {why.Trim()} "
                    + $"(PSK fingerprint {PskFingerprint()}, ts={ts})");
                return;
            }
            var body = await resp.Content.ReadFromJsonAsync<AuthTokenResp>(cancellationToken: ct)
                ?? throw new InvalidOperationException("empty auth response");
            _sessionToken = body.Token;
            _sessionExpiresUtc = DateTime.UtcNow.AddSeconds(body.ExpiresIn);
            _http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _sessionToken);
        }
        catch (Exception ex)
        {
            Log($"[auth] authentication failed: {ex.Message}");
        }
        finally { _authLock.Release(); }
    }

    public async Task<UpdateSummary> UpdateAllAsync(Action<ProgressEvent> progress,
        CancellationToken ct = default)
    {
        progress(new ProgressEvent("modules", "idle", 0, 0, 0, 0, 0, "Sprawdzam aktualizacje…"));

        try
        {
            if (Directory.Exists(DataDir))
            {
                foreach (var f in Directory.EnumerateFiles(DataDir, "*.vdeb.tmp"))
                    try { File.Delete(f); } catch { }

                foreach (var f in Directory.EnumerateFiles(DataDir, "urls-*.vdeb"))
                    try { File.Delete(f); } catch { }
            }
        }
        catch { }

        await EnsureAuthAsync(ct);

        Manifest manifest;
        try
        {
            manifest = await _http.GetFromJsonAsync<Manifest>("update/manifest", ct)
                ?? throw new Exception("brak manifestu");
        }
        catch (Exception ex)
        {
            progress(new ProgressEvent("modules", "err", 0, 0, 0, 0, 0,
                $"Nie udało się pobrać manifestu: {ex.Message}"));
            return new UpdateSummary(false, new());
        }

        var dbinfo = new Dictionary<string, DbInfoEntry>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var dbiJson = await _http.GetStringAsync("update/dbinfo", ct);
            if (JsonNode.Parse(dbiJson) is JsonObject dbi)
            {
                foreach (var (db, _, _) in DeltaDbs)
                {
                    if (dbi[db] is JsonObject e)
                        dbinfo[db] = new DbInfoEntry(
                            Seq:            e["seq"]?.GetValue<long>() ?? 0,
                            BaseSeq:        e["base_seq"]?.GetValue<long>() ?? 0,
                            DeltaAvailable: e["delta_available"]?.GetValue<bool>() ?? false,
                            Sha256:         e["sha256"]?.GetValue<string>(),
                            Version:        e["version"]?.GetValue<string>());
                }

                var urlsVer = (dbi["urls"] as JsonObject)?["version"]?.GetValue<string>();
                DbVersionStore.WriteServerVersions(Path.Combine(DataDir, "db-versions-server.json"),
                    dbinfo.TryGetValue("vps", out var vi) ? vi.Version : null,
                    dbinfo.TryGetValue("whitelist", out var wi) ? wi.Version : null,
                    urlsVer);
            }
        }
        catch {  }

        var seqStore   = LoadSeqStore();
        var needFull   = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deltaApplied = new List<string>();
        foreach (var (db, _, _) in DeltaDbs)
        {
            bool avail = db == "vps" ? manifest.Vps?.Available == true
                                     : manifest.Whitelist?.Available == true;
            if (!avail || !dbinfo.TryGetValue(db, out var info)) { needFull.Add(db); continue; }

            DeltaOutcome outcome;
            try { outcome = await TryDeltaAsync(db, info, seqStore, progress, ct); }
            catch (OperationCanceledException) { throw; }
            catch { outcome = DeltaOutcome.NeedFull; }

            if (outcome == DeltaOutcome.NeedFull) needFull.Add(db);
            else if (outcome == DeltaOutcome.AppliedDelta)
                deltaApplied.Add(db == "vps" ? "vps (delta)" : "whitelist (delta)");
        }
        SaveSeqStore(seqStore);

        var tasks = new List<(string phase, string url, string dest, FileMeta meta)>();

        if (manifest.Vps?.Available == true && needFull.Contains("vps"))
            tasks.Add(("modules", "update/vps", Path.Combine(DataDir, "vps.vdeb"), manifest.Vps));
        if (manifest.Heur?.Available == true)
            tasks.Add(("modules", "update/heur", Path.Combine(DataDir, "heur.vdeb"), manifest.Heur));
        if (manifest.Whitelist?.Available == true && needFull.Contains("whitelist"))
            tasks.Add(("extras", "update/whitelist", Path.Combine(DataDir, "rf-whitelist.vdeb"), manifest.Whitelist));

        try
        {
            if (_scannerOnly) goto skipUrls;
            string profile = ResolveUrlProfile();
            FileMeta? urlsMeta = null;
            string urlsUrl, urlsDest;
            if (manifest.UrlsProfiles != null && manifest.UrlsProfiles.TryGetValue(profile, out var pm) && pm.Available)
            {
                urlsMeta = pm;
                urlsUrl  = $"update/urls/{profile}";

                urlsDest = Path.Combine(DataDir, "urls.vdeb");
            }
            else if (manifest.Urls?.Available == true)
            {
                urlsMeta = manifest.Urls;
                urlsUrl  = "update/urls";
                urlsDest = Path.Combine(DataDir, "urls.vdeb");
            }
            else { urlsUrl = urlsDest = ""; }

            if (urlsMeta != null)
                tasks.Add(("extras", urlsUrl, urlsDest, urlsMeta));
        }
        catch {  }
        skipUrls: ;

        long totalAll = tasks.Sum(t => t.meta.Size);
        long doneAll = 0;
        var changed = new List<string>();

        var fullSynced = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        Directory.CreateDirectory(DataDir);

        foreach (var task in tasks)
        {
            string localSha = "";
            if (File.Exists(task.dest))
                localSha = ComputeSha256(task.dest);

            if (!string.IsNullOrEmpty(task.meta.Sha256)
                && localSha.Equals(task.meta.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                doneAll += task.meta.Size;
                if (dbinfo.ContainsKey(ComponentKey(task.url))) fullSynced.Add(ComponentKey(task.url));
                progress(new ProgressEvent(task.phase, "uptodate", task.meta.Size, task.meta.Size,
                    totalAll > 0 ? (double)doneAll / totalAll : 1.0, 0, 0,
                    $"{HumanLabel(task.url)} — aktualne.", ComponentKey(task.url)));
                continue;
            }

            progress(new ProgressEvent(task.phase, "busy", 0, task.meta.Size,
                totalAll > 0 ? (double)doneAll / totalAll : 0.0, 0, 0,
                $"Pobieram {HumanLabel(task.url).ToLower()}…", ComponentKey(task.url)));

            try
            {
                var tmp = task.dest + ".tmp";

                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }

                using (var resp = await _http.GetAsync(task.url, HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    resp.EnsureSuccessStatusCode();
                    long total = resp.Content.Headers.ContentLength ?? task.meta.Size;

                    using var src = await resp.Content.ReadAsStreamAsync(ct);
                    using var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024);

                    var buf = new byte[64 * 1024];
                    long downloaded = 0;
                    var speed = new SpeedWindow();
                    var lastReport = DateTimeOffset.UtcNow;

                    while (true)
                    {
                        int n = await src.ReadAsync(buf, ct);
                        if (n == 0) break;
                        await dst.WriteAsync(buf.AsMemory(0, n), ct);
                        downloaded += n;
                        speed.Add(n);

                        var now = DateTimeOffset.UtcNow;
                        if ((now - lastReport).TotalMilliseconds >= 200 || downloaded == total)
                        {
                            lastReport = now;
                            double bps = speed.GetBytesPerSec();
                            int eta = bps > 0 && total > downloaded ? (int)((total - downloaded) / bps) : 0;
                            double overall = totalAll > 0
                                ? (double)(doneAll + downloaded) / totalAll
                                : (total > 0 ? (double)downloaded / total : 0);
                            progress(new ProgressEvent(task.phase, "busy", downloaded, total, overall, bps, eta,
                                $"Pobieram {HumanLabel(task.url).ToLower()}… {FormatBytes(downloaded)} / {FormatBytes(total)}",
                                ComponentKey(task.url)));
                        }
                    }
                }

                if (File.Exists(task.dest))
                {
                    try
                    {
                        File.Replace(tmp, task.dest, destinationBackupFileName: null,
                                     ignoreMetadataErrors: true);
                    }
                    catch (IOException)
                    {
                        try
                        {
                            File.Delete(task.dest);
                            File.Move(tmp, task.dest);
                        }
                        catch
                        {
                            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                            throw;
                        }
                    }
                }
                else
                {
                    File.Move(tmp, task.dest);
                }

                doneAll += task.meta.Size;
                changed.Add(Path.GetFileName(task.dest));
                if (dbinfo.ContainsKey(ComponentKey(task.url))) fullSynced.Add(ComponentKey(task.url));
                progress(new ProgressEvent(task.phase, "ok", task.meta.Size, task.meta.Size,
                    totalAll > 0 ? (double)doneAll / totalAll : 1.0, 0, 0,
                    $"Pobrano: {HumanLabel(task.url).ToLower()}.", ComponentKey(task.url)));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                progress(new ProgressEvent(task.phase, "err", 0, task.meta.Size, 1.0, 0, 0,
                    $"Błąd: {ex.Message}", ComponentKey(task.url)));
            }
        }

        if (fullSynced.Count > 0)
        {
            foreach (var db in fullSynced)
            {
                if (!dbinfo.TryGetValue(db, out var info)) continue;
                seqStore[db] = info.BaseSeq;
                ClearOverlay(Path.Combine(DataDir, OverlayFileFor(db)));
            }
            SaveSeqStore(seqStore);
        }

        try { await DownloadExtraListsAsync(progress, ct); } catch (OperationCanceledException) { throw; } catch { }

        var allChanged = changed.Concat(deltaApplied).ToList();
        progress(new ProgressEvent("extras", "ok", totalAll, totalAll, 1.0, 0, 0,
            allChanged.Count == 0 ? "Wszystko aktualne." : $"Zaktualizowano {allChanged.Count} pozycję(e)."));
        return new UpdateSummary(allChanged.Count > 0, allChanged);
    }

    private const string CscbCertsUrl      = "https://bazaar.abuse.ch/export/csv/cscb/";

    private async Task StoreExtraListVersionsAsync(CancellationToken ct)
    {
        try
        {
            var manifest = await _http.GetFromJsonAsync<Manifest>("update/manifest", ct);
            if (manifest == null) return;
            DbVersionStore.WriteVersions(Path.Combine(DataDir, "db-versions-server.json"),
                new Dictionary<string, string?>
                {
                    ["botip"]    = manifest.IpBase?.Version,
                    ["urlcache"] = manifest.UrlCache?.Version,
                    ["byod"]     = manifest.Byod?.Version,
                });
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { Log($"extra list versions unavailable: {ex.Message}"); }
    }

    private static void BumpLocalVersionIfChanged(string path, byte[] fresh, string versionKey)
    {
        try
        {
            if (File.Exists(path))
            {
                var current = File.ReadAllBytes(path);
                if (current.Length == fresh.Length && current.AsSpan().SequenceEqual(fresh)) return;
            }
            DbVersionStore.BumpLocal(Path.Combine(DataDir, "db-versions-server.json"), versionKey);
        }
        catch { }
    }

    private async Task DownloadExtraListsAsync(Action<ProgressEvent> progress, CancellationToken ct)
    {
        Directory.CreateDirectory(DataDir);

        using var http = new HttpClient(Malward.Engine.Cloud.CertPinning.Handler(_certPin, Log))
        { Timeout = TimeSpan.FromSeconds(60) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Malward/0.4 (+https://malward)");

        await StoreExtraListVersionsAsync(ct);

        try
        {
            progress(new ProgressEvent("extras", "busy", 0, 0, 0, 0, 0,
                "Pobieram bazę podatnych sterowników…", "urls"));
            var byod = await _http.GetStringAsync("update/byod", ct);
            if (!string.IsNullOrWhiteSpace(byod))
                AtomicWrite(Path.Combine(DataDir, "vps-ex04.vdeb"), byod.Replace("\r\n", "\n"));
        }
        catch (OperationCanceledException) { throw; }
        catch {  }

        if (_scannerOnly) goto certsOnly;

        try
        {
            progress(new ProgressEvent("extras", "busy", 0, 0, 0, 0, 0, "Pobieram bazę niebezpiecznych adresów IP…", "urls"));
            var ipText = await _http.GetStringAsync("update/ipbase", ct);
            if (!string.IsNullOrWhiteSpace(ipText))
                AtomicWrite(Path.Combine(DataDir, "vps-ex01.vdeb"), ipText.Replace("\r\n", "\n"));
        }
        catch (OperationCanceledException) { throw; }
        catch {  }

        try
        {
            progress(new ProgressEvent("extras", "busy", 0, 0, 0, 0, 0, "Pobieram bazę adresów z chmury…", "urls"));
            var cache = await _http.GetByteArrayAsync("update/urlcache", ct);
            if (cache.Length > 0)
                AtomicWriteBytes(Path.Combine(DataDir, "vps-ex03.vdeb"), cache);
        }
        catch (OperationCanceledException) { throw; }
        catch {  }

        certsOnly: ;

        try
        {
            progress(new ProgressEvent("extras", "busy", 0, 0, 0, 0, 0, "Pobieram listę zablokowanych certyfikatów…", "urls"));
            var raw = await http.GetStringAsync(CscbCertsUrl, ct);
            var fps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in raw.Split('\n'))
            {
                var l = line.Trim();
                if (l.Length == 0 || l.StartsWith('#')) continue;
                if (l.StartsWith("\"time_stamp", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var field in l.Split(','))
                {
                    var f = field.Trim().Trim('"');
                    if (f.Length == 64 && IsHex(f)) { fps.Add(f.ToLowerInvariant()); break; }
                }
            }
            if (fps.Count > 0)
            {
                var certPath = Path.Combine(DataDir, "vps-ex02.vdeb");
                var certBody = string.Join("\n", fps);
                BumpLocalVersionIfChanged(certPath,
                    System.Text.Encoding.UTF8.GetBytes(certBody), "cert");
                AtomicWrite(certPath, certBody);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private static bool IsIpv4(string s)
    {
        var p = s.Split('.');
        return p.Length == 4 && p.All(x => byte.TryParse(x, out _));
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
            if (!Uri.IsHexDigit(c)) return false;
        return true;
    }

    private static void AtomicWrite(string dest, string content)
    {
        var tmp = dest + ".tmp";
        File.WriteAllText(tmp, content, new System.Text.UTF8Encoding(false));
        if (File.Exists(dest)) { try { File.Replace(tmp, dest, null); return; } catch { } }
        File.Move(tmp, dest, overwrite: true);
    }

    private static void AtomicWriteBytes(string dest, byte[] content)
    {
        var tmp = dest + ".tmp";
        File.WriteAllBytes(tmp, content);
        if (File.Exists(dest)) { try { File.Replace(tmp, dest, null); return; } catch { } }
        File.Move(tmp, dest, overwrite: true);
    }

    private static string OverlayFileFor(string db) =>
        Array.Find(DeltaDbs, d => d.Db == db).Overlay ?? (db + "-overlay.txt");

    private async Task<DeltaOutcome> TryDeltaAsync(string db, DbInfoEntry info,
        Dictionary<string, long> seqStore, Action<ProgressEvent> progress, CancellationToken ct)
    {
        string vdebName  = Array.Find(DeltaDbs, d => d.Db == db).Vdeb;
        string localPath = Path.Combine(DataDir, vdebName);
        string overlay   = Path.Combine(DataDir, OverlayFileFor(db));

        if (!info.DeltaAvailable) return DeltaOutcome.NeedFull;
        if (!File.Exists(localPath)) return DeltaOutcome.NeedFull;

        long localSeq = seqStore.TryGetValue(db, out var s) ? s : -1;

        if (localSeq < 0)
        {
            if (!string.IsNullOrEmpty(info.Sha256)
                && ComputeSha256(localPath).Equals(info.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                seqStore[db] = info.BaseSeq;
                ClearOverlay(overlay);
                return DeltaOutcome.UpToDate;
            }
            return DeltaOutcome.NeedFull;
        }

        if (localSeq >= info.Seq) return DeltaOutcome.UpToDate;

        var delta = await _http.GetFromJsonAsync<DeltaResponse>(
            $"update/{db}/delta?since={localSeq}", ct);
        if (delta == null) return DeltaOutcome.NeedFull;
        if (!string.Equals(delta.Mode, "delta", StringComparison.OrdinalIgnoreCase))
            return DeltaOutcome.NeedFull;

        int nAdd = delta.Added?.Count ?? 0;
        int nRem = delta.Removed?.Count ?? 0;
        ApplyDeltaToOverlay(overlay, delta.Added, delta.Removed);
        seqStore[db] = delta.ToSeq;

        string label = db == "vps" ? "Bazę zagrożeń" : "Białą listę";
        progress(new ProgressEvent("modules", "ok", 0, 0, 0, 0, 0,
            $"{label} zaktualizowano przyrostowo (+{nAdd} / -{nRem}).", db));
        return DeltaOutcome.AppliedDelta;
    }

    private static string SeqStorePath => Path.Combine(DataDir, "db-seq.json");

    private static Dictionary<string, long> LoadSeqStore()
    {
        var d = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (File.Exists(SeqStorePath) && JsonNode.Parse(File.ReadAllText(SeqStorePath)) is JsonObject o)
                foreach (var kv in o)
                    if (kv.Value is JsonValue v && v.TryGetValue<long>(out var seq))
                        d[kv.Key] = seq;
        }
        catch { }
        return d;
    }

    private static void SaveSeqStore(Dictionary<string, long> store)
    {
        try
        {
            var o = new JsonObject();
            foreach (var kv in store) o[kv.Key] = kv.Value;
            Directory.CreateDirectory(DataDir);
            File.WriteAllText(SeqStorePath, o.ToJsonString());
        }
        catch { }
    }

    private static void ApplyDeltaToOverlay(string overlayPath,
        IEnumerable<string>? added, IEnumerable<string>? removed)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(overlayPath)!);
        using var w = new StreamWriter(overlayPath, append: true, new System.Text.UTF8Encoding(false));
        if (added != null)
            foreach (var h in added) { var x = NormHash(h); if (x != null) w.WriteLine("+" + x); }
        if (removed != null)
            foreach (var h in removed) { var x = NormHash(h); if (x != null) w.WriteLine("-" + x); }

        static string? NormHash(string? h)
        {
            h = h?.Trim().ToLowerInvariant() ?? "";
            return (h.Length == 32 || h.Length == 64) ? h : null;
        }
    }

    private static void ClearOverlay(string overlayPath)
    {
        try { if (File.Exists(overlayPath)) File.Delete(overlayPath); } catch { }
    }

    private static string HumanLabel(string url) => url switch
    {
        "update/vps"       => "Bazę zagrożeń",
        "update/heur"      => "Moduły aplikacji",
        "update/whitelist" => "Dodatkowe moduły",
        _ => url,
    };

    private static string ComputeSha256(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            1 << 20, FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    private static string FormatBytes(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024L * 1024) return $"{b / 1024.0:F1} KB";
        if (b < 1024L * 1024 * 1024) return $"{b / 1024.0 / 1024:F1} MB";
        return $"{b / 1024.0 / 1024 / 1024:F2} GB";
    }

    private sealed class SpeedWindow
    {
        private readonly Queue<(DateTimeOffset t, long bytes)> _q = new();
        public void Add(long bytes)
        {
            var now = DateTimeOffset.UtcNow;
            _q.Enqueue((now, bytes));
            var cutoff = now - TimeSpan.FromSeconds(3);
            while (_q.Count > 0 && _q.Peek().t < cutoff) _q.Dequeue();
        }
        public double GetBytesPerSec()
        {
            if (_q.Count < 2) return 0;
            long total = 0;
            foreach (var (_, b) in _q) total += b;
            double dt = (DateTimeOffset.UtcNow - _q.Peek().t).TotalSeconds;
            return dt > 0.1 ? total / dt : 0;
        }
    }
}
