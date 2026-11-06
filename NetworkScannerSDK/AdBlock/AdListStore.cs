using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.NetworkScanner.AdBlock;

public sealed class AdListSubscription
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    [JsonPropertyName("dns_only")] public bool DnsOnly { get; set; }
    [JsonPropertyName("custom")] public bool Custom { get; set; }

    [JsonIgnore]
    public bool IsUrl =>
        Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
}

public sealed class AdListState
{
    [JsonPropertyName("lists")] public List<AdListSubscription> Lists { get; set; } = new();
    [JsonPropertyName("user_rules")] public List<string> UserRules { get; set; } = new();
    [JsonPropertyName("last_update")] public long LastUpdateUnix { get; set; }
    [JsonPropertyName("format")] public int Format { get; set; }
}

public sealed record AdListFailure(string Name, string Url, string Reason, bool HasCachedCopy);

public static class AdListStore
{
    private const int MinSize = 200;
    private const int DownloadAttempts = 4;

    private static readonly HttpClient Http = CreateClient();
    private static readonly SemaphoreSlim BuildGate = new(1, 1);

    public static string RootDir
    {
        get
        {
            var over = Environment.GetEnvironmentVariable("MALWARD_ADBLOCK_DIR");
            return string.IsNullOrWhiteSpace(over)
                ? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Malward", "data", "adblock")
                : over;
        }
    }

    public static string DatabaseDir => Path.Combine(RootDir, "db");
    public static string CacheDir => Path.Combine(RootDir, "lists");
    public static string StatePath => Path.Combine(RootDir, "subscriptions.json");

    public static List<AdListFailure> LastFailures { get; private set; } = new();

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.All,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            ConnectTimeout = TimeSpan.FromSeconds(20),
            UseProxy = false,
            Proxy = null,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(120) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Malward/1.0");
        c.DefaultRequestHeaders.Accept.ParseAdd("text/plain, */*");
        return c;
    }

    public static AdListState LoadState()
    {
        try
        {
            if (File.Exists(StatePath))
            {
                var state = JsonSerializer.Deserialize<AdListState>(File.ReadAllText(StatePath));
                if (state != null)
                {
                    if (state.Lists.Count == 0) state.Lists = Defaults();
                    return state;
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warn("AdBlock", $"Failed to read {StatePath}: {ex.Message} — using defaults.");
        }
        return new AdListState { Lists = Defaults() };
    }

    private static volatile string _lastWritten = "";
    private static long _lastWrittenTicks;

    private static readonly TimeSpan OwnWriteWindow = TimeSpan.FromSeconds(5);

    public static bool IsOwnWrite(string content)
    {
        if (content.Length == 0 || content != _lastWritten) return false;
        var when = new DateTime(Interlocked.Read(ref _lastWrittenTicks), DateTimeKind.Utc);
        return DateTime.UtcNow - when < OwnWriteWindow;
    }

    public static string ReadStateRaw()
    {
        try { return File.Exists(StatePath) ? File.ReadAllText(StatePath) : ""; }
        catch { return ""; }
    }

    public static void SaveState(AdListState state)
    {
        try
        {
            Directory.CreateDirectory(RootDir);
            var text = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            _lastWritten = text;
            Interlocked.Exchange(ref _lastWrittenTicks, DateTime.UtcNow.Ticks);
            var tmp = StatePath + ".tmp";
            File.WriteAllText(tmp, text);
            File.Move(tmp, StatePath, overwrite: true);
        }
        catch (Exception ex) { Log.Warn("AdBlock", $"Failed to save {StatePath}: {ex.Message}"); }
    }

    public static List<AdListSubscription> Defaults()
    {
        var list = new List<AdListSubscription>();
        foreach (var e in AdListCatalog.All)
            if (e.DefaultOn)
                list.Add(new AdListSubscription
                {
                    Name = e.Name, Url = e.Url, Enabled = true, DnsOnly = e.DnsOnly,
                });
        return list;
    }

    public static string CacheFileFor(string url) =>
        Path.Combine(CacheDir, HashName(url) + ".txt");

    private static string HashName(string url) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(url)))[..16].ToLowerInvariant();

    public static string StagingDir => DatabaseDir + "-new";

    public static async Task<AdRuleStats?> RefreshAsync(AdListState state, bool forceDownload,
                                                        Action<string>? progress = null,
                                                        CancellationToken ct = default,
                                                        Action? beforePublish = null)
    {
        if (!await BuildGate.WaitAsync(0, ct)) return null;
        try
        {
            Directory.CreateDirectory(CacheDir);
            Directory.CreateDirectory(DatabaseDir);

            var files = await EnsureCachedAsync(state.Lists, forceDownload, progress, ct);
            progress?.Invoke("Budowanie bazy reguł…");

            ResetDirectory(StagingDir);
            var stats = AdRuleCompiler.Build(StagingDir, files,
                new[] { string.Join("\n", state.UserRules) }, TrustedJsSources(state, files));

            beforePublish?.Invoke();
            Publish();

            state.LastUpdateUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            state.Format = AdRuleCompiler.FormatVersion;
            SaveState(state);

            Log.Info("AdBlock", $"Rule database built: {stats.BlockDomains} browser domains, "
                                + $"{stats.BlockDomainsDns} DNS domains, {stats.AllowDomains} exceptions, "
                                + $"{stats.NetworkRules} URL rules, {stats.DbBytes / 1024} KB on disk.");
            return stats;
        }
        finally { BuildGate.Release(); }
    }

    private static IReadOnlySet<string> TrustedJsSources(
        AdListState state, IReadOnlyList<(string path, bool dnsOnly, string name)> files)
    {
        var trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var sub in state.Lists)
        {
            if (sub.Custom || AdListCatalog.Find(sub.Url) == null) continue;
            var cached = sub.IsUrl ? CacheFileFor(sub.Url) : sub.Url;
            foreach (var f in files)
                if (string.Equals(f.path, cached, StringComparison.OrdinalIgnoreCase))
                    trusted.Add(f.path);
        }
        return trusted;
    }

    private static void ResetDirectory(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch { }
        Directory.CreateDirectory(dir);
    }

    private static void Publish()
    {
        Directory.CreateDirectory(DatabaseDir);
        foreach (var src in Directory.GetFiles(StagingDir))
        {
            var dst = Path.Combine(DatabaseDir, Path.GetFileName(src));
            try { File.Move(src, dst, overwrite: true); }
            catch (Exception ex)
            {
                Log.Warn("AdBlock", $"Could not publish {Path.GetFileName(src)}: {ex.Message}");
                throw;
            }
        }
        try { Directory.Delete(StagingDir, recursive: true); } catch { }
    }

    public static bool NeedsRebuild(AdListState state)
    {
        if (state.Format != AdRuleCompiler.FormatVersion) return true;
        if (AdRuleStore.StoredFormatVersion(DatabaseDir) != AdRuleCompiler.FormatVersion) return true;
        if (!File.Exists(Path.Combine(DatabaseDir, "meta.txt"))) return true;
        return false;
    }

    public static bool UpdateDue(AdListState state, TimeSpan interval)
    {
        if (state.LastUpdateUnix <= 0) return true;
        var last = DateTimeOffset.FromUnixTimeSeconds(state.LastUpdateUnix);
        return DateTimeOffset.UtcNow - last >= interval;
    }

    private static async Task<List<(string path, bool dnsOnly, string name)>> EnsureCachedAsync(
        IEnumerable<AdListSubscription> sources, bool forceDownload,
        Action<string>? progress, CancellationToken ct)
    {
        var enabled = sources.Where(x => x.Enabled && !string.IsNullOrWhiteSpace(x.Url)).ToList();
        int total = enabled.Count, done = 0, failed = 0;
        var failures = new ConcurrentBag<AdListFailure>();
        var results = new (string path, bool dnsOnly, string name)?[enabled.Count];

        using var gate = new SemaphoreSlim(6);
        var tasks = new Task[enabled.Count];
        for (int i = 0; i < enabled.Count; i++)
        {
            int idx = i;
            var s = enabled[idx];
            tasks[idx] = Task.Run(async () =>
            {
                await gate.WaitAsync(ct);
                try
                {
                    if (!s.IsUrl)
                    {
                        results[idx] = File.Exists(s.Url) ? (s.Url, s.DnsOnly, SourceName(s)) : null;
                        return;
                    }

                    var cache = CacheFileFor(s.Url);
                    bool hadCopy = File.Exists(cache) && new FileInfo(cache).Length > MinSize;

                    if (forceDownload || !hadCopy)
                    {
                        var err = await DownloadAsync(s, cache, ct);
                        if (err != null)
                        {
                            Interlocked.Increment(ref failed);
                            failures.Add(new AdListFailure(SourceName(s), s.Url, err, hadCopy));
                            Log.Warn("AdBlock", $"Download of '{SourceName(s)}' failed: {err}"
                                                + (hadCopy ? " — previous copy kept."
                                                           : " — no copy, list skipped."));
                        }
                    }

                    results[idx] = File.Exists(cache) && new FileInfo(cache).Length > MinSize
                        ? (cache, s.DnsOnly, SourceName(s)) : null;
                }
                finally
                {
                    gate.Release();
                    int d = Interlocked.Increment(ref done);
                    int f = Volatile.Read(ref failed);
                    progress?.Invoke($"Pobieranie list… {d}/{total}"
                                     + (f > 0 ? $" ({f} nieudanych)" : ""));
                }
            }, ct);
        }

        await Task.WhenAll(tasks);
        LastFailures = failures.ToList();
        return results.Where(p => p != null).Select(p => p!.Value).ToList();
    }

    private static async Task<string?> DownloadAsync(AdListSubscription s, string cache, CancellationToken ct)
    {
        string err = "unknown error";
        for (int attempt = 1; attempt <= DownloadAttempts; attempt++)
        {
            var tmp = cache + "." + Guid.NewGuid().ToString("N")[..8] + ".part";
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(45));
                using var resp = await Http.GetAsync(s.Url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                resp.EnsureSuccessStatusCode();

                long written;
                await using (var net = await resp.Content.ReadAsStreamAsync(cts.Token))
                await using (var file = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
                {
                    await net.CopyToAsync(file, cts.Token);
                    written = file.Length;
                }

                if (written < MinSize)
                {
                    err = $"response was only {written} B — not a filter list";
                    File.Delete(tmp);
                }
                else
                {
                    File.Move(tmp, cache, overwrite: true);
                    return null;
                }
            }
            catch (Exception ex)
            {
                err = DescribeError(ex);
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
            if (attempt < DownloadAttempts) await Task.Delay(400 * attempt, ct);
        }
        return err;
    }

    private static string DescribeError(Exception ex)
    {
        var se = ex as System.Net.Sockets.SocketException
                 ?? ex.InnerException as System.Net.Sockets.SocketException
                 ?? ex.InnerException?.InnerException as System.Net.Sockets.SocketException;
        if (se == null)
        {
            if (ex is TaskCanceledException or OperationCanceledException) return "timed out after 45 s";
            return (ex.InnerException?.Message ?? ex.Message).Trim();
        }
        return $"{se.SocketErrorCode} ({se.NativeErrorCode})";
    }

    private static string SourceName(AdListSubscription s)
    {
        if (!string.IsNullOrWhiteSpace(s.Name) && s.Name != s.Url) return s.Name;
        try { return s.IsUrl ? new Uri(s.Url).Host : Path.GetFileName(s.Url); }
        catch { return s.Url; }
    }
}
