using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Malward.Engine.Config;
using Malward.Engine.Util;

namespace Malward.Engine.Cloud;

public sealed class UpdateService : IDisposable
{
    private readonly Settings _settings;
    private readonly ServerClient _client;

    private enum DeltaOutcome { UpToDate, AppliedDelta, NeedFull }

    /// <summary>Component, phase (checking/downloading/updated/current) and 0..1 progress within the component.
    /// Optional: callers that only read the console output leave it null.</summary>
    public Action<string, string, double>? Progress;

    private void Report(string component, string phase, double pct)
    {
        try { Progress?.Invoke(component, phase, pct); } catch { }
    }

    public UpdateService(Settings settings)
    {
        _settings = settings;
        _client = new ServerClient(settings);
    }

    public async Task<int> UpdateAllAsync(CancellationToken ct = default)
    {
        Paths.EnsureDirs();
        var manifest = await _client.GetManifestAsync(ct);
        Console.WriteLine($"[+] Manifest: vps={manifest.Vps.Available} heur={manifest.Heur.Available} whitelist={manifest.Whitelist.Available}");

        ServerClient.DbInfo? dbi = null;
        try { dbi = await _client.GetDbInfoAsync(ct); }
        catch (Exception ex) { Console.WriteLine($"[!] dbinfo niedostępne ({ex.Message}) — pełne pobrania"); }

        var seqStore = LoadSeqStore();
        int updated = 0;

        if (manifest.Vps.Available)
            updated += await UpdateDbAsync("vps", "update/vps", Paths.VpsVdeb,
                "vps-overlay.txt", manifest.Vps.Sha256, dbi?.Vps, seqStore, ct);
        if (manifest.Heur.Available)
            updated += await DownloadIfChanged("heur", "update/heur", Paths.HeurVdeb, manifest.Heur.Sha256, ct);
        if (manifest.Whitelist.Available)
            updated += await UpdateDbAsync("whitelist", "update/whitelist", Paths.WhitelistVdeb,
                "rf-whitelist-overlay.txt", manifest.Whitelist.Sha256, dbi?.Whitelist, seqStore, ct);

        SaveSeqStore(seqStore);

        StoreVersions(new Dictionary<string, string?>
        {
            ["vps"]       = dbi?.Vps?.Version,
            ["whitelist"] = dbi?.Whitelist?.Version,
            ["heur"]      = manifest.Heur.Version,
        });

        return updated;
    }

    /// <summary>Keeps the database build numbers where every front end reads them from.</summary>
    private static void StoreVersions(IDictionary<string, string?> values)
    {
        try
        {
            var path = Path.Combine(Paths.DataDir, "db-versions-server.json");
            var o = new JsonObject();
            try
            {
                if (File.Exists(path) && JsonNode.Parse(File.ReadAllText(path)) is JsonObject current)
                    o = current;
            }
            catch { }

            bool changed = false;
            foreach (var pair in values)
            {
                if (string.IsNullOrWhiteSpace(pair.Value)) continue;
                if (o[pair.Key]?.GetValue<string>() == pair.Value) continue;
                o[pair.Key] = pair.Value;
                changed = true;
            }
            if (!changed) return;

            Directory.CreateDirectory(Paths.DataDir);
            File.WriteAllText(path, o.ToJsonString());
        }
        catch { }
    }

    private async Task<int> UpdateDbAsync(string db, string endpoint, string destPath,
        string overlayName, string? remoteSha, ServerClient.DbInfoEntry? info,
        Dictionary<string, long> seqStore, CancellationToken ct)
    {
        string overlayPath = Path.Combine(Paths.DataDir, overlayName);

        Report(db, "checking", 0);
        var outcome = await TryDeltaAsync(db, destPath, overlayPath, info, seqStore, ct);
        if (outcome == DeltaOutcome.AppliedDelta) { Report(db, "updated", 1); return 1; }
        if (outcome == DeltaOutcome.UpToDate)     { Report(db, "current", 1); return 0; }

        int n = await DownloadIfChanged(db, endpoint, destPath, remoteSha, ct);

        if (info != null)
        {
            seqStore[db] = info.BaseSeq;
            ClearOverlay(overlayPath);
        }
        return n;
    }

    private async Task<DeltaOutcome> TryDeltaAsync(string db, string destPath, string overlayPath,
        ServerClient.DbInfoEntry? info, Dictionary<string, long> seqStore, CancellationToken ct)
    {
        if (info == null || !info.DeltaAvailable) return DeltaOutcome.NeedFull;
        if (!File.Exists(destPath)) return DeltaOutcome.NeedFull;

        long localSeq = seqStore.TryGetValue(db, out var s) ? s : -1;

        if (localSeq < 0)
        {
            if (!string.IsNullOrEmpty(info.Sha256)
                && ComputeFileSha256(destPath).Equals(info.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                seqStore[db] = info.BaseSeq;
                ClearOverlay(overlayPath);
                return DeltaOutcome.UpToDate;
            }
            return DeltaOutcome.NeedFull;
        }

        if (localSeq >= info.Seq) return DeltaOutcome.UpToDate;

        var delta = await _client.GetDeltaAsync(db, localSeq, ct);
        if (delta == null || !string.Equals(delta.Mode, "delta", StringComparison.OrdinalIgnoreCase))
            return DeltaOutcome.NeedFull;

        int nAdd = delta.Added?.Count ?? 0;
        int nRem = delta.Removed?.Count ?? 0;
        ApplyDeltaToOverlay(overlayPath, delta.Added, delta.Removed);
        seqStore[db] = delta.ToSeq;
        Console.WriteLine($"[+] {db}: delta +{nAdd} / -{nRem} (seq {localSeq}→{delta.ToSeq}) — pełne pobranie pominięte");
        return DeltaOutcome.AppliedDelta;
    }

    private static string SeqStorePath => Path.Combine(Paths.DataDir, "db-seq.json");

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
            Directory.CreateDirectory(Paths.DataDir);
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

    private async Task<int> DownloadIfChanged(string component, string endpoint, string destPath,
                                              string? remoteSha, CancellationToken ct)
    {
        var name = Path.GetFileName(destPath);
        Report(component, "checking", 0);
        if (string.IsNullOrEmpty(remoteSha))
        {
            Console.WriteLine($"[!] {name}: brak sha256 w manifeście — pomijam");
            Report(component, "current", 1);
            return 0;
        }
        if (File.Exists(destPath))
        {
            var localSha = ComputeFileSha256(destPath);
            if (string.Equals(localSha, remoteSha, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[+] {name}: aktualne (sha256 match)");
                Report(component, "current", 1);
                return 0;
            }
            Console.WriteLine($"[*] {name}: zmiana detected (lokalnie {localSha[..12]}…, zdalnie {remoteSha[..12]}…)");
        }
        else
        {
            Console.WriteLine($"[*] {name}: brak lokalnie — pobieram");
        }

        Report(component, "downloading", 0);
        await _client.DownloadAsync(endpoint, destPath,
            (done, total) => Report(component, "downloading", total > 0 ? (double)done / total : 0), ct);
        Console.WriteLine($"[+] {name}: zaktualizowano");
        Report(component, "updated", 1);
        return 1;
    }

    public async Task<bool> FetchSandboxAsync(string destPath, Action<long, long>? onProgress, CancellationToken ct = default)
    {
        var manifest = await _client.GetManifestAsync(ct);
        var meta = manifest.Sandbox;
        if (meta == null || !meta.Available)
            throw new Exception("Serwer nie udostępnia obrazu piaskownicy (modules/sandbox/default.7z).");

        if (File.Exists(destPath) && !string.IsNullOrEmpty(meta.Sha256))
        {
            var localSha = ComputeFileSha256(destPath);
            if (string.Equals(localSha, meta.Sha256, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        await _client.DownloadAsync("update/sandbox", destPath, onProgress, ct);
        return true;
    }

    public static string ComputeFileSha256(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                                      1 << 20, FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    public void Dispose() => _client.Dispose();
}
