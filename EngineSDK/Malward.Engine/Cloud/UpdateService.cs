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
            updated += await DownloadIfChanged("update/heur", Paths.HeurVdeb, manifest.Heur.Sha256, ct);
        if (manifest.Whitelist.Available)
            updated += await UpdateDbAsync("whitelist", "update/whitelist", Paths.WhitelistVdeb,
                "rf-whitelist-overlay.txt", manifest.Whitelist.Sha256, dbi?.Whitelist, seqStore, ct);

        SaveSeqStore(seqStore);
        return updated;
    }

    private async Task<int> UpdateDbAsync(string db, string endpoint, string destPath,
        string overlayName, string? remoteSha, ServerClient.DbInfoEntry? info,
        Dictionary<string, long> seqStore, CancellationToken ct)
    {
        string overlayPath = Path.Combine(Paths.DataDir, overlayName);

        var outcome = await TryDeltaAsync(db, destPath, overlayPath, info, seqStore, ct);
        if (outcome == DeltaOutcome.AppliedDelta) return 1;
        if (outcome == DeltaOutcome.UpToDate)     return 0;

        int n = await DownloadIfChanged(endpoint, destPath, remoteSha, ct);

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

    private async Task<int> DownloadIfChanged(string endpoint, string destPath, string? remoteSha, CancellationToken ct)
    {
        var name = Path.GetFileName(destPath);
        if (string.IsNullOrEmpty(remoteSha))
        {
            Console.WriteLine($"[!] {name}: brak sha256 w manifeście — pomijam");
            return 0;
        }
        if (File.Exists(destPath))
        {
            var localSha = ComputeFileSha256(destPath);
            if (string.Equals(localSha, remoteSha, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[+] {name}: aktualne (sha256 match)");
                return 0;
            }
            Console.WriteLine($"[*] {name}: zmiana detected (lokalnie {localSha[..12]}…, zdalnie {remoteSha[..12]}…)");
        }
        else
        {
            Console.WriteLine($"[*] {name}: brak lokalnie — pobieram");
        }
        await _client.DownloadAsync(endpoint, destPath, ct);
        Console.WriteLine($"[+] {name}: zaktualizowano");
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
