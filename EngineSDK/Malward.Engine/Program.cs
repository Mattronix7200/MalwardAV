using System.Reflection;
using Malward.Engine.Cloud;
using Malward.Engine.Config;
using Malward.Engine.Core;
using Malward.Engine.Heuristic;
using Malward.Engine.Memory;
using Malward.Engine.Quarantine;
using Malward.Engine.Repair;
using Malward.Engine.Util;
using Malward.Engine.Vdeb;

namespace Malward.Engine;

internal static class Program
{
    private enum Verbosity { Normal, VerySilent, Silent }

    public static int Main(string[] args)
    {
        try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

        bool buildHelper = args.Length > 0
            && (args[0].Equals("make-configkey", StringComparison.OrdinalIgnoreCase)
             || args[0].Equals("make-sigdata", StringComparison.OrdinalIgnoreCase));
        if (!buildHelper) AdminCheck.RequireAdmin();

        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        var settings = Settings.Load();

        return args[0].ToLowerInvariant() switch
        {
            "scan"        => CmdScan(args, settings),
            "scan-memory" => CmdScanMemory(args, settings),
            "update"      => CmdUpdate(args, settings),
            "fetch-sandbox" => CmdFetchSandbox(args, settings),
            "quarantine"  => CmdQuarantine(args, settings),
            "analyze"     => CmdAnalyze(args, settings),
            "analyze-file" => CmdAnalyzeFile(args, settings),
            "version" or "--version" or "-v" => CmdVersion(),
            "lookup"      => CmdLookup(args),
            "diag-db"     => CmdDiagDb(args),
            "diag-cloud"  => CmdDiagCloud(settings),
            "make-configkey" => CmdMakeConfigKey(args),
            "make-sigdata"   => CmdMakeSigData(args),
            "repair"      => CmdRepair(args, settings),
            "sysrepair"   => CmdSysRepair(args),
            "submit-detection" => CmdSubmitDetection(args, settings),
            _             => PrintUsageWithError($"Unknown verb: {args[0]}"),
        };
    }

    private static int CmdMakeSigData(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("make-sigdata: usage: malscan make-sigdata <source.json> <output.vdeb>");
            return 2;
        }
        var src = args[1];
        var dst = args[2];
        try
        {
            if (!File.Exists(src)) { Console.Error.WriteLine($"[!] Source file not found: {src}"); return 1; }
            var json = File.ReadAllText(src);

            using (var doc = System.Text.Json.JsonDocument.Parse(json)) { }
            Data.SignatureStore.Write(json, dst);
            var len = new FileInfo(dst).Length;
            Console.WriteLine($"[+] sigdata: {Path.GetFileName(dst)} ({len:N0} B) z {Path.GetFileName(src)}");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine($"[!] make-sigdata: {ex.Message}"); return 1; }
    }

    internal static int CmdSubmitDetection(string[] args, Settings settings)
    {
        if (args.Length < 2) return PrintUsageWithError("submit-detection: missing file path");
        string path = args[1];
        string detection = "Behavior.Malicious";
        for (int i = 2; i < args.Length - 1; i++)
            if (args[i] is "--name" or "-n") detection = args[i + 1];

        if (!File.Exists(path)) { Console.Error.WriteLine("[!] File does not exist: " + path); return 1; }
        if (!settings.CloudScanEnabled) { Console.WriteLine("SUBMIT\tskip=cloud-disabled"); return 0; }

        try
        {
            string sha  = Malward.Engine.Core.HashService.Sha256Hex(path);
            string? imp = Malward.Engine.Util.PeImpHash.Compute(path);
            long size   = new FileInfo(path).Length;
            using var cloud = new ServerClient(settings);
            cloud.SubmitBadAsync(sha, imp, size, detection).GetAwaiter().GetResult();
            Console.WriteLine($"SUBMIT\tok=1\tsha256={sha}\timphash={imp ?? "-"}");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine($"[!] submit error: {ex.Message}"); return 1; }
    }

    private static int CmdSysRepair(string[] args)
    {
        var scanner = new Malward.Engine.SysRepair.SystemRepairScanner();
        string sub = args.Length >= 2 ? args[1].ToLowerInvariant() : "scan";

        if (sub == "fix")
        {
            if (args.Length < 3) return PrintUsageWithError("sysrepair fix: missing identifiers");
            var ids = args[2].Equals("all", StringComparison.OrdinalIgnoreCase)
                ? scanner.Scan().Where(i => i.Tampered && i.CanAutoRepair).Select(i => i.Id).ToList()
                : args[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            int fixedCount = 0;
            foreach (var id in ids)
            {
                var (ok, err) = scanner.Repair(id);
                if (ok) fixedCount++;
                Console.WriteLine($"SYSREPAIR-FIX\tid={id}\tok={(ok ? 1 : 0)}\terror={err ?? ""}");
            }
            Console.WriteLine($"SYSREPAIR-DONE\tfixed={fixedCount}\ttotal={ids.Count}");
            return fixedCount == ids.Count ? 0 : 6;
        }

        ISet<string>? enabled = null;
        if (args.Length >= 3)
            enabled = args[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var items = scanner.Scan(enabled);
        int tampered = 0;
        foreach (var it in items)
        {
            if (it.Tampered) tampered++;
            string detail = (it.Detail ?? "").Replace('\t', ' ').Replace('\n', ' ');
            Console.WriteLine($"SYSREPAIR-ITEM\tid={it.Id}\tname={it.Name}\tcat={it.Category}" +
                              $"\ttampered={(it.Tampered ? 1 : 0)}\tauto={(it.CanAutoRepair ? 1 : 0)}\tdesc={it.Description}\tdetail={detail}");
        }
        Console.WriteLine($"SYSREPAIR-SUMMARY\ttampered={tampered}\ttotal={items.Count}");
        return 0;
    }

    private static int CmdRepair(string[] args, Settings settings)
    {
        if (args.Length >= 3 && args[1] == "--list")
            return CmdRepairList(args, settings);

        if (args.Length < 3)
            return PrintUsageWithError("repair: usage: repair <quarantine|delete|entry> <path> "
                                       + "[--detection name] [--entry chain]"
                                       + " | repair --list <file> [--report <file>]");
        var action = args[1].ToLowerInvariant();
        var path = args[2];
        string? detection = null;

        string? entryChain = null;
        for (int i = 3; i < args.Length - 1; i++)
        {
            if (args[i] == "--detection") detection = args[++i];
            else if (args[i] == "--entry") entryChain = args[++i];
        }

        if (Repair.RegistryRepair.IsRegistryLocation(path))
        {
            var reg = Repair.RegistryRepair.Remove(path);
            Console.WriteLine($"[{(reg.Ok ? "OK" : "FAIL")}] registry: {path} {reg.Error ?? ""}");
            if (!reg.Ok) Console.WriteLine($"REGFAIL\tlocation={path}\treason={reg.Error ?? ""}");
            return reg.Ok ? 0 : 1;
        }

        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"[!] Does not exist: {path}");
            return 3;
        }
        try
        {
            var tempSettings = new Settings();

            int mode = action switch
            {
                "quarantine" => 2,
                "delete"     => 3,
                "entry"      => 3,   
                _            => 2,
            };
            var s2 = System.Text.Json.JsonSerializer.Deserialize<Settings>(
                System.Text.Json.JsonSerializer.Serialize(settings)) ?? settings;
            s2.RepairMode = mode;

            var repairer = new Malward.Engine.Repair.Repairer(s2);
            var sha = HashService.Sha256Hex(path);

            if (!string.IsNullOrEmpty(entryChain)) s2.ArchiveRepairMode = 2;
            var det = new DetectionResult(path, sha, Verdict.Malware,
                detection ?? "Malware", "user-batch", new FileInfo(path).Length, 0,
                ArchiveEntry: entryChain);

            var outcome = repairer.Repair(det, userInitiated: true);
            Console.WriteLine($"[{(outcome.Success ? "OK" : "FAIL")}] {action}: {outcome.Action} {outcome.Detail}");
            Console.WriteLine($"REPAIR\taction={Esc(outcome.Action)}\tok={(outcome.Success ? 1 : 0)}" +
                              $"\treboot={(outcome.RebootRequired ? 1 : 0)}\tdetail={Esc(outcome.Detail ?? "")}");

            bool didSomething = outcome.Success
                                && outcome.Action is not ("deferred" or "noop" or "system-skip");
            return didSomething ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] repair: {ex.Message}");
            return 4;
        }
    }

    /// <summary>Repairs every item of a list in ONE process run.</summary>
    /// <remarks>
    /// Written for the elevated retry: a batch of twenty protected files would otherwise mean
    /// twenty UAC prompts. The report file carries the per-item outcome back, because an
    /// elevated child cannot write to the caller's redirected stdout.
    /// </remarks>
    private static int CmdRepairList(string[] args, Settings settings)
    {
        string listPath = args[2];
        string? reportPath = null;
        for (int i = 3; i < args.Length - 1; i++)
            if (args[i] == "--report") reportPath = args[++i];

        if (!File.Exists(listPath))
        {
            Console.Error.WriteLine($"[!] repair --list: no such file: {listPath}");
            return 2;
        }

        var report = new List<string>();
        int failed = 0;

        foreach (var line in File.ReadAllLines(listPath))
        {
            if (line.Trim().Length == 0) continue;
            var parts = line.Split('\t');
            string action = parts.Length > 0 ? parts[0].ToLowerInvariant() : "quarantine";
            string path = parts.Length > 1 ? parts[1] : "";
            string detection = parts.Length > 2 ? parts[2] : "";
            string entry = parts.Length > 3 ? parts[3] : "";
            if (path.Length == 0) continue;

            var own = new List<string> { "repair", action, path };
            if (detection.Length > 0) { own.Add("--detection"); own.Add(detection); }
            if (entry.Length > 0) { own.Add("--entry"); own.Add(entry); }

            int code;
            var bufor = new StringWriter();
            var poprzedni = Console.Out;
            Console.SetOut(bufor);
            try { code = CmdRepair(own.ToArray(), settings); }
            finally { Console.SetOut(poprzedni); }

            var wypisane = bufor.ToString();
            Console.Write(wypisane);

            string outcome = wypisane.Split('\n')
                .FirstOrDefault(l => l.StartsWith("REPAIR\t", StringComparison.Ordinal))?.TrimEnd()
                ?? $"REPAIR\taction=unknown\tok=0\treboot=0\tdetail=";
            report.Add($"{outcome}\tpath={Esc(path)}");
            if (code != 0) failed++;
        }

        if (reportPath != null)
        {
            try { File.WriteAllLines(reportPath, report); }
            catch (Exception ex) { Console.Error.WriteLine($"[!] repair --list: report: {ex.Message}"); }
        }

        return failed == 0 ? 0 : 1;
    }

    private static int CmdLookup(string[] args)
    {
        if (args.Length < 2)
            return PrintUsageWithError("lookup: missing sha256");
        var sha = args[1].ToLowerInvariant();
        if (sha.Length != 64 || sha.Any(c => !"0123456789abcdef".Contains(c)))
            return PrintUsageWithError("lookup: sha256 must be 64 hex chars");

        Console.WriteLine($"Lookup: {sha}\n");
        DumpVdebLookup("VPS", Paths.VpsVdebReadable, sha);
        Console.WriteLine();
        DumpVdebLookup("Whitelist", Paths.WhitelistVdebReadable, sha);
        return 0;
    }

    private static void DumpVdebLookup(string label, string path, string sha)
    {
        Console.WriteLine($"{label} path: {path}");
        Console.WriteLine($"  exists: {File.Exists(path)}");
        if (!File.Exists(path)) return;

        try
        {
            using var r = new VdebReader(path);
            Console.WriteLine($"  entries: {r.TotalEntries:N0}");
            Console.WriteLine($"  mode   : {(r.IsCompact ? $"COMPACT-{r.CompactPrefix}B" : "FULL")}");

            var positions = BloomFilter.Positions(sha, BloomFilter.BLOOM_SIZE_BYTES);
            Console.WriteLine($"  bloom positions (7) for hash:");
            int setBits = 0;
            foreach (var pos in positions)
            {
                long byteOff = pos / 8;
                int bit = (int)(pos % 8);
                byte b = r.Bloom.ReadByteForDiag(byteOff);
                bool isSet = (b & (1 << bit)) != 0;
                if (isSet) setBits++;
                Console.WriteLine($"    pos={pos,10:N0}  byteOff={byteOff,9:N0}  bit={bit}  value=0x{b:X2}  → {(isSet ? "SET" : "unset")}");
            }
            Console.WriteLine($"  bloom may-contain: {(setBits == 7)}");

            int sampleSet = 0;
            for (long i = 0; i < 1024; i++)
            {
                byte b = r.Bloom.ReadByteForDiag(i);
                sampleSet += System.Numerics.BitOperations.PopCount(b);
            }
            Console.WriteLine($"  bloom sample (first 1024 B): {sampleSet} bits set of {1024 * 8} (~{(100.0 * sampleSet / (1024 * 8)):F1}% fill)");

            int sk = (HexNibble(sha[0]) << 4) | HexNibble(sha[1]);
            Console.WriteLine($"  shard key: 0x{sk:X2}");
            var entry = r.IndexEntryFor((ushort)sk);
            if (entry == null) { Console.WriteLine("    NOT IN INDEX"); }
            else
            {
                Console.WriteLine($"    data_offset={entry.Value.DataOffset:N0}  comp={entry.Value.CompressedSize:N0}  uncomp={entry.Value.UncompressedSize:N0}  entries={entry.Value.EntryCount:N0}");
                if (r.IsCompact)
                {
                    int n = r.CompactPrefix;
                    var prefixHex = sha.Substring(0, n * 2);
                    Console.WriteLine($"    looking for prefix: {prefixHex}");
                    Console.WriteLine($"    binary-search result: {r.HasPrefixInShard((ushort)sk, prefixHex)}");
                }
            }

            var det = r.TryFind(sha);
            Console.WriteLine($"  result : {(det != null ? $"MATCH → {det}" : "no match")}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ERROR: {ex.Message}");
        }
    }

    private static int HexNibble(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => 10 + (c - 'a'),
        >= 'A' and <= 'F' => 10 + (c - 'A'),
        _ => 0
    };

    private static int CmdMakeConfigKey(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("usage: malscan make-configkey <input.json> <output/configKey>");
            return 2;
        }
        string src = args[1], dst = args[2];
        try
        {
            if (!File.Exists(src)) { Console.Error.WriteLine($"[!] File not found: {src}"); return 1; }
            string json = File.ReadAllText(src).TrimStart('﻿');

            using var doc = System.Text.Json.JsonDocument.Parse(json);
            bool hasPsk = doc.RootElement.TryGetProperty("auth_psk", out var pskEl)
                          && !string.IsNullOrWhiteSpace(pskEl.GetString());
            if (!hasPsk) { Console.Error.WriteLine("[!] Missing non-empty auth_psk field."); return 1; }

            File.WriteAllBytes(dst, Cloud.ConfigKeyFile.Protect(json));

            var check = Cloud.ConfigKeyFile.Unprotect(File.ReadAllBytes(dst));
            if (check != json) { Console.Error.WriteLine("[!] Read-back verification failed."); return 1; }

            Console.WriteLine($"[+] {Cloud.ConfigKeyFile.FileName}: {new FileInfo(dst).Length} B, zweryfikowany");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine($"[!] {ex.Message}"); return 1; }
    }

    private static int CmdDiagCloud(Settings settings)
    {
        Console.WriteLine("=== KLIENT: sekrety ===");
        string envPsk = Environment.GetEnvironmentVariable("MALWARD_AUTH_PSK") ?? "";
        string cfgPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "client-auth.json");
        Console.WriteLine($"  MALWARD_AUTH_PSK      : {(envPsk.Length > 0 ? "ustawiona" : "brak")}");
        Console.WriteLine($"  client-auth.json      : {(File.Exists(cfgPath) ? "JEST" : "BRAK")}  {cfgPath}");
        Console.WriteLine($"  PSK wczytany          : {(Cloud.ClientSecrets.HasPsk ? "TAK" : "NIE !!!")}");
        Console.WriteLine($"  zrodlo / powod        : {Cloud.ClientSecrets.LastDiagnostic}");
        Console.WriteLine($"  PSK fingerprint       : {Cloud.ServerClient.PskFingerprint()}"
                          + $"  (dlugosc {Cloud.ClientSecrets.AuthPsk.Length})");
        Console.WriteLine($"  heur password         : {(Cloud.ClientSecrets.HeurPassword.Length > 0 ? "TAK" : "NIE")}");

        Console.WriteLine("\n=== KLIENT: konfiguracja ===");
        Console.WriteLine($"  serwer                : https://{settings.ServerIp}:{settings.ServerPort}/");
        Console.WriteLine($"  chmura wlaczona       : {settings.CloudScanEnabled}");
        Console.WriteLine($"  czas UTC              : {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}  "
                          + $"unix={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}");

        if (!Cloud.ClientSecrets.HasPsk)
        {
            Console.WriteLine("\n>>> Klient nie ma PSK — kazde zadanie dostanie 401. Utworz " + cfgPath);
            return 1;
        }

        Console.WriteLine("\n=== HANDSHAKE ===");
        try
        {
            var client = new Cloud.ServerClient(settings);
            client.EnsureAuthAsync().GetAwaiter().GetResult();
            var manifest = client.GetManifestAsync().GetAwaiter().GetResult();
            Console.WriteLine($"  /update/manifest      : OK (vps {manifest.Vps?.Size} B, "
                              + $"heur {manifest.Heur?.Size} B, whitelist {manifest.Whitelist?.Size} B)");
            Console.WriteLine("\n>>> DZIALA. Uwierzytelnienie i pobieranie aktualizacji sprawne.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  BLAD: {ex.Message}");
            Console.WriteLine("\n>>> Porownaj powyzszy fingerprint z linia [secrets] w logu serwera.");
            Console.WriteLine(">>> Rozne fingerprinty = rozne hasla. Takie same = problem po stronie serwera.");
            return 1;
        }
    }

    private static int CmdDiagDb(string[] args)
    {
        var opts = new System.Text.Json.JsonSerializerOptions { WriteIndented = false };
        try
        {
            string kind = args.Length >= 2 ? args[1].ToLowerInvariant() : "";
            object result = kind switch
            {
                "url" => DiagUrlDb(args),
                "vps" => DiagVpsDb(args),
                _     => new Dictionary<string, object?> { ["error"] = "usage: diag-db <url|vps> [...]" },
            };
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(result, opts));
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(
                new Dictionary<string, object?> { ["error"] = ex.Message }, opts));
            return 1;
        }
    }

    private static string UnixToIso(ulong ts)
        => ts == 0 ? "" : DateTimeOffset.FromUnixTimeSeconds((long)ts).UtcDateTime
                            .ToString("yyyy-MM-dd HH:mm:ss") + " UTC";

    private static object DiagUrlDb(string[] args)
    {
        int offset = args.Length >= 3 && int.TryParse(args[2], out var o) ? Math.Max(0, o) : 0;
        int limit  = args.Length >= 4 && int.TryParse(args[3], out var l) ? Math.Clamp(l, 1, 5000) : 200;
        string query = args.Length >= 5 ? args[4].ToLowerInvariant() : "";

        string path = Path.Combine(Paths.DataDir, "urls.vdeb");
        var errors = new List<string>();
        var res = new Dictionary<string, object?>
        {
            ["db"] = "url", ["path"] = path, ["exists"] = File.Exists(path),
            ["offset"] = offset, ["limit"] = limit, ["query"] = query,
        };
        if (!File.Exists(path))
        {
            res["total"] = 0; res["totalAll"] = 0; res["records"] = Array.Empty<string>();
            res["errors"] = new[] { "plik nie istnieje" };
            return res;
        }
        res["fileSize"] = new FileInfo(path).Length;

        var domains = new List<string>();
        uint declared = 0;
        try
        {
            byte[] buf;
            using (var fs = File.OpenRead(path))
            using (var gz = new System.IO.Compression.GZipStream(fs, System.IO.Compression.CompressionMode.Decompress))
            using (var ms = new MemoryStream())
            {
                gz.CopyTo(ms);
                buf = ms.ToArray();
            }
            if (buf.Length < 8 || buf[0] != (byte)'V' || buf[1] != (byte)'D' || buf[2] != (byte)'E' || buf[3] != (byte)'B')
                errors.Add("zły magic (oczekiwano 'VDEB')");
            if (buf.Length >= 8) declared = BitConverter.ToUInt32(buf, 4);

            int emptyCnt = 0, noDotCnt = 0, sortViol = 0;
            string? prev = null;
            int start = 8;
            for (int i = 8; i <= buf.Length; i++)
            {
                if (i == buf.Length || buf[i] == 0)
                {
                    if (i > start)
                    {
                        var d = System.Text.Encoding.UTF8.GetString(buf, start, i - start);
                        if (!d.Contains('.')) noDotCnt++;
                        if (prev != null && string.CompareOrdinal(prev, d) > 0) sortViol++;
                        prev = d;
                        domains.Add(d);
                    }
                    else if (i < buf.Length) emptyCnt++;
                    start = i + 1;
                }
            }
            if (declared != domains.Count) errors.Add($"count mismatch: nagłówek={declared:N0}, faktycznie={domains.Count:N0}");
            if (emptyCnt > 0) errors.Add($"puste rekordy: {emptyCnt}");
            if (noDotCnt > 0) errors.Add($"rekordy bez kropki: {noDotCnt}");
            if (sortViol > 0) errors.Add($"naruszenia sortowania leksykalnego: {sortViol}");
        }
        catch (Exception ex) { errors.Add("odczyt/gzip: " + ex.Message); }

        List<string> filtered = query.Length > 0
            ? domains.Where(d => d.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList()
            : domains;
        res["totalAll"] = domains.Count;
        res["total"] = filtered.Count;
        res["records"] = filtered.Skip(offset).Take(limit).ToArray();
        res["errors"] = errors;
        return res;
    }

    private static object DiagVpsDb(string[] args)
    {
        string query = args.Length >= 3 ? args[2].Trim().ToLowerInvariant() : "";
        string path = Paths.VpsVdebReadable;
        var errors = new List<string>();
        var res = new Dictionary<string, object?>
        {
            ["db"] = "vps", ["path"] = path, ["exists"] = File.Exists(path), ["query"] = query,
        };
        if (!File.Exists(path)) { res["errors"] = new[] { "plik nie istnieje" }; return res; }
        res["fileSize"] = new FileInfo(path).Length;
        try
        {
            using var r = new VdebReader(path);
            res["magicOk"] = true;
            res["compact"] = r.IsCompact;
            res["compactPrefix"] = (int)r.CompactPrefix;
            res["total"] = r.TotalEntries;
            res["malwareCount"] = r.MalwareCount;
            res["cleanCount"] = r.CleanCount;
            res["created"] = UnixToIso(r.CreatedTs);
            res["last"] = UnixToIso(r.LastTs);

            var shards = r.ShardKeys;
            res["shardCount"] = shards.Count;
            ulong sum = 0;
            foreach (var k in shards) { var e = r.IndexEntryFor(k); if (e != null) sum += e.Value.EntryCount; }
            res["shardEntrySum"] = sum;
            if (sum != r.TotalEntries)
                errors.Add($"suma wpisów shardów ({sum:N0}) ≠ TotalEntries ({r.TotalEntries:N0})");

            var sample = new List<Dictionary<string, object?>>();
            const int want = 200;
            foreach (var k in shards)
            {
                try
                {
                    foreach (var (hex, type, det) in r.EnumerateShard(k))
                    {
                        sample.Add(new Dictionary<string, object?> { ["hash"] = hex, ["type"] = type, ["det"] = det });
                        if (sample.Count >= want) break;
                    }
                }
                catch (Exception ex) { errors.Add($"shard 0x{k:X2} dekompresja: {ex.Message}"); }
                if (sample.Count >= want) break;
            }
            res["sample"] = sample;

            if (query.Length == 32 || query.Length == 64)
            {
                string? det = r.TryFind(query.Length == 32 ? query : null, query.Length == 64 ? query : null);
                res["lookup"] = new Dictionary<string, object?>
                {
                    ["query"] = query, ["found"] = det != null, ["detection"] = det,
                };
            }
            else if (query.Length > 0)
            {
                res["lookup"] = new Dictionary<string, object?>
                {
                    ["query"] = query, ["error"] = "hash musi mieć 32 (MD5) lub 64 (SHA-256) znaki hex",
                };
            }
        }
        catch (Exception ex) { res["magicOk"] = false; errors.Add("VdebReader: " + ex.Message); }
        res["errors"] = errors;
        return res;
    }

    private static readonly EnumerationOptions _scanOpts = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.Device
                         | FileAttributes.ReparsePoint,
    };

    private sealed record CliOptions(string Target, Verbosity Verbosity, string? ReportPath, bool Realtime,
                                     string? Profile = null, string? PlanFile = null);

    private static List<string> SafeList(string root, EnumerationOptions opts, CancellationToken ct = default)
    {
        var result = new List<string>();
        try
        {
            foreach (var f in Directory.EnumerateFiles(root, "*", opts))
            {
                if (ct.IsCancellationRequested) break;
                result.Add(f);
            }
        }
        catch {  }
        return result;
    }

    private static CliOptions? ParseScanArgs(string[] args)
    {
        Verbosity verb = Verbosity.Normal;
        string? reportPath = null;
        string? target = null;
        bool realtime = false;
        string? profile = null, planFile = null;

        for (int i = 1; i < args.Length; i++)
        {
            var a = args[i];
            switch (a.ToLowerInvariant())
            {
                case "-silent":
                case "-s":
                    verb = Verbosity.Silent;
                    break;
                case "--profile":

                    if (i + 1 < args.Length) profile = args[++i];
                    break;
                case "--plan":

                    if (i + 1 < args.Length) planFile = args[++i];
                    break;
                case "--realtime":
                case "-rt":

                    realtime = true;
                    break;
                case "-verysilent":
                case "-vs":
                    verb = Verbosity.VerySilent;
                    break;
                case "-raport":
                case "-r":

                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        reportPath = args[++i];
                    }
                    else
                    {
                        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                        reportPath = Path.Combine(desktop,
                            $"malward-report-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
                    }
                    break;
                default:
                    if (target == null) target = a;
                    break;
            }
        }

        if (string.IsNullOrEmpty(target) && profile == null && planFile == null) return null;
        return new CliOptions(target ?? "", verb, reportPath, realtime, profile, planFile);
    }

    private static bool CoveredByFolderTargets(Core.ScanPlan plan, string dir)
    {
        var d = dir.TrimEnd(Path.DirectorySeparatorChar);
        foreach (var t in plan.Folders)
        {
            if (t.Extensions.Length != 0) continue;
            var root = t.Path.TrimEnd(Path.DirectorySeparatorChar);
            if (root.Length == 0) continue;
            if (d.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;
            if (d.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    internal static int CmdScan(string[] args, Settings settings, CancellationToken external = default)
    {
        var opts = ParseScanArgs(args);
        if (opts == null)
            return PrintUsageWithError("scan: missing path");

        bool showStatus = opts.Verbosity != Verbosity.Silent;
        bool showLogs   = opts.Verbosity == Verbosity.Normal;
        bool machine    = Environment.GetEnvironmentVariable("MALWARD_MACHINE_OUTPUT") == "1";

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(external);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        using var status = showStatus ? new StatusBar() : null;
        using var pipe = new ScanPipeline(settings) { Status = status };

        ServerClient? cloudForRepairer = null;
        try { if (settings.CloudScanEnabled) cloudForRepairer = new ServerClient(settings); }
        catch {  }
        var repairer = new Repairer(settings, cloudForRepairer);

        var stats = new ScanStats();
        string target = opts.Target;
        bool canceled = false;

        ScanPlan plan;
        if (!string.IsNullOrEmpty(opts.PlanFile) && File.Exists(opts.PlanFile))
            plan = ScanPlan.FromJson(File.ReadAllText(opts.PlanFile)) ?? ScanPlan.SingleTarget(target);
        else if (!string.IsNullOrEmpty(opts.Profile))
            plan = opts.Profile!.Equals("full", StringComparison.OrdinalIgnoreCase) ? ScanPlan.Full()
                 : opts.Profile!.Equals("quick", StringComparison.OrdinalIgnoreCase) ? ScanPlan.Quick()
                 : ScanPlan.SingleTarget(target);
        else
            plan = ScanPlan.SingleTarget(target);

        if (plan.IsEmpty && !File.Exists(target))
            return PrintUsageWithError("scan: the plan covers nothing — select at least one item");

        if (machine)
        {
            Console.WriteLine($"SCANPLAN	name={Esc(plan.Name)}	stages={Esc(string.Join(",", plan.ActiveStageNames()))}" +
                              $"	folders={plan.Folders.Count}");

            foreach (var f in plan.Folders)
                Console.WriteLine($"SCANFOLDER	path={Esc(f.Path)}" +
                                  $"	ext={Esc(f.Extensions.Length == 0 ? "*" : string.Join(",", f.Extensions))}");
        }
        if (showLogs)
        {
            Console.WriteLine($"[+] Plan skanowania: {plan.Name} — etapy: {string.Join(", ", plan.ActiveStageNames())}, " +
                              $"foldery: {plan.Folders.Count}");
            foreach (var f in plan.Folders) Console.WriteLine($"      • {f.Path}");
        }

        bool systemWideScan = !plan.IsEmpty;

        if (showStatus)
            status!.SetStagePlan(new (string, double)[]
            {
                ("memory",   plan.Memory   ? 5  : 0),
                ("rootkit",  plan.Rootkit  ? 3  : 0),
                ("drivers",  plan.Drivers  ? 2  : 0),
                ("tasks",    plan.Tasks    ? 5  : 0),
                ("registry", plan.Registry ? 10 : 0),
                ("files",    plan.Folders.Count > 0 || File.Exists(target) ? 75 : 0),
            });

        try
        {
            if (!plan.Memory) throw new OperationCanceledException();
            if (showStatus) status!.BeginStage("memory");
            var procScanner = new Memory.ProcessScanner(settings);
            int memHits = 0, memChecked = 0;
            foreach (var r in procScanner.ScanRunningProcesses(pipe, status))
            {
                if (cts.IsCancellationRequested) break;
                memChecked++;
                stats.RecordResult(r);
                if (r.Verdict != Verdict.Malware) continue;
                memHits++;
                RepairOutcome mrep;
                lock (repairer) { mrep = repairer.Repair(r); }
                if (showLogs) Console.WriteLine($"[!] PAMIĘĆ: {r.Path} ({r.Detection})");
                if (machine)
                    Console.WriteLine($"DETECTION	path={Esc(r.Path)}	det={Esc(r.Detection ?? "")}" +
                                      $"	source={Esc(r.Source ?? "")}	action={Esc(mrep.Action)}	entry=" +
                                      $"	display={Esc("Proces: " + Path.GetFileName(r.Path))}");
            }
            if (showStatus) status!.CompleteStage();
            if (machine) Console.WriteLine($"STAGE	name=memory	checked={memChecked}	findings={memHits}");
            if (showLogs) Console.WriteLine($"[+] Pamięć: sprawdzono {memChecked} procesów, zagrożeń: {memHits}");
        }
        catch (OperationCanceledException) {  }
        catch (Exception ex) { Console.Error.WriteLine($"[!] memory: {ex.Message}"); }

        try
        {
            if (!plan.Rootkit) throw new OperationCanceledException();
            if (showStatus) status!.BeginStage("rootkit", 1);
            var rk = RootkitScanner.Scan();
            foreach (var f in rk)
            {
                if (showLogs) Console.WriteLine($"[!] ROOTKIT: {f.Description}");
                if (machine)
                    Console.WriteLine($"ROOTKIT\tkind={Esc(f.Kind)}\tpid={f.Pid}" +
                                      $"\tpath={Esc(f.ImagePath)}\tdesc={Esc(f.Description)}");
            }
            if (rk.Count == 0 && showLogs) Console.WriteLine("[+] Anti-rootkit: brak ukrytych procesów.");

            var procMq = RootkitScanner.ScanProcessMasquerades();
            foreach (var h in procMq)
            {
                if (showLogs) Console.WriteLine($"[!] PROCES: {h.Reason}");
                if (machine)
                    Console.WriteLine($"DETECTION	path={Esc(h.Image)}	det={Esc(h.Detection)}" +
                                      $"	source=Process	action=report	entry=	display={Esc("Proces PID " + h.Pid + ": " + Path.GetFileName(h.Image))}");
            }

            if (showStatus) status!.CompleteStage();
            if (machine) Console.WriteLine($"STAGE	name=rootkit	findings={rk.Count + procMq.Count}");
        }
        catch (OperationCanceledException) {  }
        catch (Exception ex) { Console.Error.WriteLine($"[!] anti-rootkit: {ex.Message}"); }

        try
        {
            if (!plan.Registry && !plan.Tasks) throw new OperationCanceledException();
            if (showStatus) status!.BeginStage("registry");
            var regItems = RegistryScanner.Collect();
            if (showStatus) status!.SetTotal(regItems.Count);
            int regHits = 0;

            var regFailures = new List<(string Location, string Reason)>();
            const string TAB = "\t";
            foreach (var item in regItems)
            {
                if (cts.IsCancellationRequested) break;
                if (showStatus) status!.Step(item.Location);
                var rr = pipe.Scan(item.FilePath);
                stats.RecordResult(rr);

                var shape = rr.Verdict == Verdict.Malware ? null : RegistryScanner.ClassifyPersistence(item);

                if (rr.Verdict != Verdict.Malware && shape == null) continue;

                if (rr.Verdict != Verdict.Malware) stats.RecordThreatOnly();

                regHits++;
                var det = rr.Verdict == Verdict.Malware ? (rr.Detection ?? "") : shape!.Detection;
                var src = rr.Verdict == Verdict.Malware ? (rr.Source ?? "") : "Registry:heuristic";
                var effective = rr.Verdict == Verdict.Malware
                    ? rr
                    : rr with { Verdict = Verdict.Malware, Detection = det, Source = src };
                RepairOutcome rep;
                lock (repairer) { rep = repairer.Repair(effective); }

                var regRem = Repair.RegistryRepair.Remove(item.Location);
                if (!regRem.Ok)
                {
                    regFailures.Add((item.Location, regRem.Error ?? "nieznany błąd"));
                    if (machine)
                        Console.WriteLine($"REGFAIL{TAB}location={Esc(item.Location)}{TAB}reason={Esc(regRem.Error ?? "")}");
                }

                if (showLogs)
                    Console.WriteLine($"[!] REJESTR: {item.Location} -> {item.FilePath} ({det})");
                if (machine)
                    Console.WriteLine($"DETECTION	path={Esc(item.FilePath)}	det={Esc(det)}" +
                                      $"	source={Esc(src)}	action={Esc(rep.Action)}	entry=" +
                                      $"	display={Esc(item.Location + " -> " + Path.GetFileName(item.FilePath))}");
            }

            var loadPoints = RegistryLoadPoints.Collect();
            foreach (var lp in loadPoints)
            {
                if (cts.IsCancellationRequested) break;
                if (showStatus) status!.State("rejestr", lp.Location);
                var lr = pipe.Scan(lp.FilePath);
                stats.RecordResult(lr);

                var lshape = lr.Verdict == Verdict.Malware ? null : Masquerade.CheckFile(lp.FilePath, verifySignature: true);
                if (lr.Verdict != Verdict.Malware && lshape == null) continue;

                regHits++;
                var ldet = lr.Verdict == Verdict.Malware ? (lr.Detection ?? "") : lshape!.Detection;
                var lsrc = lr.Verdict == Verdict.Malware ? (lr.Source ?? "") : "Registry:heuristic";
                var leffective = lr.Verdict == Verdict.Malware
                    ? lr
                    : lr with { Verdict = Verdict.Malware, Detection = ldet, Source = lsrc };
                RepairOutcome lrep;
                lock (repairer) { lrep = repairer.Repair(leffective); }
                if (showLogs)
                    Console.WriteLine($"[!] REJESTR ({lp.Kind}): {lp.Location} -> {lp.FilePath} ({ldet})");
                if (machine)
                    Console.WriteLine($"DETECTION	path={Esc(lp.FilePath)}	det={Esc(ldet)}" +
                                      $"	source={Esc(lsrc)}	action={Esc(lrep.Action)}	entry=" +
                                      $"	display={Esc(lp.Location + " -> " + Path.GetFileName(lp.FilePath))}");
            }

            foreach (var ind in RegistryScanner.CollectIndicators())
            {
                if (ind.Artifact)
                {
                    regHits++;

                    string act = "report";
                    stats.RecordThreatOnly();
                    if (settings.RepairMode != 0)
                    {
                        var rem = Repair.RegistryRepair.Remove(ind.Location);
                        act = rem.Ok ? "registry-removed" : "failed";
                        if (!rem.Ok)
                        {
                            regFailures.Add((ind.Location, rem.Error ?? "nieznany błąd"));
                            if (machine)
                                Console.WriteLine($"REGFAIL{TAB}location={Esc(ind.Location)}{TAB}reason={Esc(rem.Error ?? "")}");
                        }
                    }
                    if (showLogs) Console.WriteLine($"[!] REJESTR: {ind.Detail} ({ind.Location})");
                    if (machine)
                        Console.WriteLine($"DETECTION	path={Esc(ind.Location)}	det={Esc(ind.Detection)}" +
                                          $"	source=Registry	action={Esc(act)}	entry=	display={Esc(ind.Detail)}");
                }
                else
                {
                    if (showLogs) Console.WriteLine($"[i] USTAWIENIE: {ind.Detail} ({ind.Location})");
                    if (machine)
                        Console.WriteLine($"SYSSETTING	id={Esc(ind.Detection)}	location={Esc(ind.Location)}" +
                                          $"	desc={Esc(ind.Detail)}");
                }
            }

            if (showLogs)
                Console.WriteLine($"[+] Rejestr: sprawdzono {regItems.Count + loadPoints.Count} wpisów, zagrożeń: {regHits}");
            if (machine)
                Console.WriteLine($"STAGE	name=registry	checked={regItems.Count + loadPoints.Count}	findings={regHits}	failed={regFailures.Count}");
            if (showLogs && regFailures.Count > 0)
            {
                Console.WriteLine($"[!] Nie udało się usunąć {regFailures.Count} wpisów rejestru:");
                foreach (var (loc, why) in regFailures) Console.WriteLine($"    {loc} — {why}");
            }
        }
        catch (OperationCanceledException) {  }
        catch (Exception ex) { Console.Error.WriteLine($"[!] registry: {ex.Message}"); }

        try
        {
            if (!plan.Registry) throw new OperationCanceledException();

            var damageRoots = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                var bin = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                if (Directory.Exists(bin)) damageRoots.Add(bin);
            }
            var ownDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            if (Directory.Exists(ownDir) && !CoveredByFolderTargets(plan, ownDir))
                damageRoots.Add(ownDir);

            var damageOpts = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            };

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (cts.IsCancellationRequested) break;
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                IEnumerable<string> dirs;
                try { dirs = Directory.EnumerateDirectories(drive.RootDirectory.FullName, "*",
                        new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }); }
                catch { continue; }
                foreach (var d in dirs)
                {
                    if (Masquerade.CheckFolder(d, out var freason))
                    {
                        if (showLogs) Console.WriteLine($"[!] FOLDER: {freason}");
                        if (machine)
                            Console.WriteLine($"DETECTION	path={Esc(d)}	det={Core.DetectionNames.ForText(d)}" +
                                              $"	source=Folder	action=report	entry=	display={Esc("Folder: " + d)}");
                    }
                }
            }

            int dmgChecked = 0, dmgHits = 0;
            foreach (var root in damageRoots)
            {
                if (cts.IsCancellationRequested) break;
                if (showStatus) status!.State("obszary poinfekcyjne", root);
                IEnumerable<string> dfiles;
                try { dfiles = Directory.EnumerateFiles(root, "*", damageOpts); }
                catch { continue; }

                foreach (var f in dfiles)
                {
                    if (cts.IsCancellationRequested) break;
                    dmgChecked++;
                    var dr = pipe.Scan(f);
                    stats.RecordResult(dr);
                    if (dr.Verdict != Verdict.Malware) continue;

                    dmgHits++;
                    RepairOutcome drep;
                    lock (repairer) { drep = repairer.Repair(dr); }
                    bool inBin = f.Contains("$Recycle.Bin", StringComparison.OrdinalIgnoreCase);
                    string where = inBin ? "Kosz" : "Katalog programu";
                    if (showLogs)
                        Console.WriteLine($"[!] {where}: {f} ({dr.Detection})");
                    if (machine)
                        Console.WriteLine($"DETECTION	path={Esc(f)}	det={Esc(dr.Detection ?? "")}" +
                                          $"	source={Esc(dr.Source ?? "")}	action={Esc(drep.Action)}	entry=" +
                                          $"	display={Esc(where + ": " + Path.GetFileName(f))}");
                }
            }
            if (showLogs)
                Console.WriteLine($"[+] Obszary poinfekcyjne: sprawdzono {dmgChecked}, zagrożeń: {dmgHits}");
            if (machine)
                Console.WriteLine($"STAGE	name=damage	checked={dmgChecked}	findings={dmgHits}");
        }
        catch (OperationCanceledException) {  }
        catch (Exception ex) { Console.Error.WriteLine($"[!] post-infection areas: {ex.Message}"); }

        try
        {
            if (!plan.Drivers) throw new OperationCanceledException();
            var drvDir = ScanPlan.DriversDir;
            if (Directory.Exists(drvDir))
            {
                if (showStatus) status!.BeginStage("drivers", 0);
                var drvFiles = SafeList(drvDir, _scanOpts, cts.Token);
                if (showStatus) status!.SetTotal(drvFiles.Count);
                int drvHits = 0;
                foreach (var f in drvFiles)
                {
                    if (cts.IsCancellationRequested) break;
                    if (showStatus) status!.Step(f);
                    var dr = pipe.Scan(f);
                    stats.RecordResult(dr);
                    if (dr.Verdict != Verdict.Malware) continue;
                    drvHits++;
                    RepairOutcome drep;
                    lock (repairer) { drep = repairer.Repair(dr); }
                    if (showLogs) Console.WriteLine($"[!] STEROWNIK: {f} ({dr.Detection})");
                    if (machine)
                        Console.WriteLine($"DETECTION	path={Esc(f)}	det={Esc(dr.Detection ?? "")}" +
                                          $"	source={Esc(dr.Source ?? "")}	action={Esc(drep.Action)}	entry=" +
                                          $"	display={Esc("Sterownik: " + Path.GetFileName(f))}");
                }
                if (machine)
                    Console.WriteLine($"STAGE	name=drivers	checked={drvFiles.Count}	findings={drvHits}");
                if (showLogs)
                    Console.WriteLine($"[+] Sterowniki: sprawdzono {drvFiles.Count}, zagrożeń: {drvHits}");
            }
        }
        catch (OperationCanceledException) {  }
        catch (Exception ex) { Console.Error.WriteLine($"[!] drivers: {ex.Message}"); }

        try
        {
            var planFolders = plan.Folders.Count > 0
                ? plan.Folders
                : (Directory.Exists(target)
                    ? new List<ScanPlan.FolderTarget> { new(target, Array.Empty<string>()) }
                    : new List<ScanPlan.FolderTarget>());

            if (planFolders.Count > 0)
            {
                if (showStatus) status!.BeginStage("files");
                var files = new List<string>();
                var seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var folder in planFolders)
                {
                    if (cts.IsCancellationRequested) break;
                    if (showStatus) status!.State("listing files", folder.Path);
                    foreach (var f in SafeList(folder.Path, _scanOpts, cts.Token))
                    {
                        if (!folder.Matches(f)) continue;

                        if (seenFiles.Add(f)) files.Add(f);
                    }
                }
                if (showStatus) status!.SetTotal(files.Count);

                int cpuLimit = settings.ScanCpuLimitPercent;
                var cpuEnv = Environment.GetEnvironmentVariable("MALWARD_SCAN_CPU_PERCENT");
                if (!string.IsNullOrEmpty(cpuEnv) && int.TryParse(cpuEnv, out var cpuVal))
                    cpuLimit = cpuVal;
                var governor = new Util.CpuGovernor(cpuLimit <= 0 ? 100 : cpuLimit);
                if (governor.Active)
                {
                    try
                    {
                        System.Diagnostics.Process.GetCurrentProcess().PriorityClass =
                            System.Diagnostics.ProcessPriorityClass.BelowNormal;
                    }
                    catch { }
                }

                int threads = settings.ScanMaxParallelism;
                var threadsEnv = Environment.GetEnvironmentVariable("MALWARD_SCAN_PARALLELISM");
                if (!string.IsNullOrEmpty(threadsEnv) && int.TryParse(threadsEnv, out var threadsVal))
                    threads = threadsVal;
                if (threads <= 0) threads = governor.SuggestedThreads;

                if (showLogs)
                    Console.WriteLine($"[+] Files stage: {threads} thread(s), CPU budget {(governor.Active ? cpuLimit + "%" : "unlimited")}.");

                var po = new ParallelOptions {
                    MaxDegreeOfParallelism = threads,
                    CancellationToken = cts.Token,
                };

                try
                {
                    Parallel.ForEach(files, po, f =>
                    {
                        if (cts.IsCancellationRequested) return;

                        if (Thread.CurrentThread.Priority != ThreadPriority.BelowNormal)
                            try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }
                        governor.Throttle();

                        if (showStatus) status!.Step(f);
                        DetectionResult r;
                        try { r = pipe.Scan(f); }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                        {
                            stats.RecordBlocked();
                            if (showLogs) status?.LogError($"BLOCKED  {f}: {ex.Message}");
                            return;
                        }
                        catch (OperationCanceledException) { return; }
                        catch (Exception ex)
                        {
                            stats.RecordBlocked();
                            if (showLogs) status?.LogError($"ERR      {f}: {ex.Message}");
                            return;
                        }

                        stats.RecordResult(r);

                        if (r.Verdict == Verdict.Malware)
                        {
                            string displayTarget = string.IsNullOrEmpty(r.ArchiveEntry)
                                ? r.Path
                                : $"{Path.GetFileName(r.Path)} @ {r.ArchiveEntry.Replace("|", ", ")}";
                            if (showStatus) status!.State("threat found — repair", displayTarget);
                            RepairOutcome rep;
                            lock (repairer) { rep = repairer.Repair(r); }
                            PrintResult(status, r, rep, showLogs);

                            if (machine)
                            {
                                if (r.ArchiveFindings is { Count: > 0 } afs)
                                {
                                    foreach (var af in afs)
                                        Console.WriteLine($"DETECTION\tpath={Esc(r.Path)}\tdet={Esc(af.Detection)}\tsource={Esc(af.Source)}\taction={Esc(rep.Action)}\tentry={Esc(af.Entry)}\tdisplay={Esc(af.Display)}");
                                }
                                else
                                {
                                    Console.WriteLine($"DETECTION\tpath={Esc(r.Path)}\tdet={Esc(r.Detection ?? "")}\tsource={Esc(r.Source ?? "")}\taction={Esc(rep.Action)}\tentry={Esc(r.ArchiveEntry ?? "")}");
                                }
                            }
                        }
                        else if (r.Verdict == Verdict.Clean) {  }
                        else
                        {
                            if (showLogs) PrintResult(status, r, null, true);

                            if (machine)
                            {
                                string category = ClassifySkip(r);
                                Console.WriteLine($"SKIP\tpath={Esc(r.Path)}\tcategory={category}\tsource={Esc(r.Source ?? "")}\treason={Esc(r.Error ?? "")}");
                            }
                        }
                    });
                }
                catch (OperationCanceledException) { canceled = true; }

                if (showStatus && !canceled) status!.ForceFinalRender();
                if (showStatus) status!.Clear();
            }
            else if (File.Exists(target))
            {
                if (showStatus) { status!.SetTotal(1); status!.Step(target); }

                var r = opts.Realtime ? pipe.ScanRealtime(target) : pipe.Scan(target);
                stats.RecordResult(r);
                if (r.Verdict == Verdict.Malware)
                {
                    string displayTarget = string.IsNullOrEmpty(r.ArchiveEntry)
                        ? r.Path
                        : $"{Path.GetFileName(r.Path)} @ {r.ArchiveEntry.Replace("|", ", ")}";
                    if (showStatus) status!.State("threat found — repair", displayTarget);
                    var rep = repairer.Repair(r);
                    PrintResult(status, r, rep, showLogs);
                    if (machine)
                        Console.WriteLine($"DETECTION\tpath={Esc(r.Path)}\tdet={Esc(r.Detection ?? "")}\tsource={Esc(r.Source ?? "")}\taction={Esc(rep.Action)}\tentry={Esc(r.ArchiveEntry ?? "")}");
                }
                else
                {
                    PrintResult(status, r, null, showLogs);
                    if (machine && r.Verdict != Verdict.Clean)
                    {
                        string category = ClassifySkip(r);
                        Console.WriteLine($"SKIP\tpath={Esc(r.Path)}\tcategory={category}\tsource={Esc(r.Source ?? "")}\treason={Esc(r.Error ?? "")}");
                    }
                }
                if (showStatus) status!.Clear();
            }
            else
            {
                Console.Error.WriteLine($"[!] Does not exist: {target}");
                cloudForRepairer?.Dispose();
                if (machine) EmitSummaryJson(stats, target, canceled: false);
                return 3;
            }
        }
        catch (OperationCanceledException) { canceled = true; }
        finally
        {
            cloudForRepairer?.Dispose();

            if (machine) EmitSummaryJson(stats, target, canceled, plan.Folders.Select(f => f.Path).ToList());
        }

        var report = stats.BuildReport(target, plan.Folders.Select(f => f.Path).ToList());
        if (opts.Verbosity != Verbosity.Silent) Console.WriteLine();
        if (opts.Verbosity != Verbosity.Silent) Console.WriteLine(report);

        if (!string.IsNullOrEmpty(opts.ReportPath))
        {
            try
            {
                File.WriteAllText(opts.ReportPath, report);
                if (opts.Verbosity != Verbosity.Silent)
                    Console.WriteLine($"[+] Raport zapisany: {opts.ReportPath}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Failed to write report: {ex.Message}");
            }
        }

        return Volatile.Read(ref stats.Threats) > 0 ? 2 : 0;
    }

    private static string Esc(string s) =>
        (s ?? "").Replace("\t", " ").Replace("\n", " ").Replace("\r", " ");

    private static string ClassifySkip(DetectionResult r)
    {
        if (r.Source != null && r.Source.StartsWith("System:", StringComparison.Ordinal))
            return "system";

        if (r.Source == "Microsoft/System" || r.Source == "Whitelist")
            return "system";
        if (r.Error != null)
        {
            if (r.Error.Contains("password", StringComparison.OrdinalIgnoreCase)
             || r.Error.Contains("encrypt", StringComparison.OrdinalIgnoreCase))
                return "encrypted";
            if (r.Error.Contains("Access", StringComparison.OrdinalIgnoreCase)
             || r.Error.Contains("denied", StringComparison.OrdinalIgnoreCase)
             || r.Error.Contains("blocked", StringComparison.OrdinalIgnoreCase)
             || r.Error.Contains("locked", StringComparison.OrdinalIgnoreCase))
                return "blocked";
        }
        return "skipped";
    }

    private static void EmitSummaryJson(ScanStats s, string target, bool canceled,
                                        IReadOnlyList<string>? folders = null)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            target,
            folders = folders is { Count: > 0 } ? folders : null,
            canceled,
            filesTotal = Volatile.Read(ref s.FilesTotal),
            threats    = Volatile.Read(ref s.Threats),
            blocked    = Volatile.Read(ref s.Blocked),
            safe       = Volatile.Read(ref s.Safe),
            cloud      = Volatile.Read(ref s.Cloud),
            system     = Volatile.Read(ref s.System),
            skipped    = Volatile.Read(ref s.Skipped),
            encrypted  = Volatile.Read(ref s.Encrypted),
            bytes      = Volatile.Read(ref s.BytesScanned),
            elapsedSec = (int)s.Elapsed.TotalSeconds,
        });
        Console.Out.WriteLine($"SUMMARY\t{json}");
        Console.Out.Flush();
    }

    internal static int CmdScanMemory(string[] args, Settings settings, CancellationToken external = default)
    {
        if (!settings.MemoryScan)
            Console.WriteLine("[*] memory_scan=false in settings.json (kontynuujemy mimo to)");

        bool machine = Environment.GetEnvironmentVariable("MALWARD_MACHINE_OUTPUT") == "1";

        using var status = new StatusBar();
        using var pipe = new ScanPipeline(settings) { Status = status };
        ServerClient? cloudForRepairer = null;
        try { if (settings.CloudScanEnabled) cloudForRepairer = new ServerClient(settings); } catch { }
        var repairer = new Repairer(settings, cloudForRepairer);
        var ms = new ProcessScanner(settings);
        var au = new AutostartScanner(settings);
        var stats = new ScanStats();

        foreach (var r in ms.ScanRunningProcesses(pipe, status))
        {
            stats.RecordResult(r);
            if (r.Verdict == Verdict.Malware)
            {
                var rep = repairer.Repair(r);
                PrintResult(status, r, rep, true);
                if (machine)
                    Console.WriteLine($"DETECTION\tpath={Esc(r.Path)}\tdet={Esc(r.Detection ?? "")}\tsource={Esc(r.Source ?? "")}\taction={Esc(rep.Action)}\tentry=");
            }
            else
            {
                if (r.Verdict == Verdict.Error || r.Detection != null)
                    PrintResult(status, r, null, true);
                if (machine && r.Verdict != Verdict.Clean)
                {
                    string category = ClassifySkip(r);
                    Console.WriteLine($"SKIP\tpath={Esc(r.Path)}\tcategory={category}\tsource={Esc(r.Source ?? "")}\treason={Esc(r.Error ?? "")}");
                }
            }
        }

        foreach (var r in au.ScanAutostart(pipe))
        {
            stats.RecordResult(r);
            if (r.Verdict == Verdict.Malware)
            {
                var rep = repairer.Repair(r);
                PrintResult(status, r, rep, true);
                if (machine)
                    Console.WriteLine($"DETECTION\tpath={Esc(r.Path)}\tdet={Esc(r.Detection ?? "")}\tsource={Esc(r.Source ?? "")}\taction={Esc(rep.Action)}\tentry=");
            }
            else
            {
                if (r.Verdict == Verdict.Error || r.Detection != null)
                    PrintResult(status, r, null, true);
                if (machine && r.Verdict != Verdict.Clean)
                {
                    string category = ClassifySkip(r);
                    Console.WriteLine($"SKIP\tpath={Esc(r.Path)}\tcategory={category}\tsource={Esc(r.Source ?? "")}\treason={Esc(r.Error ?? "")}");
                }
            }
        }

        status.Clear();
        Console.WriteLine();
        Console.WriteLine(stats.BuildReport("[memory + autostart scan]"));

        if (machine) EmitSummaryJson(stats, "[memory]", canceled: false);

        cloudForRepairer?.Dispose();
        return Volatile.Read(ref stats.Threats) > 0 ? 2 : 0;
    }

    private static int CmdAnalyze(string[] args, Settings settings)
    {
        if (args.Length < 2)
            return PrintUsageWithError("analyze: missing quarantine-id (GUID)");
        if (!Guid.TryParse(args[1], out var id))
            return PrintUsageWithError("analyze: invalid GUID");

        var store = new QuarantineStore();
        var decrypted = store.DecryptPayload(id);
        if (decrypted == null)
        {
            Console.Error.WriteLine("[!] Cannot read quarantine payload");
            Console.WriteLine("ANALYZE-VERDICT:error:decrypt-failed");
            return 7;
        }
        var (entry, plainBytes) = decrypted.Value;

        if (entry.Detection?.StartsWith("Heur.", StringComparison.OrdinalIgnoreCase) == true)
        {
            Console.Error.WriteLine("[!] Heuristic detection — cloud re-analysis not available");
            Console.WriteLine("ANALYZE-VERDICT:error:heuristic-not-supported");
            return 7;
        }
        if (!settings.CloudScanEnabled)
        {
            Console.Error.WriteLine("[!] Cloud scan disabled in settings");
            Console.WriteLine("ANALYZE-VERDICT:error:cloud-disabled");
            return 7;
        }

        var analyzeDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "analyze");
        Directory.CreateDirectory(analyzeDir);
        var ext = Path.GetExtension(entry.OriginalPath);
        var tmp = Path.Combine(analyzeDir, $"malward-analyze-{id:N}{ext}");
        try
        {
            File.WriteAllBytes(tmp, plainBytes);

            Console.WriteLine("ANALYZE-PHASE:upload");
            using var cloud = new ServerClient(settings);

            Console.WriteLine("ANALYZE-PHASE:scanning");
            var scan = cloud.ScanFileAsync(tmp, settings.ScanLevel).GetAwaiter().GetResult();

            Console.WriteLine("ANALYZE-PHASE:done");

            if (scan.Verdict == "malware")
            {
                Console.WriteLine($"ANALYZE-VERDICT:malware:{scan.Name}");
                return 2;
            }

            if (scan.Verdict == "clean")
            {
                var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(plainBytes))
                                  .ToLowerInvariant();

                Console.WriteLine("ANALYZE-VERDICT:clean");
                return 0;
            }

            Console.WriteLine($"ANALYZE-VERDICT:error:scan-inconclusive:{scan.Verdict}");
            return 6;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] analyze failed: {ex.Message}");
            Console.WriteLine($"ANALYZE-VERDICT:error:{ex.Message}");
            return 6;
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    private static int CmdAnalyzeFile(string[] args, Settings settings)
    {
        if (args.Length < 2)
            return PrintUsageWithError("analyze-file: missing path");
        var path = args[1];
        if (!File.Exists(path))
        {
            Console.WriteLine("ANALYZE-VERDICT:error:file-not-found");
            return 7;
        }
        if (!settings.CloudScanEnabled)
        {
            Console.WriteLine("ANALYZE-VERDICT:error:cloud-disabled");
            return 7;
        }

        try
        {
            Console.WriteLine("ANALYZE-PHASE:upload");
            using var cloud = new ServerClient(settings);
            Console.WriteLine("ANALYZE-PHASE:scanning");

            var vt = new ServerClient.VirusTotalOptions(
                Enabled: Environment.GetEnvironmentVariable("MALWARD_VT") != "0",
                ApiKey: Environment.GetEnvironmentVariable("MALWARD_VT_KEY"),
                GreaterThan: int.TryParse(Environment.GetEnvironmentVariable("MALWARD_VT_GT"), out var gt) ? gt : -1);

            var scan = cloud.ScanFileAsync(path, settings.ScanLevel, vt, default,
                    (sent, total) => Console.WriteLine($"ANALYZE-PROGRESS:{sent}/{total}"),
                    unlimited: true)
                .GetAwaiter().GetResult();
            Console.WriteLine("ANALYZE-PHASE:done");
            if (!string.IsNullOrEmpty(scan.Label)) Console.WriteLine($"ANALYZE-LABEL:{scan.Label}");
            if (scan.VtTotal is > 0) Console.WriteLine($"ANALYZE-VT:{scan.VtDetected ?? 0}/{scan.VtTotal}");

            if (scan.Verdict == "malware")
            {
                Console.WriteLine($"ANALYZE-VERDICT:malware:{scan.Name}");
                return 2;
            }

            if (scan.Verdict == "clean")
            {
                Console.WriteLine("ANALYZE-VERDICT:clean");
                return 0;
            }

            Console.WriteLine($"ANALYZE-VERDICT:error:scan-inconclusive:{scan.Verdict}");
            return 6;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] analyze-file failed: {ex.Message}");
            Console.WriteLine($"ANALYZE-VERDICT:error:{ex.Message}");
            return 6;
        }
    }

    private static int CmdUpdate(string[] args, Settings settings)
    {
        try
        {
            using var svc = new UpdateService(settings);
            int n = svc.UpdateAllAsync().GetAwaiter().GetResult();
            Console.WriteLine($"[*] Update done: {n} file(s) refreshed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] update failed: {ex.Message}");
            return 6;
        }
    }

    private static int CmdFetchSandbox(string[] args, Settings settings)
    {
        if (args.Length < 2)
            return PrintUsageWithError("fetch-sandbox <destPath>");
        string dest = args[1];
        bool machine = Environment.GetEnvironmentVariable("MALWARD_MACHINE_OUTPUT") == "1";
        try
        {
            using var svc = new UpdateService(settings);
            long lastEmit = 0;
            Action<long, long> prog = (done, total) =>
            {
                long now = Environment.TickCount64;
                if (now - lastEmit < 200 && done != total) return;
                lastEmit = now;
                double pct = total > 0 ? (100.0 * done / total) : 0.0;
                if (machine)

                    Console.WriteLine(FormattableString.Invariant($"SBDL\tdone={done}\ttotal={total}\tpct={pct:F1}"));
                else
                    Console.Write($"\r[*] sandbox: {done / (1024 * 1024)} / {(total > 0 ? total / (1024 * 1024) : 0)} MB ({pct:F1}%)   ");
            };
            bool downloaded = svc.FetchSandboxAsync(dest, prog).GetAwaiter().GetResult();
            if (machine) Console.WriteLine($"SBDL\tdone=1\ttotal=1\tpct=100.0");
            Console.WriteLine();
            Console.WriteLine(downloaded ? "[+] sandbox: pobrano." : "[+] sandbox: aktualny.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] fetch-sandbox failed: {ex.Message}");
            if (machine) Console.WriteLine($"SBDL\terror={Esc(ex.Message)}");
            return 6;
        }
    }

    private static int CmdQuarantine(string[] args, Settings settings)
    {
        if (args.Length < 2)
            return PrintUsageWithError("quarantine: missing action (list/restore/extract/export/decrypt/delete)");

        if (args[1].Equals("decrypt", StringComparison.OrdinalIgnoreCase))
            return CmdQuarantineDecrypt(args);

        var store = new QuarantineStore();
        switch (args[1].ToLowerInvariant())
        {
            case "list":
                var items = store.List();
                Console.WriteLine($"[*] Quarantine: {items.Count} entrie(s)");
                foreach (var e in items)
                {
                    var when = DateTimeOffset.FromUnixTimeSeconds((long)e.QuarantinedTs).LocalDateTime;

                    Console.WriteLine($"  {e.Id}  {when:yyyy-MM-dd HH:mm:ss}  {e.Size}  {e.Detection,-40}  {e.OriginalPath}");
                }
                return 0;

            case "restore":
                if (args.Length < 3) return PrintUsageWithError("restore <id> [destPath]");
                if (!Guid.TryParse(args[2], out var rid))
                    return PrintUsageWithError("invalid guid");
                var dest = args.Length >= 4 ? args[3] : null;
                if (store.Restore(rid, dest)) return 0;
                Console.Error.WriteLine("[!] Restore failed.");
                return 7;

            case "extract":

                if (args.Length < 4) return PrintUsageWithError("extract <id> <destDir> [name]");
                if (!Guid.TryParse(args[2], out var eid))
                    return PrintUsageWithError("invalid guid");
                var extracted = store.Extract(eid, args[3], args.Length >= 5 ? args[4] : null);
                if (extracted != null) { Console.WriteLine($"[+] Extracted to: {extracted}"); return 0; }
                Console.Error.WriteLine("[!] Extract failed.");
                return 7;

            case "export":
                {
                    if (args.Length < 4) return PrintUsageWithError("export <id> <destPath>");
                    if (!Guid.TryParse(args[2], out var xid))
                        return PrintUsageWithError("invalid guid");
                    var problem = store.ExportContainer(xid, args[3]);
                    if (problem.Length == 0) { Console.WriteLine($"[+] Exported to: {args[3]}"); return 0; }
                    Console.Error.WriteLine($"[!] Export failed: {problem}");
                    return 7;
                }

            case "delete":
                if (args.Length < 3) return PrintUsageWithError("delete <id>");
                if (!Guid.TryParse(args[2], out var did))
                    return PrintUsageWithError("invalid guid");
                if (store.Delete(did)) { Console.WriteLine("[+] Removed."); return 0; }
                Console.Error.WriteLine("[!] Not found.");
                return 7;

            default:
                return PrintUsageWithError($"unknown quarantine action: {args[1]}");
        }
    }

    private static int CmdQuarantineDecrypt(string[] args)
    {
        if (args.Length < 4) return PrintUsageWithError("decrypt <container.quarantine> <destPath>");
        var src = args[2];
        if (!File.Exists(src))
        {
            Console.Error.WriteLine($"[!] No such file: {src}");
            return 7;
        }
        if (!Malward.ResidentShield.QuarantineCrypto.IsContainer(src))
        {
            Console.Error.WriteLine("[!] Not a Malward quarantine container (no MWQ1 header).");
            return 7;
        }
        if (!Malward.ResidentShield.QuarantineCrypto.DecryptFile(src, args[3]))
        {
            Console.Error.WriteLine("[!] Decryption failed — the container is damaged or was tampered with.");
            return 7;
        }
        Console.WriteLine($"[+] Decrypted to: {args[3]}");
        Console.WriteLine("[!] WARNING: this is the original file, live. Handle it in an isolated environment.");
        return 0;
    }

    private static int CmdVersion()
    {
        var asm = Assembly.GetExecutingAssembly();
        var ver = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                  ?? asm.GetName().Version?.ToString()
                  ?? "?";
        var title = asm.GetCustomAttribute<AssemblyTitleAttribute>()?.Title ?? "Malward(R) Virus Scanner";
        Console.WriteLine($"{title}");
        Console.WriteLine($"  Engine version : {ver}");
        Console.WriteLine($"  Author         : Community Edition");
        Console.WriteLine($"  Creator        : Jakub Michalski");

        var vpsPath = Paths.VpsVdebReadable;
        if (File.Exists(vpsPath))
        {
            try
            {
                using var r = new VdebReader(vpsPath);
                var created = DateTimeOffset.FromUnixTimeSeconds((long)r.CreatedTs).LocalDateTime;
                var lastTs = DateTimeOffset.FromUnixTimeSeconds((long)r.LastTs).LocalDateTime;
                var size = new FileInfo(vpsPath).Length / (1024.0 * 1024.0);
                var mode = r.IsCompact ? $"COMPACT-{r.CompactPrefix}B" : "FULL";
                var sha8 = ComputeSha8(vpsPath);
                Console.WriteLine($"  VPS database   : {r.TotalEntries:N0} entries, {size:F1} MB ({mode})");
                Console.WriteLine($"      built     : {created:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"      last data : {lastTs:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"      sha8      : {sha8}");
                Console.WriteLine($"      path      : {vpsPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  VPS database   : (load error: {ex.Message})");
            }
        }
        else
        {
            Console.WriteLine($"  VPS database   : (not present, run `malscan.exe update`)");
        }

        var heurPath = Paths.HeurVdebReadable;
        if (File.Exists(heurPath))
        {
            try
            {
                using var hr = new HeurReader(heurPath);
                var created = DateTimeOffset.FromUnixTimeSeconds(hr.CreatedTs).LocalDateTime;
                var size = new FileInfo(heurPath).Length / (1024.0 * 1024.0);
                var sha8 = ComputeSha8(heurPath);
                Console.WriteLine($"  Heur database  : {hr.Rules.Count} rule(s), {size:F1} MB (HVDB v{hr.Version})");
                Console.WriteLine($"      built     : {created:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"      sha8      : {sha8}");
                Console.WriteLine($"      path      : {heurPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Heur database  : (load error: {ex.Message})");
            }
        }
        else
        {
            Console.WriteLine($"  Heur database  : (not present)");
        }

        var wlPath = Paths.WhitelistVdebReadable;
        if (File.Exists(wlPath))
        {
            try
            {
                using var wr = new VdebReader(wlPath);
                var size = new FileInfo(wlPath).Length / (1024.0 * 1024.0);
                var sha8 = ComputeSha8(wlPath);
                Console.WriteLine($"  Whitelist DB   : {wr.TotalEntries:N0} entries, {size:F1} MB");
                Console.WriteLine($"      sha8      : {sha8}");
                Console.WriteLine($"      path      : {wlPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Whitelist DB   : (load error: {ex.Message})");
            }
        }
        else
        {
            Console.WriteLine($"  Whitelist DB   : (not present)");
        }

        return 0;
    }

    private static string ComputeSha8(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                1 << 20, FileOptions.SequentialScan);
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
        }
        catch { return "?"; }
    }

    private static void PrintResult(StatusBar? status, DetectionResult r, RepairOutcome? rep, bool showLogs)
    {
        if (!showLogs) return;
        var verd = r.Verdict switch
        {
            Verdict.Malware => "MALWARE",
            Verdict.Clean   => "clean",
            Verdict.Skipped => "skip",
            Verdict.Error   => "ERR",
            _               => "?",
        };
        var det = r.Detection != null ? $" [{r.Detection}]" : "";
        var src = $" ({r.Source})";
        var err = r.Error != null ? $" -- {r.Error}" : "";
        var rs = rep != null ? $"  -> {rep.Action}{(rep.Success ? "(ok)" : "(FAIL)")}" : "";
        var line = $"{verd,-7}{src}{det,-40} {r.Path}{err}{rs}";
        if (status != null)
        {
            if (r.Verdict == Verdict.Error || rs.Contains("FAIL")) status.LogError(line);
            else status.Log(line);
        }
        else
        {
            if (r.Verdict == Verdict.Error || rs.Contains("FAIL")) Console.Error.WriteLine(line);
            else Console.WriteLine(line);
        }
    }

    private static int PrintUsageWithError(string msg)
    {
        Console.Error.WriteLine($"[!] {msg}\n");
        PrintUsage();
        return 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
Malward(R) Virus Scanner — modular antivirus engine

Użycie:
  malscan.exe scan <ścieżka> [-silent|-s] [-verysilent|-vs] [-raport|-r [path]]
                                      Skanuje plik lub katalog (rekursywnie)
  malscan.exe scan-memory             Skanuje pamięć (procesy uruchomione)
  malscan.exe update                  Pobiera vps.vdeb / heur.vdeb / rf-whitelist.vdeb
  malscan.exe quarantine list         Listuje pliki w kwarantannie
  malscan.exe quarantine restore <id> [destPath]   Przywraca plik
  malscan.exe quarantine extract <id> <folder> [nazwa]   Kopiuje odszyfrowany plik
  malscan.exe quarantine export  <id> <cel>        Kontener .quarantine do zgloszenia FP
  malscan.exe quarantine decrypt <kontener> <cel>  Odszyfrowuje samodzielny .quarantine
  malscan.exe quarantine delete  <id>              Usuwa wpis z kwarantanny
  malscan.exe version                 Wersja silnika + bazy VPS/Heur

Tryby logowania (dla `scan`):
  -silent      / -s    bez logów (tylko exit code; brak summary unless -raport)
  -verysilent  / -vs   tylko status bar + summary
  -raport      / -r    zapisz raport tekstowy na pulpicie (lub w podanej ścieżce)

Wymaga uprawnień administratora.
""");
    }
}
