using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class ProgramUpdateService
{
    public const string BaseUrl = "https://jmsoft.pl/downloads/software/Malward/updates/";

    private const string ManifestName = "latest.json";

    private readonly HttpClient _http;
    private readonly string _installDir;
    private readonly string _dataDir;

    public sealed record Release(string Version, string Zip, string? Sha256, long Size, string? Notes,
                                 string? Released, string? MinVersion);

    public sealed record CheckResult(bool Available, string CurrentVersion, Release? Release, string? Error);

    public sealed record Progress(string Phase, long Done, long Total, string Message);

    public ProgramUpdateService(string installDir, string dataDir)
    {
        _installDir = installDir;
        _dataDir = dataDir;

        _http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("Malward/" + CurrentVersion());
    }

    private static void Log(string message)
    {
        System.Diagnostics.Debug.WriteLine(message);
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

    private (bool ok, string why) VerifyStagedSignatures(string root)
    {
        string mySelf = Environment.ProcessPath ?? Path.Combine(_installDir, "Malward.exe");
        if (!Malward.Engine.Util.CodeSignature.IsSignedAtAll(mySelf))
        {
            Log("[update] this build is not signed — skipping the signature check on the package");
            return (true, "");
        }

        string[] binaria =
        {
            "mwupdate.exe", "Malward.exe", "malscan.exe", "mwshield.exe",
            "netmonitor.exe", "bkmonitor.exe", "MalwardCtx.exe",
        };

        int sprawdzone = 0;
        foreach (var nazwa in binaria)
        {
            var sciezka = Path.Combine(root, nazwa);
            if (!File.Exists(sciezka)) continue;
            if (!Malward.Engine.Util.CodeSignature.IsSignedBy(
                    sciezka, Malward.Engine.Util.CodeSignature.ReleaseSubject, out var powod))
            {
                Log($"[update] REJECTED: {powod}");
                return (false, powod);
            }
            sprawdzone++;
        }

        if (sprawdzone == 0)
        {
            Log("[update] REJECTED: no binary in the package could be verified");
            return (false, "W pakiecie nie ma pliku, którego podpis dałoby się sprawdzić.");
        }
        Log($"[update] signatures verified: {sprawdzone} file(s)");
        return (true, "");
    }

    public static string CurrentVersion()
    {
        try
        {
            var asm = System.Reflection.Assembly.GetEntryAssembly();
            var info = asm?.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                          .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault();
            var v = info?.InformationalVersion ?? asm?.GetName().Version?.ToString() ?? "0.0.0";

            int plus = v.IndexOf('+');
            return plus > 0 ? v[..plus] : v;
        }
        catch { return "0.0.0"; }
    }

    public async Task<CheckResult> CheckAsync(CancellationToken ct = default)
    {
        string current = CurrentVersion();
        try
        {
            var url = BaseUrl + ManifestName + "?t=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(30));
            var text = await _http.GetStringAsync(url, cts.Token);

            text = text.TrimStart('﻿', '​').TrimStart();

            JsonObject? o;
            try
            {
                o = JsonNode.Parse(text) as JsonObject;
            }
            catch (System.Text.Json.JsonException ex)
            {
                return new CheckResult(false, current, null,
                    $"{ManifestName} na serwerze nie jest poprawnym plikiem JSON. "
                    + "Nazwy pól i teksty muszą być w cudzysłowach, a po nazwie pola musi stać dwukropek, "
                    + "np. \"version\": \"1.0.1\". Szczegóły: " + ex.Message);
            }
            if (o == null)
                return new CheckResult(false, current, null,
                    $"{ManifestName} na serwerze nie zawiera obiektu JSON z informacją o wersji.");

            var rel = new Release(
                Version:    Str(o, "version"),
                Zip:        Str(o, "zip"),
                Sha256:     o["sha256"]?.GetValue<string>(),
                Size:       Num(o, "size"),
                Notes:      o["notes"]?.GetValue<string>(),
                Released:   o["released"]?.GetValue<string>(),
                MinVersion: o["min_version"]?.GetValue<string>());

            var brak = new List<string>();
            if (rel.Version.Length == 0) brak.Add("version");
            if (rel.Zip.Length == 0)     brak.Add("zip");
            if (brak.Count > 0)
                return new CheckResult(false, current, null,
                    $"{ManifestName} jest niekompletny — brakuje pól: {string.Join(", ", brak)}.");

            if (!string.IsNullOrWhiteSpace(rel.Sha256))
            {
                var h = rel.Sha256.Trim();
                if (h.Length != 64 || !h.All(Uri.IsHexDigit))
                    return new CheckResult(false, current, null,
                        "Pole \"sha256\" w pliku informacji o wersji nie wygląda na sumę SHA-256 "
                        + $"(oczekiwane 64 znaki szesnastkowe, jest {h.Length}).");
            }

            return new CheckResult(IsNewer(rel.Version, current), current, rel, null);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return new CheckResult(false, current, null, null);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return new CheckResult(false, current, null, ex.Message); }
    }

    private static string Str(JsonObject o, string name)
    {
        try
        {
            var n = o[name];
            if (n == null) return "";
            return n.GetValueKind() switch
            {
                System.Text.Json.JsonValueKind.String => n.GetValue<string>().Trim(),
                System.Text.Json.JsonValueKind.Number => n.ToJsonString().Trim(),
                _ => "",
            };
        }
        catch { return ""; }
    }

    private static long Num(JsonObject o, string name)
    {
        try
        {
            var n = o[name];
            if (n == null) return 0;
            return n.GetValueKind() switch
            {
                System.Text.Json.JsonValueKind.Number => n.GetValue<long>(),
                System.Text.Json.JsonValueKind.String => long.TryParse(n.GetValue<string>(), out var v) ? v : 0,
                _ => 0,
            };
        }
        catch { return 0; }
    }

    internal static bool IsNewer(string candidate, string current)
    {
        static int[] Parts(string v)
        {
            var list = new List<int>();
            foreach (var p in (v ?? "").Split('.', '-', '+'))
                if (int.TryParse(p, out var n)) list.Add(n); else break;
            return list.ToArray();
        }
        var a = Parts(candidate);
        var b = Parts(current);
        for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            int x = i < a.Length ? a[i] : 0;
            int y = i < b.Length ? b[i] : 0;
            if (x != y) return x > y;
        }
        return false;
    }

    public string StagingDir => Path.Combine(_dataDir, "update", "staging");

    public bool HasPartialDownload(Release rel)
    {
        try
        {
            var p = Path.Combine(_dataDir, "update", rel.Zip);
            return File.Exists(p) && new FileInfo(p).Length > 0;
        }
        catch { return false; }
    }

    public async Task<(bool ok, string message)> PrepareAsync(Release rel, Action<Progress> progress,
                                                              CancellationToken ct = default)
    {
        var workDir = Path.Combine(_dataDir, "update");
        var zipPath = Path.Combine(workDir, rel.Zip);
        try
        {
            Directory.CreateDirectory(workDir);

            progress(new Progress("download", 0, rel.Size, "Pobieranie aktualizacji…"));
            await DownloadWithRetryAsync(BaseUrl + rel.Zip, zipPath, rel.Size, progress, ct);

            progress(new Progress("verify", 0, 0, "Sprawdzanie pobranego pliku…"));
            if (!string.IsNullOrWhiteSpace(rel.Sha256))
            {
                var actual = await Sha256Async(zipPath, ct);
                if (!string.Equals(actual, rel.Sha256.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    TryDelete(zipPath);
                    return (false, "Suma kontrolna pobranego pliku się nie zgadza — aktualizacja przerwana.");
                }
            }

            progress(new Progress("extract", 0, 0, "Rozpakowywanie…"));
            var staging = StagingDir;
            TryDeleteDir(staging);
            Directory.CreateDirectory(staging);
            ExtractSafely(zipPath, staging);

            var root = FindRoot(staging);
            if (root == null)
            {
                TryDeleteDir(staging);
                return (false, "Archiwum nie zawiera plików programu Malward.");
            }
            if (!File.Exists(Path.Combine(root, "mwupdate.exe")))
            {
                TryDeleteDir(staging);
                return (false, "Archiwum nie zawiera instalatora aktualizacji (mwupdate.exe).");
            }

            progress(new Progress("verify", 0, 0, "Sprawdzanie podpisu aktualizacji…"));
            var (podpisOk, coNieTak) = VerifyStagedSignatures(root);
            if (!podpisOk)
            {
                TryDeleteDir(staging);
                return (false, "Podpis aktualizacji jest nieprawidłowy — instalacja przerwana. " + coNieTak);
            }

            File.WriteAllText(Path.Combine(workDir, "staging-root.txt"), root);

            TryDelete(zipPath);
            progress(new Progress("ready", 0, 0, "Aktualizacja gotowa do zainstalowania."));
            return (true, root);
        }
        catch (OperationCanceledException)
        {
            TryDelete(zipPath);
            TryDeleteDir(StagingDir);
            throw;
        }
        catch (IOException ex)
        {
            return (false, ex.Message);
        }
        catch (Exception ex)
        {
            TryDelete(zipPath);
            return (false, ex.Message);
        }
    }

    private static readonly TimeSpan StallTimeout = TimeSpan.FromSeconds(15);

    private const int MaxAttempts = 60;

    private const int MaxSterileAttempts = 4;

    private async Task DownloadWithRetryAsync(string url, string dest, long expected,
                                              Action<Progress> progress, CancellationToken ct)
    {
        int attempt = 0, sterile = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            long before = Size(dest);
            try
            {
                await DownloadAsync(url, dest, expected, progress, ct);
                return;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is IOException or HttpRequestException)
            {
                long after = Size(dest);

                if (after > before) sterile = 0; else sterile++;

                if (++attempt >= MaxAttempts || sterile >= MaxSterileAttempts)
                    throw new IOException(
                        $"Nie udało się pobrać całego pliku. Pobrano {Human(after)}"
                        + (expected > 0 ? $" z {Human(expected)}" : "")
                        + $" w {attempt} próbach. Ostatni błąd: {ex.Message}");

                var pauza = TimeSpan.FromSeconds(sterile == 0 ? 3 : Math.Min(10, 3 + sterile * 3));
                progress(new Progress("download", after, expected,
                    $"Połączenie przerwane po {Human(after)} — wznawiam automatycznie "
                    + $"(próba {attempt + 1})…"));
                await Task.Delay(pauza, ct);
            }
        }
    }

    private static long Size(string path)
    {
        try { return File.Exists(path) ? new FileInfo(path).Length : 0; }
        catch { return 0; }
    }

    private async Task DownloadAsync(string url, string dest, long expected, Action<Progress> progress,
                                     CancellationToken ct)
    {
        long have = 0;
        try { if (File.Exists(dest)) have = new FileInfo(dest).Length; } catch { have = 0; }
        if (have > 0 && expected > 0 && have >= expected) have = 0;
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (have > 0) req.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(have, null);

        HttpResponseMessage resp;
        try
        {
            using var headCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            headCts.CancelAfter(TimeSpan.FromSeconds(20));
            resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, headCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new IOException("serwer nie odesłał nagłówków w ciągu 20 s");
        }
        using var _resp = resp;

        bool resuming = have > 0 && resp.StatusCode == System.Net.HttpStatusCode.PartialContent;
        if (have > 0 && !resuming) have = 0;
        resp.EnsureSuccessStatusCode();

        long total = resp.Content.Headers.ContentLength is long len && len > 0
            ? len + have
            : expected;

        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = new FileStream(dest, resuming ? FileMode.Append : FileMode.Create,
                                             FileAccess.Write, FileShare.None, 1 << 16, true);

        var buf = new byte[1 << 16];
        long done = have;
        var startedAt = DateTime.UtcNow;
        long doneAtStart = have;
        var lastReport = DateTime.UtcNow;

        while (true)
        {
            int read;

            using (var stall = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                stall.CancelAfter(StallTimeout);
                try
                {
                    read = await src.ReadAsync(buf, stall.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    throw new IOException(
                        $"brak danych przez {StallTimeout.TotalSeconds:F0} s przy {Human(done)}");
                }
            }
            if (read <= 0) break;

            await dst.WriteAsync(buf.AsMemory(0, read), ct);
            done += read;

            if ((DateTime.UtcNow - lastReport).TotalMilliseconds > 250)
            {
                lastReport = DateTime.UtcNow;
                progress(new Progress("download", done, total, Opis(done, total, doneAtStart, startedAt)));
            }
        }

        if (total > 0 && done < total)
            throw new IOException($"serwer przerwał wysyłanie przy {Human(done)} z {Human(total)}");

        progress(new Progress("download", done, total, $"Pobrano {Human(done)}."));
    }

    private static string Opis(long done, long total, long doneAtStart, DateTime startedAt)
    {
        var sec = (DateTime.UtcNow - startedAt).TotalSeconds;
        double bps = sec > 0.5 ? (done - doneAtStart) / sec : 0;
        var txt = total > 0 ? $"Pobieranie: {Human(done)} z {Human(total)}" : $"Pobieranie: {Human(done)}";
        if (bps > 1) txt += $" · {Human((long)bps)}/s";
        if (bps > 1 && total > done)
        {
            var eta = TimeSpan.FromSeconds((total - done) / bps);
            txt += eta.TotalHours >= 1
                ? $" · pozostało {eta.Hours} h {eta.Minutes} min"
                : $" · pozostało {Math.Max(1, (int)eta.TotalMinutes)} min";
        }
        return txt;
    }

    private static string Human(long b)
    {
        if (b < 1024) return b + " B";
        if (b < 1048576) return (b / 1024.0).ToString("F1") + " KB";
        if (b < 1073741824) return (b / 1048576.0).ToString("F1") + " MB";
        return (b / 1073741824.0).ToString("F2") + " GB";
    }

    private static async Task<string> Sha256Async(string path, CancellationToken ct)
    {
        await using var s = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(s, ct);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void ExtractSafely(string zipPath, string destDir)
    {
        var full = Path.GetFullPath(destDir) + Path.DirectorySeparatorChar;
        using var zip = ZipFile.OpenRead(zipPath);
        foreach (var entry in zip.Entries)
        {
            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\')) continue;   
            var target = Path.GetFullPath(Path.Combine(destDir, entry.FullName));
            if (!target.StartsWith(full, StringComparison.OrdinalIgnoreCase))
                throw new IOException($"Archiwum zawiera wpis wskazujący poza katalog docelowy: {entry.FullName}");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, overwrite: true);
        }
    }

    private static string? FindRoot(string staging)
    {
        if (File.Exists(Path.Combine(staging, "Malward.exe"))) return staging;
        try
        {
            foreach (var d in Directory.EnumerateDirectories(staging))
                if (File.Exists(Path.Combine(d, "Malward.exe"))) return d;
        }
        catch { }
        return null;
    }

    public (bool ok, string message) LaunchInstaller(string stagingRoot, bool relaunch = true)
    {
        try
        {
            var exe = Path.Combine(stagingRoot, "mwupdate.exe");
            if (!File.Exists(exe)) return (false, "Nie znaleziono instalatora aktualizacji.");

            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                WorkingDirectory = stagingRoot,
                Verb = "runas",
            };
            psi.ArgumentList.Add("--staging");  psi.ArgumentList.Add(stagingRoot);
            psi.ArgumentList.Add("--install");  psi.ArgumentList.Add(_installDir);
            psi.ArgumentList.Add("--wait-pid"); psi.ArgumentList.Add(Environment.ProcessId.ToString());
            if (relaunch) psi.ArgumentList.Add("--relaunch");

            var p = Process.Start(psi);
            return p != null
                ? (true, "Instalowanie aktualizacji…")
                : (false, "Nie udało się uruchomić instalatora aktualizacji.");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return (false, "Aktualizacja anulowana — instalator wymaga uprawnień administratora.");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public void CleanupAfterUpdate()
    {
        try
        {
            var marker = Path.Combine(_dataDir, "update", "cleanup.txt");
            if (!File.Exists(marker)) return;
            var dir = File.ReadAllText(marker).Trim();

            var expected = Path.GetFullPath(Path.Combine(_dataDir, "update"));
            if (dir.Length > 0 && Path.GetFullPath(dir).StartsWith(expected, StringComparison.OrdinalIgnoreCase))
                TryDeleteDir(dir);
            TryDelete(marker);
        }
        catch { }
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
    private static void TryDeleteDir(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { } }
}
