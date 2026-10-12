using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class BackupEngineClient
{
    public string? LastError { get; private set; }

    private static string? ExePath => BackupServiceController.FindBkmonitor();

    public bool IsAvailable => ExePath != null && File.Exists(ExePath);

    public Task<BackupStatus?> StatusAsync()
        => RunJson("status", el => new BackupStatus
        {
            BkfPath   = GetStr(el, "bkf_path"),
            BkfSize   = GetLong(el, "bkf_size"),
            SnapCount = (int)GetLong(el, "snap_count"),
            Schedule  = GetStr(el, "schedule"),
            NextFire  = GetStr(el, "next_fire"),
            CompressionMode = (int)GetLong(el, "compression_mode"),
            OnFileChange = el.TryGetProperty("on_file_change", out var ofc) && ofc.ValueKind == JsonValueKind.True,
            WatchFolders = el.TryGetProperty("watch_folders", out var wf) && wf.ValueKind == JsonValueKind.Array
                ? wf.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToList()
                : new List<string>(),
        }, timeoutMs: 8000);

    public Task<List<SnapshotInfo>?> SnapshotListAsync()
        => RunJson("list", el =>
        {
            var list = new List<SnapshotInfo>();
            if (el.TryGetProperty("snapshots", out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var e in arr.EnumerateArray())
                    list.Add(new SnapshotInfo
                    {
                        SnapId = GetStr(e, "snap_id"),
                        Timestamp = GetLong(e, "timestamp"),
                        Size = GetLong(e, "size"),
                        Trigger = GetStr(e, "trigger_name"),
                    });
            return list;
        }, timeoutMs: 15000);

    public Task<List<SnapshotFile>?> SnapshotFilesAsync(string snapId)
        => RunJson($"files {Q(snapId)}", el =>
        {
            var list = new List<SnapshotFile>();
            if (el.TryGetProperty("files", out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var e in arr.EnumerateArray())
                    list.Add(new SnapshotFile
                    {
                        Path = GetStr(e, "path"),
                        Size = GetLong(e, "size"),
                        Mtime = GetLong(e, "mtime"),
                    });
            return list;
        }, timeoutMs: 60000);

    public Task<bool> BackupNowAsync(string trigger = "manual")
        => RunBool($"backup --trigger {trigger}", "snap_id", timeoutMs: 30 * 60 * 1000);

    public Task<BackupEstimate?> EstimateAsync()
        => RunJson("estimate", el => new BackupEstimate
        {
            Files = (int)GetLong(el, "files"),
            Bytes = GetLong(el, "bytes"),
            RateBps = GetLong(el, "rate_bps"),
            EtaSec = GetLong(el, "eta_sec"),
        }, timeoutMs: 120000);

    public static string CancelFlagPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "backup", "backup-cancel");

    public void RequestCancel()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CancelFlagPath)!);
            File.WriteAllText(CancelFlagPath, DateTimeOffset.UtcNow.ToString("o"));
        }
        catch (Exception ex) { LastError = ex.Message; }
    }

    public async Task<BackupRunOutcome> BackupNowAsync(string trigger,
                                                       Action<long, long, long, long>? onProgress,
                                                       CancellationToken ct)
    {
        LastError = null;
        var exe = ExePath;
        if (exe == null) { LastError = "nie znaleziono bkmonitor.exe"; return new BackupRunOutcome(); }

        try { File.Delete(CancelFlagPath); } catch { }

        var psi = new ProcessStartInfo(exe)
        {
            Arguments = $"backup --trigger {trigger}",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };

        try
        {
            using var p = Process.Start(psi);
            if (p == null) { LastError = "nie udało się uruchomić bkmonitor.exe"; return new BackupRunOutcome(); }

            using var stop = ct.Register(RequestCancel);

            string? json = null;
            const string MARK = "BACKUP-PROGRESS:";
            string? line;
            while ((line = await p.StandardOutput.ReadLineAsync()) != null)
            {
                line = line.Trim();
                if (line.StartsWith(MARK, StringComparison.Ordinal))
                {
                    if (TryParseProgress(line, out var df, out var tf, out var db, out var tb))
                        onProgress?.Invoke(df, tf, db, tb);
                    continue;
                }
                if (line.StartsWith("{", StringComparison.Ordinal)) json = line;
            }

            await Task.Run(() => p.WaitForExit(60000));

            if (json == null) { LastError = "brak JSON na stdout"; return new BackupRunOutcome(); }

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!(root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True))
            {
                LastError = root.TryGetProperty("error", out var e) ? e.GetString() : "operacja nieudana";
                return new BackupRunOutcome();
            }

            var res = root.TryGetProperty("result", out var r) ? r : default;
            bool cancelled = res.ValueKind == JsonValueKind.Object
                             && res.TryGetProperty("cancelled", out var cEl)
                             && cEl.ValueKind == JsonValueKind.True;
            bool empty = res.ValueKind == JsonValueKind.Object
                         && res.TryGetProperty("empty", out var emEl)
                         && emEl.ValueKind == JsonValueKind.True;

            return new BackupRunOutcome { Ok = !cancelled, Cancelled = cancelled, Empty = empty };
        }
        catch (Exception ex)
        {
            LastError = ex.GetType().Name + ": " + ex.Message;
            return new BackupRunOutcome();
        }
        finally { try { File.Delete(CancelFlagPath); } catch { } }
    }

    public async Task<RestoreResult?> RestoreAsync(string snapId, List<string> paths, string? target = null)
    {
        var pf = WritePathsTemp(paths);
        try
        {
            var args = $"restore {Q(snapId)} --paths-file {Q(pf)}";
            if (!string.IsNullOrEmpty(target)) args += $" --target {Q(target!)}";
            return await RunJson(args, el => new RestoreResult
            {
                Restored = (int)GetLong(el, "restored"),
                Failed = (int)GetLong(el, "failed"),
            }, timeoutMs: 30 * 60 * 1000);
        }
        finally { try { File.Delete(pf); } catch { } }
    }

    public Task<bool> DeleteAsync(string snapId)
        => RunBool($"delete {Q(snapId)}", "deleted", timeoutMs: 60000);

    public Task<bool> ExportAsync(string snapId, string outPath)
        => RunBool($"export {Q(snapId)} {Q(outPath)}", "ok", timeoutMs: 60000);

    public Task<int> ImportAsync(string inPath)
        => RunInt($"import {Q(inPath)}", el => (int)GetLong(el, "imported"), timeoutMs: 60000);

    public Task UninstallLegacyAsync() => RunRaw("uninstall", 10000);

    public Task<string?> BootStatusJsonAsync()  => RunResultJson("boot-status", 30000);
    public Task<string?> BootBackupJsonAsync()  => RunResultJson("boot-backup", 60000);
    public Task<string?> BootRestoreJsonAsync(int? drive, bool all)
    {
        var args = "boot-restore";
        if (all) args += " --all";
        if (drive.HasValue) args += $" --drive {drive.Value}";
        return RunResultJson(args, 60000);
    }

    private async Task<string?> RunResultJson(string args, int timeoutMs)
    {
        var (ok, root) = await RunAndParse(args, timeoutMs);
        if (!ok || root is null) return null;
        try { return root.Value.GetRawText(); }
        catch (Exception ex) { LastError = "serialize: " + ex.Message; return null; }
    }

    internal const string ProgressMark = "BACKUP-PROGRESS:";

    internal static bool TryParseProgress(string line, out long doneFiles, out long totalFiles,
                                          out long doneBytes, out long totalBytes)
    {
        doneFiles = totalFiles = doneBytes = totalBytes = 0;
        if (line == null) return false;
        line = line.Trim();
        if (!line.StartsWith(ProgressMark, StringComparison.Ordinal)) return false;

        var body = line[ProgressMark.Length..].Split(':');
        if (body.Length != 2) return false;
        var f = body[0].Split('/');
        var b = body[1].Split('/');
        if (f.Length != 2 || b.Length != 2) return false;

        return long.TryParse(f[0], out doneFiles) && long.TryParse(f[1], out totalFiles)
            && long.TryParse(b[0], out doneBytes) && long.TryParse(b[1], out totalBytes);
    }

    public sealed class BackupEstimate
    {
        public int Files { get; set; }
        public long Bytes { get; set; }
        public long RateBps { get; set; }
        public long EtaSec { get; set; }
    }

    public sealed class BackupRunOutcome
    {
        public bool Ok { get; set; }
        public bool Cancelled { get; set; }
        public bool Empty { get; set; }
    }

    private async Task<T?> RunJson<T>(string args, Func<JsonElement, T> map, int timeoutMs) where T : class
    {
        var (ok, root) = await RunAndParse(args, timeoutMs);
        if (!ok || root is null) return null;
        try { return map(root.Value); }
        catch (Exception ex) { LastError = "parse: " + ex.Message; return null; }
    }

    private async Task<int> RunInt(string args, Func<JsonElement, int> map, int timeoutMs)
    {
        var (ok, root) = await RunAndParse(args, timeoutMs);
        if (!ok || root is null) return 0;
        try { return map(root.Value); } catch { return 0; }
    }

    private async Task<bool> RunBool(string args, string field, int timeoutMs)
    {
        var (ok, root) = await RunAndParse(args, timeoutMs);
        if (!ok || root is null) return false;
        if (!root.Value.TryGetProperty(field, out var v)) return true;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => !string.IsNullOrEmpty(v.GetString()),
            _ => true,
        };
    }

    private async Task RunRaw(string args, int timeoutMs) => await RunAndParse(args, timeoutMs);

    private async Task<(bool ok, JsonElement? result)> RunAndParse(string args, int timeoutMs)
    {
        LastError = null;
        var exe = ExePath;
        if (exe == null) { LastError = "nie znaleziono bkmonitor.exe"; return (false, null); }

        var psi = new ProcessStartInfo(exe)
        {
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        try
        {
            using var p = Process.Start(psi);
            if (p == null) { LastError = "nie udało się uruchomić bkmonitor.exe"; return (false, null); }
            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();
            var exited = await Task.Run(() => p.WaitForExit(timeoutMs));
            if (!exited)
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                LastError = "timeout operacji bkmonitor";
                return (false, null);
            }
            var stdout = await stdoutTask;

            var line = stdout.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("{"));
            if (string.IsNullOrEmpty(line)) { LastError = "brak JSON na stdout (exit=" + p.ExitCode + ")"; return (false, null); }
            using var doc = JsonDocument.Parse(line);
            var rootEl = doc.RootElement;
            bool ok = rootEl.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
            if (!ok)
            {
                LastError = rootEl.TryGetProperty("error", out var errEl) ? errEl.GetString() : "operacja nieudana";
                return (false, null);
            }
            if (rootEl.TryGetProperty("result", out var resEl))
                return (true, resEl.Clone());
            return (true, null);
        }
        catch (Exception ex)
        {
            LastError = ex.GetType().Name + ": " + ex.Message;
            return (false, null);
        }
    }

    private static string WritePathsTemp(IEnumerable<string> paths)
    {
        var f = Path.Combine(Path.GetTempPath(), "mwbk-paths-" + Guid.NewGuid().ToString("N")[..8] + ".txt");
        File.WriteAllLines(f, paths);
        return f;
    }

    private static string Q(string s) => "\"" + s.Replace("\"", "\\\"") + "\"";
    private static string GetStr(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    private static long GetLong(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : 0;
}

public sealed class BackupStatus
{
    public string BkfPath { get; set; } = "";
    public long BkfSize { get; set; }
    public int SnapCount { get; set; }
    public string Schedule { get; set; } = "";
    public string NextFire { get; set; } = "";
    public int CompressionMode { get; set; }
    public bool OnFileChange { get; set; }
    public List<string> WatchFolders { get; set; } = new();
}

public sealed class SnapshotInfo
{
    public string SnapId { get; set; } = "";
    public long Timestamp { get; set; }
    public long Size { get; set; }
    public string Trigger { get; set; } = "";
}

public sealed class SnapshotFile
{
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public long Mtime { get; set; }
}

public sealed class RestoreResult
{
    public int Restored { get; set; }
    public int Failed { get; set; }
}
