using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public sealed class EngineBridge : IDisposable
{
    private readonly string _malscanPath;
    private readonly ChildJobObject _job;
    private Process? _currentScan;
    private CancellationTokenSource? _cancelCts;

    public EngineBridge(string malscanPath)
    {
        _malscanPath = malscanPath;
        _job = new ChildJobObject();
    }

    public void Dispose() => _job.Dispose();

    public sealed record ScanProgress(int Done, int Total, double Pct, string State, string File);

    public sealed record ScanLine(string Verdict, string Source, string? Detection, string Path, string? Error,
                                  string? ArchiveEntry = null,
                                  string? ArchiveDisplay = null);

    public sealed record ScanSkip(string Category, string Path, string Source, string Reason);
    public sealed record ScanSummary(
        long Encrypted, long Blocked, long Safe, long Cloud,
        long Threats, long System, long Skipped, long FilesTotal,
        string TimeText, string BytesText, bool Canceled);

    public event Action<ScanProgress>? OnProgress;
    public event Action<ScanLine>? OnLine;
    public event Action<ScanSkip>? OnSkip;
    public event Action<ScanSummary>? OnDone;
    public event Action<string>? OnRawLine;
    public event Action<string>? OnError;

    private static readonly Regex _ansiRe = new(@"\x1b\[[0-9;]*[A-Za-z]", RegexOptions.Compiled);
    private static readonly Regex _progressRe = new(
        @"^\[(\d+)/(\d+)\s+([\d.]+)%\]\s+(?:([^:]+):\s*)?(.*)$", RegexOptions.Compiled);
    private static readonly Regex _lineRe = new(
        @"^(MALWARE|clean|skip|ERR)\s+\(([^)]+)\)\s*(?:\[([^\]]+)\])?\s*(.+?)(?:\s+--\s+(.+?))?(?:\s+->\s+.+)?$",
        RegexOptions.Compiled);

    public async Task<int> RunScanAsync(string target, CancellationToken externalCt = default,
                                        string? profile = null, string? planFile = null)
    {
        _cancelCts?.Dispose();
        _cancelCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);

        var args = new List<string> { "scan" };

        if (!string.IsNullOrEmpty(target)) args.Add(target);
        if (!string.IsNullOrEmpty(planFile)) { args.Add("--plan"); args.Add(planFile!); }
        else if (!string.IsNullOrEmpty(profile)) { args.Add("--profile"); args.Add(profile!); }
        args.Add("-vs");

        if (ServiceScanAvailable())
        {
            var viaService = await TryRunScanViaServiceAsync(target, profile, planFile, _cancelCts.Token);
            if (viaService.HasValue) return viaService.Value;
            OnRawLine?.Invoke("[i] Usługa nie odebrała zlecenia — skanuję w tym procesie.");
        }

        return await RunInProcessAsync(
            (writer, ct) => Malward.Engine.EngineHost.RunScan(args.ToArray(), writer, ct),
            _cancelCts.Token);
    }

    private static string ScanDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "data");

    private static bool ServiceScanAvailable()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("MalwardResidentShield");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch { return false; }
    }

    private static bool ScanLeaseHolds(string scanId)
    {
        try
        {
            var own = new FileInfo(Path.Combine(ScanDataDir, $"scan-active-{scanId}"));
            if (own.Exists)
                return DateTime.UtcNow - own.LastWriteTimeUtc <= TimeSpan.FromSeconds(15);

            var path = Path.Combine(ScanDataDir, "scan-active");
            var fi = new FileInfo(path);
            if (!fi.Exists) return false;
            if (DateTime.UtcNow - fi.LastWriteTimeUtc > TimeSpan.FromSeconds(15)) return false;
            var id = File.ReadAllText(path).Trim();

            return id.Length == 0 || string.Equals(id, scanId, StringComparison.Ordinal);
        }
        catch
        {
            return true;
        }
    }

    internal static List<string> ServiceScanIds()
    {
        var ids = new List<string>();
        try
        {
            if (!Directory.Exists(ScanDataDir)) return ids;
            foreach (var path in Directory.EnumerateFiles(ScanDataDir, "scan-active-*"))
            {
                try
                {
                    var fi = new FileInfo(path);
                    if (DateTime.UtcNow - fi.LastWriteTimeUtc > TimeSpan.FromSeconds(15)) continue;
                    var id = File.ReadAllText(path).Trim();
                    if (id.Length == 0)
                        id = Path.GetFileName(path)["scan-active-".Length..];
                    if (id.Length > 0 && !ids.Contains(id)) ids.Add(id);
                }
                catch { }
            }
            if (ids.Count == 0)
            {
                var legacy = ServiceScanId();
                if (legacy != null) ids.Add(legacy);
            }
        }
        catch { }
        return ids;
    }

    internal static bool SubmitServiceScan(string? target, string? profile, string? planFile,
                                           out string id)
    {
        id = Guid.NewGuid().ToString("N")[..12];
        if (!ServiceScanAvailable()) return false;
        try { return WriteScanRequest(id, target, profile, planFile); }
        catch { return false; }
    }

    internal static bool WriteScanRequest(string id, string? target, string? profile, string? planFile)
    {
        Directory.CreateDirectory(ScanDataDir);
        var reqPath = Path.Combine(ScanDataDir, "scan-request.json");

        for (int i = 0; i < 20 && File.Exists(reqPath); i++) Thread.Sleep(150);
        if (File.Exists(reqPath)) return false;

        var targets = new System.Text.Json.Nodes.JsonArray();
        if (!string.IsNullOrEmpty(target)) targets.Add(target);

        var req = new System.Text.Json.Nodes.JsonObject
        {
            ["id"] = id,
            ["targets"] = targets,
        };
        if (!string.IsNullOrEmpty(planFile)) req["plan"] = planFile;
        else if (!string.IsNullOrEmpty(profile)) req["profile"] = profile;

        File.WriteAllText(reqPath, req.ToJsonString());
        return true;
    }

    internal static void CancelServiceScan(string id)
    {
        Directory.CreateDirectory(ScanDataDir);
        File.WriteAllText(Path.Combine(ScanDataDir, $"scan-cancel-{id}"), id);
    }

    internal static bool ServiceScanRunning()
    {
        try
        {
            var fi = new FileInfo(Path.Combine(ScanDataDir, "scan-active"));
            return fi.Exists && DateTime.UtcNow - fi.LastWriteTimeUtc <= TimeSpan.FromSeconds(15);
        }
        catch { return false; }
    }

    internal static string? ServiceScanId()
    {
        try
        {
            if (!ServiceScanRunning()) return null;
            var id = File.ReadAllText(Path.Combine(ScanDataDir, "scan-active")).Trim();
            return id.Length == 0 ? null : id;
        }
        catch { return null; }
    }

    internal static DateTime? ServiceScanStartedUtc(string id)
    {
        try
        {
            var fi = new FileInfo(Path.Combine(ScanDataDir, $"scan-{id}.out"));
            return fi.Exists ? fi.CreationTimeUtc : null;
        }
        catch { return null; }
    }

    private string? _serviceScanId;

    private async Task<int?> TryRunScanViaServiceAsync(string target, string? profile,
                                                       string? planFile, CancellationToken ct)
    {
        string id = Guid.NewGuid().ToString("N")[..12];
        string dir = ScanDataDir;
        string outPath = Path.Combine(dir, $"scan-{id}.out");
        string reqPath = Path.Combine(dir, "scan-request.json");

        try
        {
            Directory.CreateDirectory(dir);
            try { File.Delete(outPath); } catch { }

            if (!WriteScanRequest(id, target, profile, planFile))
            {
                _serviceScanId = null;
                return null;
            }
            _serviceScanId = id;

            for (int i = 0; i < 40 && !File.Exists(outPath); i++)
            {
                if (ct.IsCancellationRequested) break;
                await Task.Delay(250, CancellationToken.None);
            }

            if (!File.Exists(outPath))
            {
                DropOwnRequest(reqPath, id);
                _serviceScanId = null;
                return null;
            }

            return await TailServiceScanAsync(outPath, id, ct);
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Zlecenie skanu do usługi nie powiodło się: {ex.Message}");
            DropOwnRequest(reqPath, id);
            _serviceScanId = null;
            return null;
        }
        finally { _serviceScanId = null; }
    }

    private static void DropOwnRequest(string reqPath, string id)
    {
        try
        {
            if (!File.Exists(reqPath)) return;
            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(reqPath));
            if (!string.Equals(node?["id"]?.GetValue<string>(), id, StringComparison.Ordinal)) return;
            File.Delete(reqPath);
        }
        catch { }
    }

    internal string? CurrentServiceScanId => _serviceScanId;

    internal sealed record ScanPeek(string? Profile, string? FirstFolder, int FolderCount,
                                    double Pct, long Done, long Total, string? File);

    internal static ScanPeek PeekServiceScan(string id)
    {
        string? profile = null, firstFolder = null, file = null;
        int folders = 0;
        double pct = -1;
        long done = 0, total = 0;
        try
        {
            var path = Path.Combine(ScanDataDir, $"scan-{id}.out");
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite | FileShare.Delete);

            using (var head = new StreamReader(fs, Encoding.UTF8, false, 4096, leaveOpen: true))
            {
                for (int i = 0; i < 60; i++)
                {
                    var line = head.ReadLine();
                    if (line == null) break;
                    if (line.StartsWith("SCANPLAN\t", StringComparison.Ordinal))
                    {
                        profile = Field(line, "name");
                        int.TryParse(Field(line, "folders"), out folders);
                    }
                    else if (firstFolder == null && line.StartsWith("SCANFOLDER\t", StringComparison.Ordinal))
                        firstFolder = Field(line, "path");
                }
            }

            const int ogon = 16 * 1024;
            if (fs.Length > 0)
            {
                fs.Position = Math.Max(0, fs.Length - ogon);
                var bufor = new byte[Math.Min(ogon, fs.Length)];
                int n = fs.Read(bufor, 0, bufor.Length);
                var tekst = Encoding.UTF8.GetString(bufor, 0, n);
                foreach (var line in tekst.Split('\n'))
                {
                    if (!line.StartsWith("PROGRESS\t", StringComparison.Ordinal)) continue;
                    if (double.TryParse(Field(line, "pct"), System.Globalization.NumberStyles.Float,
                                        System.Globalization.CultureInfo.InvariantCulture, out var p))
                        pct = p;
                    long.TryParse(Field(line, "done"), out done);
                    long.TryParse(Field(line, "total"), out total);
                    file = Field(line, "file");
                }
            }
        }
        catch { }
        return new ScanPeek(profile, firstFolder, folders, pct, done, total, file);
    }

    private static string? Field(string line, string nazwa)
    {
        foreach (var czesc in line.Split('\t'))
        {
            if (!czesc.StartsWith(nazwa + "=", StringComparison.Ordinal)) continue;
            return czesc.Substring(nazwa.Length + 1).TrimEnd('\r');
        }
        return null;
    }

    public async Task<int> AttachToServiceScanAsync(string scanId, CancellationToken ct)
    {
        var outPath = Path.Combine(ScanDataDir, $"scan-{scanId}.out");
        if (!File.Exists(outPath)) return -1;
        _serviceScanId = scanId;
        try { return await TailServiceScanAsync(outPath, scanId, ct); }
        finally { _serviceScanId = null; }
    }

    internal volatile bool DetachRequested;

    private async Task<int> TailServiceScanAsync(string outPath, string scanId, CancellationToken ct)
    {
        ScanSummary? summary = null;
        int rc = -1;

        using var fs = new FileStream(outPath, FileMode.Open, FileAccess.Read,
                                      FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(fs, Encoding.UTF8);

        long lastLength = -1;
        var lastGrowth = DateTime.UtcNow;
        var stallLimit = TimeSpan.FromSeconds(20);

        DateTime? anulowanoO = null;

        while (true)
        {
            var line = await reader.ReadLineAsync();
            if (line == null)
            {
                if (DetachRequested) { rc = -2; break; }

                if (ct.IsCancellationRequested)
                {
                    anulowanoO ??= DateTime.UtcNow;
                    if (DateTime.UtcNow - anulowanoO > TimeSpan.FromSeconds(10)) { rc = -1; break; }
                    await Task.Delay(150, CancellationToken.None);
                    continue;
                }

                long len = -1;
                try { len = fs.Length; } catch { }
                if (len != lastLength) { lastLength = len; lastGrowth = DateTime.UtcNow; }

                else if (DateTime.UtcNow - lastGrowth > stallLimit
                         && (!ScanLeaseHolds(scanId) || !ServiceScanAvailable()))
                {
                    OnError?.Invoke("Skanowanie w usłudze ochrony przerwało się — nie otrzymano wyniku.");
                    rc = 2;
                    break;
                }

                await Task.Delay(150, CancellationToken.None);
                continue;
            }

            if (line.StartsWith("SCANEND\t", StringComparison.Ordinal))
            {
                var v = line["SCANEND\trc=".Length..];
                if (!int.TryParse(v, out rc)) rc = 0;
                break;
            }
            if (line.StartsWith("ERROR\t", StringComparison.Ordinal))
            {
                OnRawLine?.Invoke(line);
                OnError?.Invoke(line);
                continue;
            }
            summary = ParseLine(line, summary);
        }

        if (rc == -2)
        {
            DetachRequested = false;
            return rc;
        }

        summary ??= new ScanSummary(0, 0, 0, 0, 0, 0, 0, 0, "—", "—", Canceled: true);
        OnDone?.Invoke(summary);

        return rc;
    }

    private async Task<int> RunInProcessAsync(Func<TextWriter, CancellationToken, int> command,
                                              CancellationToken ct)
    {
        ScanSummary? summary = null;
        int exit = -1;

        var lines = System.Threading.Channels.Channel.CreateUnbounded<string>(
            new System.Threading.Channels.UnboundedChannelOptions { SingleReader = true, SingleWriter = true });

        var writer = new ChannelLineWriter(lines.Writer);

        var engineTask = Task.Factory.StartNew(() =>
        {
            try { return command(writer, ct); }
            finally
            {
                try { writer.Flush(); } catch { }
                lines.Writer.TryComplete();
            }
        }, ct, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        try
        {
            await foreach (var line in lines.Reader.ReadAllAsync(CancellationToken.None))
            {
                if (line.StartsWith("ERROR\t", StringComparison.Ordinal))
                {
                    OnRawLine?.Invoke(line);
                    OnError?.Invoke(line);
                    continue;
                }
                summary = ParseLine(line, summary);
            }
        }
        catch (OperationCanceledException) {  }

        try { exit = await engineTask; }
        catch (OperationCanceledException) { exit = -1; }
        catch (Exception ex) { OnError?.Invoke(ex.Message); exit = 2; }

        summary ??= new ScanSummary(0, 0, 0, 0, 0, 0, 0, 0, "—", "—", Canceled: true);
        OnDone?.Invoke(summary);

        Malward.Engine.Util.MemoryTrim.AfterLongRun();
        return exit;
    }

    private sealed class ChannelLineWriter : TextWriter
    {
        private readonly System.Threading.Channels.ChannelWriter<string> _out;
        private readonly System.Text.StringBuilder _buf = new();

        public ChannelLineWriter(System.Threading.Channels.ChannelWriter<string> output) => _out = output;

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value)
        {
            if (value == '\n') { Emit(); return; }
            if (value != '\r') _buf.Append(value);
        }

        public override void Write(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            foreach (var c in value) Write(c);
        }

        public override void WriteLine(string? value) { Write(value); Emit(); }

        public override void Flush() => Emit();

        private void Emit()
        {
            if (_buf.Length == 0) return;
            _out.TryWrite(_buf.ToString());
            _buf.Clear();
        }
    }

    public async Task<int> RunScanMemoryAsync(CancellationToken externalCt = default)
    {
        _cancelCts?.Dispose();
        _cancelCts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);

        return await RunInProcessAsync(
            (writer, ct) => Malward.Engine.EngineHost.RunScanMemory(new[] { "scan-memory", "-vs" }, writer, ct),
            _cancelCts.Token);
    }

    public Task CancelScanAsync()
    {
        try
        {
            var id = _serviceScanId;
            if (id != null || ServiceScanRunning())
            {
                try
                {
                    Directory.CreateDirectory(ScanDataDir);
                    File.WriteAllText(Path.Combine(ScanDataDir, "scan-cancel"), id ?? "*");
                }
                catch { }
            }

            _cancelCts?.Cancel();

            var p = _currentScan;
            if (p != null)
            {
                try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
            }
        }
        catch { }
        return Task.CompletedTask;
    }

    public sealed record UpdatePhaseEvent(string Phase, string Status,
        long? BytesDownloaded, long? BytesTotal, double OverallPct, string Message);
    public event Action<UpdatePhaseEvent>? OnUpdatePhase;

    public async Task<int> RunUpdateAsync(Action<string, int> progressLineCb, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _malscanPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("update");

        var p = Process.Start(psi)!;
        _currentScan = p;
        _job.AssignProcess(p);

        var phaseMap = new[]
        {
            ("vps.vdeb",          "program",  0.10, 0.40),
            ("heur.vdeb",         "modules",  0.40, 0.75),
            ("rf-whitelist.vdeb", "extras",   0.75, 1.00),
        };

        void emit(string phase, string status, double overallPct, string msg)
        {
            OnUpdatePhase?.Invoke(new UpdatePhaseEvent(phase, status, null, null, overallPct, msg));
            progressLineCb(msg, (int)Math.Round(overallPct * 100));
        }

        try
        {
            await foreach (var line in ReadLinesAsync(p.StandardOutput, ct))
            {
                OnRawLine?.Invoke(line);
                if (line.Contains("Manifest:", StringComparison.Ordinal))
                { emit("program", "busy", 0.05, "Sprawdzam wersje na serwerze…"); continue; }

                foreach (var (token, phase, lo, hi) in phaseMap)
                {
                    if (!line.Contains(token, StringComparison.OrdinalIgnoreCase)) continue;
                    if (line.Contains("aktualne", StringComparison.OrdinalIgnoreCase))
                        emit(phase, "uptodate", hi, $"{HumanPhase(phase)} — aktualne.");
                    else if (line.Contains("pobieram", StringComparison.OrdinalIgnoreCase) ||
                             line.Contains("zmiana", StringComparison.OrdinalIgnoreCase))
                        emit(phase, "busy", (lo + hi) / 2, $"Pobieram {HumanPhase(phase).ToLower()}…");
                    else if (line.Contains("zaktualizowano", StringComparison.OrdinalIgnoreCase))
                        emit(phase, "ok", hi, $"{HumanPhase(phase)} zaktualizowane.");
                    else if (line.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
                             line.Contains("error", StringComparison.OrdinalIgnoreCase))
                        emit(phase, "err", hi, $"{HumanPhase(phase)} — błąd: {line}");
                    break;
                }
            }
            await foreach (var line in ReadLinesAsync(p.StandardError, ct))
                if (!string.IsNullOrWhiteSpace(line)) { OnError?.Invoke(line); progressLineCb(line, -1); }

            await p.WaitForExitAsync(ct);
            progressLineCb("Zakończono.", 100);
            return p.ExitCode;
        }
        finally
        {
            try { p.Dispose(); } catch { }
            _currentScan = null;
        }
    }

    public async Task<string> RunVersionAsync(CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _malscanPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("version");
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try
        {
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            return output;
        }
        finally { try { p.Dispose(); } catch { } }
    }

    public async Task<List<QuarantineItem>> RunQuarantineListAsync(CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _malscanPath, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("quarantine");
        psi.ArgumentList.Add("list");
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try
        {
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);

            var items = new List<QuarantineItem>();
            var guidRe = new Regex(@"^\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s+(.+)$");
            var tsRe = new Regex(@"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(.+)$");
            foreach (var line in output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var mg = guidRe.Match(line);
                if (!mg.Success) continue;
                var id = mg.Groups[1].Value;
                var mt = tsRe.Match(mg.Groups[2].Value);
                if (!mt.Success) continue;
                var time = mt.Groups[1].Value;

                var parts = Regex.Split(mt.Groups[2].Value, @"\s{2,}")
                    .Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
                long size = 0;
                int di = 0;
                if (parts.Length >= 1 && long.TryParse(parts[0], out var sz)) { size = sz; di = 1; }
                string det, path;
                if (parts.Length - di >= 2) { det = parts[di]; path = string.Join("  ", parts.Skip(di + 1)); }
                else if (parts.Length - di == 1)
                {
                    var fb = Regex.Match(parts[di], @"^(\S+)\s+(.+)$");
                    if (!fb.Success) continue;
                    det = fb.Groups[1].Value; path = fb.Groups[2].Value.Trim();
                }
                else continue;
                items.Add(new QuarantineItem(id, time, det, path, size));
            }
            return items;
        }
        finally { try { p.Dispose(); } catch { } }
    }

    public async Task<bool> RunQuarantineRestoreAsync(string id, string? destPath, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo { FileName = _malscanPath, UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add("quarantine"); psi.ArgumentList.Add("restore"); psi.ArgumentList.Add(id);
        if (!string.IsNullOrEmpty(destPath)) psi.ArgumentList.Add(destPath);
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try { await p.WaitForExitAsync(ct); return p.ExitCode == 0; }
        finally { try { p.Dispose(); } catch { } }
    }

    private static RepairOutcome ParseRepairLine(string? line, bool exitOk)
    {
        if (line == null) return new RepairOutcome(exitOk, "", "", false);
        string Pole(string klucz)
        {
            int i = line.IndexOf(klucz, StringComparison.Ordinal);
            if (i < 0) return "";
            int start = i + klucz.Length;
            int end = line.IndexOf('\t', start);
            var v = end < 0 ? line[start..] : line[start..end];
            return v.Replace("\\t", "\t").Replace("\\n", "\n").Trim();
        }
        return new RepairOutcome(Pole("ok=") == "1", Pole("action="), Pole("detail="),
                                 Pole("reboot=") == "1");
    }

    /// <summary>Repairs the whole batch in one elevated run, so the user sees ONE UAC prompt.</summary>
    public async Task<Dictionary<string, RepairOutcome>> RunRepairBatchElevatedAsync(
        IReadOnlyList<(string Action, string Path, string Detection, string Entry)> items,
        CancellationToken ct = default)
    {
        var wynik = new Dictionary<string, RepairOutcome>(StringComparer.OrdinalIgnoreCase);
        if (items.Count == 0) return wynik;

        string lista = Path.Combine(Path.GetTempPath(), "mw-repair-" + Guid.NewGuid().ToString("N")[..8] + ".txt");
        string raport = lista + ".report";
        try
        {
            await File.WriteAllLinesAsync(lista,
                items.Select(i => string.Join('\t', i.Action, i.Path, i.Detection, i.Entry)), ct);

            var psi = new ProcessStartInfo
            {
                FileName = _malscanPath,
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            psi.ArgumentList.Add("repair");
            psi.ArgumentList.Add("--list");
            psi.ArgumentList.Add(lista);
            psi.ArgumentList.Add("--report");
            psi.ArgumentList.Add(raport);

            using var p = Process.Start(psi);
            if (p == null) return wynik;
            await p.WaitForExitAsync(ct);

            if (!File.Exists(raport)) return wynik;
            foreach (var line in await File.ReadAllLinesAsync(raport, ct))
            {
                int i = line.IndexOf("\tpath=", StringComparison.Ordinal);
                if (i < 0) continue;
                var sciezka = line[(i + 6)..].Replace("\\t", "\t").Replace("\\n", "\n");
                wynik[sciezka] = ParseRepairLine(line[..i], false);
            }
            return wynik;
        }
        finally
        {
            try { File.Delete(lista); } catch { }
            try { File.Delete(raport); } catch { }
        }
    }

    public async Task<string?> RunQuarantineExtractAsync(string id, string destDir, string? nameHint,
                                                         CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _malscanPath, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, StandardOutputEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("quarantine"); psi.ArgumentList.Add("extract");
        psi.ArgumentList.Add(id); psi.ArgumentList.Add(destDir);
        if (!string.IsNullOrEmpty(nameHint)) psi.ArgumentList.Add(nameHint!);
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try
        {
            var output = await p.StandardOutput.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0) return null;
            foreach (var line in output.Split('\n'))
            {
                var t = line.Trim();
                if (t.StartsWith("[+] Extracted to: ", StringComparison.Ordinal))
                    return t["[+] Extracted to: ".Length..].Trim();
            }
            return null;
        }
        finally { try { p.Dispose(); } catch { } }
    }

    public async Task<string> RunQuarantineExportAsync(string id, string destPath,
                                                       CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _malscanPath, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardError = true, StandardErrorEncoding = Encoding.UTF8,
        };
        psi.ArgumentList.Add("quarantine"); psi.ArgumentList.Add("export");
        psi.ArgumentList.Add(id); psi.ArgumentList.Add(destPath);
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try
        {
            var err = await p.StandardError.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);
            if (p.ExitCode == 0 && File.Exists(destPath)) return "";
            var line = err.Split('\n').Select(x => x.Trim())
                          .FirstOrDefault(x => x.StartsWith("[!]", StringComparison.Ordinal));
            return string.IsNullOrEmpty(line)
                ? $"silnik zakończył się kodem {p.ExitCode}"
                : line!.TrimStart('[', '!', ']', ' ');
        }
        finally { try { p.Dispose(); } catch { } }
    }

    public async Task<bool> RunQuarantineDeleteAsync(string id, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo { FileName = _malscanPath, UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add("quarantine"); psi.ArgumentList.Add("delete"); psi.ArgumentList.Add(id);
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try { await p.WaitForExitAsync(ct); return p.ExitCode == 0; }
        finally { try { p.Dispose(); } catch { } }
    }

    public sealed record RepairOutcome(bool Ok, string Action, string Detail, bool RebootRequired);

    public async Task<bool> RunRepairAsync(string action, string path, string detection,
        string? entryChain = null, CancellationToken ct = default)
        => (await RunRepairDetailedAsync(action, path, detection, entryChain, ct)).Ok;

    public async Task<RepairOutcome> RunRepairDetailedAsync(string action, string path, string detection,
        string? entryChain = null, CancellationToken ct = default)
    {
        if (action == "ignore" || action == "exclude")
            return new RepairOutcome(true, action, "", false);
        var psi = new ProcessStartInfo
        {
            FileName = _malscanPath, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding  = System.Text.Encoding.UTF8,
        };
        psi.ArgumentList.Add("repair");
        psi.ArgumentList.Add(action);
        psi.ArgumentList.Add(path);
        if (!string.IsNullOrEmpty(detection))
        {
            psi.ArgumentList.Add("--detection");
            psi.ArgumentList.Add(detection);
        }
        if (!string.IsNullOrEmpty(entryChain))
        {
            psi.ArgumentList.Add("--entry");
            psi.ArgumentList.Add(entryChain);
        }
        var p = Process.Start(psi)!;
        _job.AssignProcess(p);
        try
        {
            string wyjscie = await p.StandardOutput.ReadToEndAsync(ct);
            string blad = await p.StandardError.ReadToEndAsync(ct);
            await p.WaitForExitAsync(ct);

            var linia = wyjscie.Split('\n')
                .FirstOrDefault(l => l.StartsWith("REPAIR\t", StringComparison.Ordinal));
            var outcome = ParseRepairLine(linia, p.ExitCode == 0);
            if (!outcome.Ok && outcome.Detail.Length == 0 && blad.Trim().Length > 0)
                outcome = outcome with { Detail = blad.Trim() };
            return outcome;
        }
        finally { try { p.Dispose(); } catch { } }
    }

    private async Task<int> RunAndParseScanAsync(ProcessStartInfo psi, CancellationToken ct)
    {
        var p = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null");
        _currentScan = p;
        _job.AssignProcess(p);

        ScanSummary? summary = null;

        var stdoutTask = Task.Run(async () =>
        {
            while (!p.StandardOutput.EndOfStream && !ct.IsCancellationRequested)
            {
                var line = await p.StandardOutput.ReadLineAsync();
                if (line == null) break;
                summary = ParseLine(line, summary);
            }
        }, ct);

        var stderrTask = Task.Run(async () =>
        {
            while (!p.StandardError.EndOfStream && !ct.IsCancellationRequested)
            {
                var line = await p.StandardError.ReadLineAsync();
                if (line == null) break;
                OnRawLine?.Invoke(line);
                if (!string.IsNullOrEmpty(line)) OnError?.Invoke(line);
            }
        }, ct);

        try { await Task.WhenAll(stdoutTask, stderrTask); }
        catch (OperationCanceledException) {  }

        try { await p.WaitForExitAsync(CancellationToken.None); } catch { }

        summary ??= new ScanSummary(0, 0, 0, 0, 0, 0, 0, 0, "—", "—", Canceled: true);
        OnDone?.Invoke(summary);

        int exit;
        try { exit = p.ExitCode; } catch { exit = -1; }
        try { p.Dispose(); } catch { }
        _currentScan = null;
        return exit;
    }

    private ScanSummary? ParseLine(string raw, ScanSummary? prevSummary)
    {
        var line = _ansiRe.Replace(raw, "");

        var idx = line.LastIndexOf('\r');
        if (idx >= 0) line = line[(idx + 1)..];

        OnRawLine?.Invoke(line);
        if (string.IsNullOrWhiteSpace(line)) return prevSummary;

        if (line.StartsWith("PROGRESS\t", StringComparison.Ordinal))
        {
            var fields = ParseTsv(line.AsSpan("PROGRESS\t".Length));
            int done = ParseInt(fields, "done"), total = ParseInt(fields, "total");
            double pct = ParseDouble(fields, "pct");
            string state = fields.GetValueOrDefault("state", "");
            string file = fields.GetValueOrDefault("file", "");
            OnProgress?.Invoke(new ScanProgress(done, total, pct, state, file));
            return prevSummary;
        }

        if (line.StartsWith("DETECTION\t", StringComparison.Ordinal))
        {
            var fields = ParseTsv(line.AsSpan("DETECTION\t".Length));
            var entry = fields.GetValueOrDefault("entry", "");

            var display = fields.GetValueOrDefault("display", "");
            OnLine?.Invoke(new ScanLine(
                Verdict: "MALWARE",
                Source: fields.GetValueOrDefault("source", ""),
                Detection: fields.GetValueOrDefault("det", null!),
                Path: fields.GetValueOrDefault("path", ""),
                Error: null,
                ArchiveEntry: string.IsNullOrEmpty(entry) ? null : entry,
                ArchiveDisplay: string.IsNullOrEmpty(display) ? null : display));
            return prevSummary;
        }

        if (line.StartsWith("SKIP\t", StringComparison.Ordinal))
        {
            var fields = ParseTsv(line.AsSpan("SKIP\t".Length));
            OnSkip?.Invoke(new ScanSkip(
                Category: fields.GetValueOrDefault("category", "skipped"),
                Path:     fields.GetValueOrDefault("path", ""),
                Source:   fields.GetValueOrDefault("source", ""),
                Reason:   fields.GetValueOrDefault("reason", "")));
            return prevSummary;
        }

        if (line.StartsWith("SUMMARY\t", StringComparison.Ordinal))
        {
            try
            {
                var json = line["SUMMARY\t".Length..];
                using var doc = JsonDocument.Parse(json);
                var r = doc.RootElement;
                long GetL(string k) => r.TryGetProperty(k, out var v) && v.TryGetInt64(out var x) ? x : 0;
                bool GetB(string k) => r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
                int elapsedSec = (int)GetL("elapsedSec");
                long bytes = GetL("bytes");
                return new ScanSummary(
                    GetL("encrypted"), GetL("blocked"), GetL("safe"), GetL("cloud"),
                    GetL("threats"), GetL("system"), GetL("skipped"), GetL("filesTotal"),
                    FormatTime(elapsedSec), FormatBytes(bytes), GetB("canceled"));
            }
            catch (Exception ex) { OnError?.Invoke($"SUMMARY parse: {ex.Message}"); return prevSummary; }
        }

        var mp = _progressRe.Match(line);
        if (mp.Success)
        {
            int done = int.TryParse(mp.Groups[1].Value, out var d) ? d : 0;
            int total = int.TryParse(mp.Groups[2].Value, out var t) ? t : 0;
            double pct = double.TryParse(mp.Groups[3].Value, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var p) ? p : 0;
            string state = mp.Groups[4].Success ? mp.Groups[4].Value.Trim() : "";
            string file = mp.Groups[5].Value.Trim();
            OnProgress?.Invoke(new ScanProgress(done, total, pct, state, file));
            return prevSummary;
        }
        var ml = _lineRe.Match(line);
        if (ml.Success)
        {
            OnLine?.Invoke(new ScanLine(
                ml.Groups[1].Value, ml.Groups[2].Value,
                ml.Groups[3].Success ? ml.Groups[3].Value : null,
                ml.Groups[4].Value.Trim(),
                ml.Groups[5].Success ? ml.Groups[5].Value : null));
        }
        return prevSummary;
    }

    private static Dictionary<string, string> ParseTsv(ReadOnlySpan<char> input)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var range in input.ToString().Split('\t'))
        {
            int eq = range.IndexOf('=');
            if (eq <= 0) continue;
            d[range[..eq]] = range[(eq + 1)..];
        }
        return d;
    }
    private static int ParseInt(Dictionary<string, string> d, string key) =>
        d.TryGetValue(key, out var v) && int.TryParse(v, out var x) ? x : 0;
    private static double ParseDouble(Dictionary<string, string> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || string.IsNullOrEmpty(v)) return 0.0;

        var norm = v.Replace(',', '.');
        return double.TryParse(norm, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var x) ? x : 0.0;
    }

    private static string FormatTime(int sec)
    {
        if (sec <= 0) return "—";
        var h = sec / 3600; var m = (sec % 3600) / 60; var s = sec % 60;
        return h > 0 ? $"{h}h {m:D2}m {s:D2}s" : m > 0 ? $"{m}m {s:D2}s" : $"{s}s";
    }
    private static string FormatBytes(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024L * 1024) return $"{b / 1024.0:F1} KB";
        if (b < 1024L * 1024 * 1024) return $"{b / 1024.0 / 1024:F1} MB";
        return $"{b / 1024.0 / 1024 / 1024:F2} GB";
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(StreamReader reader,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        while (!reader.EndOfStream && !ct.IsCancellationRequested)
        {
            var l = await reader.ReadLineAsync(ct);
            if (l == null) yield break;
            yield return l;
        }
    }

    private static string HumanPhase(string phase) => phase switch
    {
        "program" => "Program",
        "modules" => "Moduły aplikacji",
        "extras"  => "Dodatkowe moduły",
        _         => phase,
    };
}

public sealed record QuarantineItem(string Id, string Time, string Detection, string Path, long Size = 0);
