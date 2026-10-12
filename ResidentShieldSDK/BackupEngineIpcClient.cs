using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Malward.ResidentShield;

public sealed class BackupEngineIpcClient
{
    private readonly string _pipeName;
    private static int _nextId;

    public BackupEngineIpcClient(string pipeName = "malward-backup")
    {
        _pipeName = pipeName;
    }

    public bool IsAvailable
    {
        get
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", _pipeName,
                    PipeDirection.InOut, PipeOptions.Asynchronous);
                pipe.Connect(timeout: 250);
                return pipe.IsConnected;
            }
            catch { return false; }
        }
    }

    public async Task<RollbackResult?> RollbackAsync(int pid, IEnumerable<string> paths,
                                                      DateTimeOffset since, int timeoutMs = 30_000,
                                                      CancellationToken ct = default)
    {
        var req = new
        {
            id = Interlocked.Increment(ref _nextId),
            cmd = "rollback",
            pid,
            paths = paths.ToArray(),
            since = since.ToUnixTimeSeconds(),
        };
        var resp = await SendAsync(JsonSerializer.Serialize(req), timeoutMs, ct);
        if (resp == null) return null;
        try
        {
            using var doc = JsonDocument.Parse(resp);
            var root = doc.RootElement;
            if (!root.TryGetProperty("ok", out var okEl) || !okEl.GetBoolean()) return null;
            var result = root.GetProperty("result");
            return new RollbackResult
            {
                Restored = result.TryGetProperty("restored", out var r) ? r.GetInt32() : 0,
                Failed   = result.TryGetProperty("failed",   out var f) ? f.GetInt32() : 0,
                FromBkf  = result.TryGetProperty("from_bkf", out var b) ? b.GetInt32() : 0,
                FromVss  = result.TryGetProperty("from_vss", out var v) ? v.GetInt32() : 0,
            };
        }
        catch (Exception ex)
        {
            Log.Warn("BackupIpc", $"Bad JSON in response: {ex.Message}");
            return null;
        }
    }

    public async Task<string?> StatusAsync(CancellationToken ct = default)
    {
        var req = new { id = Interlocked.Increment(ref _nextId), cmd = "status" };
        return await SendAsync(JsonSerializer.Serialize(req), 5000, ct);
    }

    public async Task<bool> ForceBackupNowAsync(CancellationToken ct = default)
    {
        var req = new { id = Interlocked.Increment(ref _nextId), cmd = "force_backup_now" };
        var resp = await SendAsync(JsonSerializer.Serialize(req), 120_000, ct);
        if (resp == null) return false;
        try
        {
            using var doc = JsonDocument.Parse(resp);
            return doc.RootElement.TryGetProperty("ok", out var ok) && ok.GetBoolean();
        }
        catch { return false; }
    }

    private async Task<string?> SendAsync(string line, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", _pipeName,
                PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeoutMs, ct);

            var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
            var reader = new StreamReader(pipe, Encoding.UTF8);
            await writer.WriteLineAsync(line.AsMemory(), ct);
            return await reader.ReadLineAsync(ct);
        }
        catch (TimeoutException)
        {
            Log.Debug("BackupIpc", "Timeout — BackupEngine is not responding (is bkmonitor.exe running?)");
            return null;
        }
        catch (Exception ex)
        {
            Log.Debug("BackupIpc", $"IPC error: {ex.Message}");
            return null;
        }
    }
}

public sealed class RollbackResult
{
    public int Restored { get; set; }
    public int Failed { get; set; }
    public int FromBkf { get; set; }
    public int FromVss { get; set; }
}
