using System.IO.Pipes;

namespace Malward.ResidentShield;

public sealed class HookPipe : IDisposable
{
    private readonly ScanEngine   _scanEngine;
    private readonly ShieldConfig _config;
    private readonly CancellationToken _ct;
    private bool _running;

    private const string PipeName = "MalwardShieldHook";

    public HookPipe(ScanEngine scanEngine, ShieldConfig config, CancellationToken ct)
    {
        _scanEngine = scanEngine;
        _config     = config;
        _ct         = ct;
    }

    public void Start()
    {
        _running = true;
        Task.Run(AcceptLoopAsync, _ct);
        Log.Info("Pipe", $"Server started: \\\\.\\pipe\\{PipeName}");
    }

    private async Task AcceptLoopAsync()
    {
        while (_running && !_ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(_ct);
                _ = HandleClientAsync(pipe);
            }
            catch (OperationCanceledException) { pipe?.Dispose(); break; }
            catch (Exception ex)
            {
                pipe?.Dispose();
                Log.Error("Pipe", $"Accept error: {ex.Message}");
                await Task.Delay(500, _ct).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe)
    {
        try
        {
            using (pipe)
            using (var reader = new StreamReader(pipe, leaveOpen: true))
            using (var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true })
            {
                string? filePath = await reader.ReadLineAsync(_ct);
                if (string.IsNullOrWhiteSpace(filePath))
                {
                    await writer.WriteLineAsync("ALLOW");
                    return;
                }

                Log.Debug("Pipe", $"Query: {filePath}");

                var result = await _scanEngine.ScanAsync(filePath, _ct);

                if (result.Verdict == ScanVerdict.Threat)
                {
                    Log.Alert("Pipe", $"Launch BLOCKED: {Path.GetFileName(filePath)} → {result.ThreatName}");
                    await writer.WriteLineAsync("BLOCK");
                }
                else
                {
                    await writer.WriteLineAsync("ALLOW");
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.Error("Pipe", $"Client error: {ex.Message}");
        }
    }

    public void Dispose() => _running = false;
}
