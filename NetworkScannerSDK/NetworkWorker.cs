using Microsoft.Extensions.Hosting;

namespace Malward.NetworkScanner;

public sealed class NetworkWorker : BackgroundService
{
    private readonly NetworkConfig _config;
    private NetworkService? _service;

    public NetworkWorker(NetworkConfig config) => _config = config;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Log.Info("Service", "Malward Network Scanner service started.");
        _service = new NetworkService(_config);
        _service.Start();

        var tcs = new TaskCompletionSource();
        stoppingToken.Register(() => tcs.TrySetResult());
        return tcs.Task;
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Info("Service", "Stopping service…");
        if (_service != null)
        {
            try { await _service.StopAsync(); } catch { }
            await _service.DisposeAsync();
            _service = null;
        }
        await base.StopAsync(cancellationToken);
    }
}
