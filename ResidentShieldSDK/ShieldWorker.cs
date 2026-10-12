using Microsoft.Extensions.Hosting;

namespace Malward.ResidentShield;

public sealed class ShieldWorker : BackgroundService, IReconfigurable
{
    private readonly ShieldConfig    _config;
    private ShieldService?           _service;

    public ShieldWorker(ShieldConfig config) => _config = config;

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Log.Info("Service", "Malward Resident Shield service started.");

        NotifyBus.ClearStale();
        _service = new ShieldService(_config);
        _service.Start();

        var tcs = new TaskCompletionSource();
        stoppingToken.Register(() => tcs.TrySetResult());
        return tcs.Task;
    }

    public Task<bool> ReconfigureAsync(CancellationToken ct)
        => _service?.ReconfigureAsync(ct) ?? Task.FromResult(false);

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        Log.Info("Service", "Stopping the service...");
        if (_service != null)
        {
            try { await _service.StopAsync(); } catch { }
            await _service.DisposeAsync();
            _service = null;
        }
        await base.StopAsync(cancellationToken);
    }
}
