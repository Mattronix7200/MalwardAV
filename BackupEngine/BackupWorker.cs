using Microsoft.Extensions.Hosting;

namespace Malward.BackupEngine;

public sealed class BackupWorker : BackgroundService
{
    private readonly BackupConfig _config;

    public BackupWorker(BackupConfig config) => _config = config;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_config.OnFileChange)
        {
            Log.Info("Watch", "on_file_change=false — file-change watch inactive.");
            return;
        }

        Log.Info("Watch", "File-change watch started inside the service process.");

        FileWatcher? watcher = null;
        try
        {
            watcher = new FileWatcher(_config);
            watcher.Start();

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var ready = watcher.DrainReady();
                    if (ready.Count > 0)
                    {
                        Guid id;
                        using (var runner = new BackupRunner(_config))
                        {
                            id = runner.DoBackupPaths(ready, BkfFormat.Trigger.FsWatch);
                            foreach (var p in ready) watcher.MarkBackupDone(p);
                        }

                        if (id != Guid.Empty)
                            Log.Info("Watch", $"FsWatch snapshot {id} from {ready.Count} candidates");
                        else
                            Log.Debug("Watch", $"No snapshot — {ready.Count} candidates, 0 files to write.");

                        TrimWorkingSet();
                    }
                }
                catch (Exception ex) { Log.Warn("Watch", ex.Message); }

                try { await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }
        catch (Exception ex)
        {
            Log.Error("Watch", $"File-change watch stopped: {ex.Message}");
        }
        finally
        {
            try { watcher?.Dispose(); } catch { }
            Log.Info("Watch", "File-change watch stopped.");
        }
    }

    private static void TrimWorkingSet()
    {
        try
        {
            SetProcessWorkingSetSize(System.Diagnostics.Process.GetCurrentProcess().Handle,
                                     (IntPtr)(-1), (IntPtr)(-1));
        }
        catch { }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool SetProcessWorkingSetSize(IntPtr proc, IntPtr min, IntPtr max);
}
