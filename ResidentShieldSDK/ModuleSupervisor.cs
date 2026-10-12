using Microsoft.Extensions.Hosting;

namespace Malward.ResidentShield;

public sealed class ModuleSupervisor : BackgroundService
{
    private readonly ShieldConfig _startupConfig;

    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(3);

    private static readonly TimeSpan RetryBase = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RetryMax = TimeSpan.FromMinutes(10);

    private static readonly TimeSpan StopBudget = TimeSpan.FromSeconds(15);

    private readonly Slot _resident;
    private readonly Slot _network;
    private readonly Slot _backup;
    private readonly Slot[] _slots;

    private volatile bool _stopping;

    private readonly SemaphoreSlim _gate = new(1, 1);

    public ModuleSupervisor(ShieldConfig config)
    {
        _startupConfig = config;

        _resident = new Slot("Resident protection", CreateResident)
        {
            SettingsPath = () => ShieldConfig.ConfigPath,

            IgnoredKeys = new[] { "resident_shield_enabled", "network_shield_enabled" },
        };
        _network  = new Slot("Network shield", CreateNetwork)
        {
            SettingsPath = () => Malward.NetworkScanner.NetworkConfig.DefaultPath,

            IgnoredKeys = new[] { "exclusions" },
        };
        _backup   = new Slot("Backup", CreateBackup)
        {
            SettingsPath = () => Malward.BackupEngine.BackupConfig.DefaultConfigPath,
        };

        _slots = new[] { _resident, _network, _backup };
    }

    private sealed class Slot
    {
        public Slot(string name, Func<IHostedService> factory)
        {
            Name = name;
            Factory = factory;
        }

        public string Name { get; }
        public Func<IHostedService> Factory { get; }

        public IHostedService? Running;

        public volatile bool Faulted;

        public int Failures;
        public DateTime NextAttemptUtc = DateTime.MinValue;

        public Func<string>? SettingsPath;

        public string[]? IgnoredKeys;
        public string StampApplied = "";
        public string StampSeen = "";
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Log.Info("Modules", "Module supervisor started — module switches take effect without restarting the service.");

        await SyncAsync(stoppingToken);

        try
        {
            using var timer = new PeriodicTimer(Tick);
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await SyncAsync(stoppingToken);
        }
        catch (OperationCanceledException) {  }
    }

    private async Task SyncAsync(CancellationToken ct)
    {
        if (_stopping) return;

        await _gate.WaitAsync(CancellationToken.None);
        try
        {
            if (_stopping) return;

            ShieldConfig.ModuleFlags want;
            try { want = ShieldConfig.ModuleFlagsNow(); }
            catch (Exception ex)
            {
                Log.Debug("Modules", $"Could not read the module flags: {ex.Message} — keeping the current set.");
                return;
            }

            await ApplyAsync(_resident, want.Resident, ct);
            await ApplyAsync(_network, want.Network, ct);
            await ApplyAsync(_backup, want.Backup, ct);

            foreach (var slot in _slots)
                await ReloadOnSettingsChangeAsync(slot, ct);
        }
        finally
        {
            _gate.Release();
            PublishState();
        }
    }

    private static string StatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "module-state.json");

    private string _stateWritten = "";
    private DateTime _stateWrittenUtc = DateTime.MinValue;

    private void PublishState()
    {
        try
        {
            string content =
                "{\"resident\":" + (_resident.Running != null ? "true" : "false") +
                ",\"network\":" + (_network.Running != null ? "true" : "false") +
                ",\"backup\":" + (_backup.Running != null ? "true" : "false") +
                ",\"ts\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + "}";

            string shape = content.Substring(0, content.IndexOf(",\"ts\"", StringComparison.Ordinal));
            if (shape == _stateWritten && DateTime.UtcNow - _stateWrittenUtc < TimeSpan.FromSeconds(10))
                return;

            Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
            File.WriteAllText(StatePath, content);
            _stateWritten = shape;
            _stateWrittenUtc = DateTime.UtcNow;
        }
        catch {  }
    }

    private async Task ApplyAsync(Slot slot, bool want, CancellationToken ct)
    {
        if (slot.Running != null && slot.Faulted && want)
        {
            Log.Warn("Modules", $"{slot.Name}: its background task ended with an error — tearing it down.");
            await StopSlotAsync(slot);
            NoteFailure(slot);
        }

        if (want && slot.Running == null)
        {
            if (_stopping) return;
            if (DateTime.UtcNow < slot.NextAttemptUtc) return;

            IHostedService? instance = null;
            try
            {
                instance = slot.Factory();

                slot.Running = instance;
                await instance.StartAsync(ct);
                slot.Faulted = false;
                slot.Failures = 0;
                slot.NextAttemptUtc = DateTime.MinValue;

                slot.StampApplied = StampOf(slot);
                slot.StampSeen = slot.StampApplied;
                ObserveFault(slot, instance);
                Log.Info("Modules", $"{slot.Name}: ENABLED.");
            }
            catch (Exception ex)
            {
                if (instance != null) await DiscardAsync(instance);
                slot.Running = null;
                NoteFailure(slot);
                var wait = slot.NextAttemptUtc - DateTime.UtcNow;
                Log.Error("Modules", $"{slot.Name}: failed to start ({ex.GetType().Name}: {ex.Message}) — " +
                                     $"retrying in {Math.Max(0, wait.TotalSeconds):F0} s.");

                Log.Error("Modules", $"{slot.Name}: {Details(ex)}");
            }
        }
        else if (!want && slot.Running != null)
        {
            await StopSlotAsync(slot);

            slot.Failures = 0;
            slot.NextAttemptUtc = DateTime.MinValue;
            Log.Info("Modules", $"{slot.Name}: DISABLED.");
        }
    }

    private async Task ReloadOnSettingsChangeAsync(Slot slot, CancellationToken ct)
    {
        if (slot.SettingsPath == null) return;

        string stamp = StampOf(slot);

        if (slot.Running == null)
        {
            slot.StampApplied = stamp;
            slot.StampSeen = stamp;
            return;
        }

        if (stamp.Length > 0 && stamp == slot.StampSeen && stamp != slot.StampApplied)
        {
            bool applied = false;
            if (slot.Running is IReconfigurable r)
            {
                try { applied = await r.ReconfigureAsync(ct); }
                catch (Exception ex)
                {
                    Log.Warn("Modules", $"{slot.Name}: applying settings in place failed " +
                                        $"({ex.GetType().Name}: {ex.Message}) — rebuilding the module.");
                    applied = false;
                }
            }

            if (applied)
            {
                Log.Info("Modules", $"{slot.Name}: settings applied without a restart.");
                slot.StampApplied = stamp;
                slot.StampSeen = stamp;
                return;
            }

            Log.Info("Modules", $"{slot.Name}: settings changed — reloading the module in place.");
            await StopSlotAsync(slot);
            await ApplyAsync(slot, true, ct);

            if (slot.Running == null) slot.StampApplied = StampOf(slot);
            stamp = slot.StampApplied;
        }

        slot.StampSeen = stamp;
    }

    private static string StampOf(Slot slot)
    {
        try
        {
            var path = slot.SettingsPath?.Invoke();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";

            var raw = File.ReadAllText(path);
            if (slot.IgnoredKeys is { Length: > 0 }
                && System.Text.Json.Nodes.JsonNode.Parse(raw) is System.Text.Json.Nodes.JsonObject obj)
            {
                foreach (var key in slot.IgnoredKeys) obj.Remove(key);

                raw = JsonText.Indented(obj);
            }

            var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(hash, 0, 8);
        }
        catch { return ""; }
    }

    private static async Task StopSlotAsync(Slot slot)
    {
        var instance = slot.Running;
        slot.Running = null;
        slot.Faulted = false;
        if (instance == null) return;
        await DiscardAsync(instance);
    }

    private static async Task DiscardAsync(IHostedService instance)
    {
        try
        {
            using var budget = new CancellationTokenSource(StopBudget);
            await instance.StopAsync(budget.Token);
        }
        catch (Exception ex)
        {
            Log.Warn("Modules", $"Stopping a module reported: {ex.Message}");
        }
        finally
        {
            if (instance is IDisposable d)
            {
                try { d.Dispose(); } catch { }
            }
        }
    }

    private static void ObserveFault(Slot slot, IHostedService instance)
    {
        if (instance is not BackgroundService bs) return;
        if (bs.ExecuteTask is not Task task) return;

        _ = task.ContinueWith(finished =>
        {
            if (!finished.IsFaulted) return;
            slot.Faulted = true;
            try
            {
                Log.Error("Modules",
                    $"{slot.Name}: stopped with an error — {finished.Exception?.GetBaseException().Message}");
            }
            catch { }
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private static void NoteFailure(Slot slot)
    {
        slot.Failures = Math.Min(slot.Failures + 1, 16);
        double seconds = RetryBase.TotalSeconds * Math.Pow(2, slot.Failures - 1);
        if (seconds > RetryMax.TotalSeconds || double.IsInfinity(seconds)) seconds = RetryMax.TotalSeconds;
        slot.NextAttemptUtc = DateTime.UtcNow.AddSeconds(seconds);
    }

    private IHostedService CreateResident()
    {
        ShieldConfig cfg;
        try { cfg = ShieldConfig.Load(null); }
        catch { cfg = _startupConfig; }
        return new ShieldWorker(cfg);
    }

    private IHostedService CreateNetwork()
    {
        var netConfig = Malward.NetworkScanner.NetworkConfig.Load(null);

        netConfig.Enabled = true;

        Malward.NetworkScanner.Log.FileLoggingEnabled = true;
        return new Malward.NetworkScanner.NetworkWorker(netConfig);
    }

    private IHostedService CreateBackup()
    {
        Program.RetireLegacyBackupService();
        var bkConfig = Malward.BackupEngine.BackupConfig.Load();
        return new Malward.BackupEngine.BackupWorker(bkConfig);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _stopping = true;
        try { await base.StopAsync(cancellationToken); }
        catch (Exception ex) { Log.Warn("Modules", $"Stopping the supervisor loop reported: {ex.Message}"); }

        bool got = await _gate.WaitAsync(TimeSpan.FromSeconds(20), CancellationToken.None);
        if (!got)
            Log.Warn("Modules", "A module operation is still running at shutdown — tearing the modules down anyway.");
        try
        {
            foreach (var slot in _slots)
            {
                try { await StopSlotAsync(slot); }
                catch (Exception ex) { Log.Warn("Modules", $"{slot.Name}: shutdown reported {ex.Message}"); }
            }
        }
        finally { if (got) _gate.Release(); }

        PublishState();
        Log.Info("Modules", "Module supervisor stopped.");
    }

    private static string Details(Exception ex)
    {
        var sb = new System.Text.StringBuilder();
        for (var e = ex; e != null; e = e.InnerException)
        {
            sb.Append(e.GetType().FullName).Append(": ").Append(e.Message).Append('\n');
            if (!string.IsNullOrEmpty(e.StackTrace)) sb.Append(e.StackTrace).Append('\n');
            if (e.InnerException != null) sb.Append("  ---> caused by:\n");
        }
        return sb.ToString().TrimEnd();
    }
}
