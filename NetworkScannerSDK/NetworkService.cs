namespace Malward.NetworkScanner;

public sealed class NetworkService : IAsyncDisposable
{
    private readonly NetworkConfig _config;
    private readonly UrlBlocklist _blocklist;

    private readonly UrlBlocklist _urlCache;
    private readonly ServerClient _server;
    private readonly ActivityReporter _activity;

    private BotIpBlocklist? _botIps;
    private readonly SystemDnsManager _dnsMgr = new();
    private DnsProxy? _proxy;
    private BlockPageServer? _blockPage;
    private RootCaManager? _rootCa;
    private LeafCertCache? _leaves;
    private TlsBlockServer? _tlsBlock;
    private ConnectionMonitor? _connMon;

    private Timer? _updateTimer;
    private static readonly string UrlsVdebTarget = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "urls.vdeb");

    private static readonly string UrlCacheTarget = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "vps-ex03.vdeb");

    private volatile bool _stopping;

    public NetworkService(NetworkConfig config)
    {
        _config    = config;

        _blocklist = new UrlBlocklist(lowMemory: config.LowMemory, deferred: config.IsCloudUrlOnly);

        _urlCache = new UrlBlocklist(UrlCacheTarget,
                                     lowMemory: config.LowMemory || config.IsCloudUrlOnly,
                                     deferred: false, exclusivePath: true);
        _server    = new ServerClient();
        _activity  = new ActivityReporter();

        _dnsMgr.ShieldEnabled = () => _config.Enabled && !_stopping;
    }

    public void Start()
    {
        if (!_config.Enabled)
        {
            Log.Info("Service", "Network shield DISABLED in configuration — nothing is started.");

            if (SystemDnsManager.HasPendingSnapshot())
                _ = Task.Run(async () => { try { await _dnsMgr.RecoverStaleAsync(); } catch { } });
            return;
        }

        if (_config.AutoSetSystemDns && SystemDnsManager.HasPendingSnapshot())
        {
            try { _dnsMgr.RecoverStaleAsync().GetAwaiter().GetResult(); }
            catch (Exception ex) { Log.Error("Service", $"DNS self-repair at startup: {ex.Message}"); }
        }

        _activity.Start();

        _blocklist.MaybeReload();
        _urlCache.MaybeReload();

        _blockPage = new BlockPageServer();
        _blockPage.Start();

        try
        {
            _rootCa = new RootCaManager();
            _rootCa.EnsureInstalled();
            if (_rootCa.IsAvailable)
            {
                _leaves = new LeafCertCache(_rootCa);
                _tlsBlock = new TlsBlockServer(_leaves, host => _blockPage!.LookupBlockInfo(host));
                _tlsBlock.Start();
            }
        }
        catch (Exception ex)
        {
            Log.Warn("Service", $"TLS block server init failed: {ex.Message}");
        }

        _botIps = new BotIpBlocklist(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Malward", "data", "vps-ex01.vdeb"));

        _proxy = new DnsProxy(_config, _blocklist, _server, _activity, _blockPage, _botIps, _urlCache);
        _proxy.Start();

        _connMon = new ConnectionMonitor(_config, _activity, _blockPage, _botIps);
        _connMon.Start();

        if (_config.AutoSetSystemDns && _proxy.IsRunning && _proxy.ActivePort == DnsProxy.DefaultPort)
        {
            _dnsMgr.ProxyAlive = () => _proxy is { IsRunning: true }
                                       && _proxy.ActivePort == DnsProxy.DefaultPort;
            _ = Task.Run(async () =>
            {
                try { await _dnsMgr.ApplyAsync(); }
                catch (Exception ex) { Log.Error("Service", $"Auto-DNS apply failed: {ex.Message}"); }
            });
        }
        else if (_config.AutoSetSystemDns && _proxy.ActivePort != DnsProxy.DefaultPort)
        {
            Log.Warn("Service",
                $"Auto-DNS skipped — proxy is listening on port {_proxy.ActivePort}, " +
                "but the system always queries DNS on 53. Free port 53 (Dnscache) and restart the service.");

            _ = Task.Run(async () =>
            {
                try { await _dnsMgr.RecoverStaleAsync(); }
                catch (Exception ex) { Log.Error("Service", $"DNS rollback failed: {ex.Message}"); }
            });
        }

        bool haveDb = _blocklist.DeferredMode ? _blocklist.HasDatabaseFile : _blocklist.IsLoaded;
        _updateTimer = new Timer(_ => SafeUpdateUrls(),
            state: null,
            dueTime: haveDb ? TimeSpan.FromMinutes(5) : TimeSpan.FromSeconds(15),
            period: TimeSpan.FromHours(1));

        Log.Info("Service",
            $"Network shield started. " +
            (_blocklist.DeferredMode
                ? $"Database: deferred (cloud-only URL scanning), file {(_blocklist.HasDatabaseFile ? _blocklist.ActivePath : "not downloaded yet")} — loaded on first cloud outage. "
                : $"Database: {_blocklist.DomainCount:N0} domains ({_blocklist.LoadedPath ?? "none"}). ") +
            $"Mode: {_config.Mode}.");
    }

    private void SafeUpdateUrls()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                string profile = _config.GetServerProfileName();
                Log.Info("Update", $"Downloading urls-{profile}.vdeb from server…");
                bool ok = await _server.DownloadUrlsAsync(UrlsVdebTarget, profile);

                if (ok && _blocklist.DeferredMode)
                {
                    _blocklist.MaybeReload();
                    Log.Info("Update", $"urls-{profile}.vdeb downloaded (kept on disk — cloud-only URL scanning).");
                }
                else if (ok && _blocklist.MaybeReload())
                    Log.Info("Update", $"urls-{profile}.vdeb reloaded ({_blocklist.DomainCount:N0} domains).");
                else if (!ok)
                    Log.Warn("Update", $"Download of urls-{profile}.vdeb failed (server offline?). Using local copy.");

                if (await _server.DownloadUrlCacheAsync(UrlCacheTarget) && _urlCache.MaybeReload())
                    Log.Info("Update", $"vps-ex03.vdeb reloaded ({_urlCache.DomainCount:N0} cached URLs).");
            }
            catch (Exception ex) { Log.Warn("Update", $"update error: {ex.Message}"); }
        });
    }

    public async Task StopAsync()
    {
        _stopping = true;
        try { _updateTimer?.Dispose(); } catch { }
        _updateTimer = null;

        if (_config.AutoSetSystemDns)
        {
            try { await _dnsMgr.RestoreAsync(); } catch (Exception ex)
            { Log.Error("Service", $"Auto-DNS restore failed: {ex.Message}"); }
        }

        try { _connMon?.Stop(); } catch { }
        _connMon = null;
        try { _proxy?.Stop(); } catch { }
        _proxy = null;
        try { _tlsBlock?.Stop(); } catch { }
        _tlsBlock = null;
        try { _blockPage?.Stop(); } catch { }
        _blockPage = null;
        try { _activity.Stop(); } catch { }

        _botIps = null;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        try { _server.Dispose(); } catch { }
        try { _activity.Dispose(); } catch { }

        try { _blocklist.Dispose(); } catch { }
        try { _urlCache.Dispose(); } catch { }
    }
}
