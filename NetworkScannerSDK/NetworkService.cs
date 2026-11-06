using Malward.NetworkScanner.AdBlock;

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
    private readonly DohGuard _doh = new();
    private readonly DnsLeakGuard _dnsLeak = new();
    private readonly BrowserProxyGuard _browserProxy = new();
    private readonly QuicGuard _quic = new();
    private UrlFilterProxy? _httpFilter;
    private DnsProxy? _proxy;
    private BlockPageServer? _blockPage;
    private RootCaManager? _rootCa;
    private LeafCertCache? _leaves;
    private TlsBlockServer? _tlsBlock;
    private ConnectionMonitor? _connMon;
    private AdBlockService? _adBlock;

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
        _dnsMgr.OnStandDown = () =>
        {
            try { _dnsLeak.Remove(); } catch { }
            try { _browserProxy.Restore(); } catch { }
            try { _quic.Remove(); } catch { }
            try { _httpFilter?.Stop(); } catch { }
        };
    }

    public void Start()
    {
        if (!_config.Enabled)
        {
            Log.Info("Service", "Network shield DISABLED in configuration — nothing is started.");

            if (SystemDnsManager.HasPendingSnapshot())
                _ = Task.Run(async () => { try { await _dnsMgr.RecoverStaleAsync(); } catch { } });
            if (DohGuard.HasPendingSnapshot())
                _ = Task.Run(() => { try { _doh.Restore(); } catch { } });
            _ = Task.Run(() => { try { _dnsLeak.Remove(); } catch { } });
            if (QuicGuard.HasPendingMarker())
                _ = Task.Run(() => { try { _quic.Remove(); } catch { } });
            if (BrowserProxyGuard.HasPendingSnapshot())
                _ = Task.Run(() => { try { _browserProxy.Restore(); } catch { } });
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

        if (_config.AdBlockingEnabled)
        {
            _adBlock = new AdBlockService();
            _adBlock.Cosmetics.Cosmetic = _config.AdBlockCosmetic;
            _adBlock.Cosmetics.CosmeticGeneric = _config.AdBlockCosmeticGeneric;
            _adBlock.Cosmetics.Scriptlets = _config.AdBlockScriptlets;
            _adBlock.Cosmetics.YouTube = _config.AdBlockYouTube;
            _adBlock.Cosmetics.Stealth = _config.AdBlockStealth;
            _adBlock.Start(enabled: true, httpFiltering: _config.AdBlockHttpFilter && _config.HttpFilter);
        }

        AdoptManualUpstreamDns();

        _proxy = new DnsProxy(_config, _blocklist, _server, _activity, _blockPage, _botIps, _urlCache);
        _proxy.AttachAdBlock(_adBlock);
        _proxy.Start();

        if (_config.HttpFilter && _leaves != null)
        {
            _httpFilter = new UrlFilterProxy(_leaves, _activity, _blockPage,
                (host, path, inspected, ct) => _proxy!.VerdictForHttpAsync(host, path, inspected, ct),
                host => _proxy!.HasPathRules(host),
            (host, path) => _proxy!.PathVerdict(host, path));

            _httpFilter.AttachAdBlock(_adBlock);

            if (_httpFilter.Start(_config.HttpFilterPort))
            {
                _browserProxy.Apply(_httpFilter.ActivePort);
                if (_config.BlockQuic) _quic.Apply();
            }
            else
                StartHttpFilterRetry();
        }
        else if (BrowserProxyGuard.HasPendingSnapshot())
        {
            _browserProxy.Restore();
        }

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

            if (_config.BlockDoh)
                _ = Task.Run(() =>
                {
                    try { _doh.Apply(); }
                    catch (Exception ex) { Log.Error("Service", $"DoH policy apply failed: {ex.Message}"); }
                });

            if (_config.BlockForeignDns)
                _ = Task.Run(() =>
                {
                    try { _dnsLeak.Apply(_config.UpstreamDns); }
                    catch (Exception ex) { Log.Error("Service", $"foreign DNS block failed: {ex.Message}"); }
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

            if (DohGuard.HasPendingSnapshot())
                _ = Task.Run(() => { try { _doh.Restore(); } catch { } });
        }
        else if (DohGuard.HasPendingSnapshot())
        {
            _ = Task.Run(() => { try { _doh.Restore(); } catch { } });
        }

        bool haveDb = _blocklist.DeferredMode ? _blocklist.HasDatabaseFile : _blocklist.IsLoaded;
        if (ProfileChangedSinceLastDownload()) haveDb = false;
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

    private static readonly string ProfileMarkerPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "urls-profile.txt");

    private bool ProfileChangedSinceLastDownload()
    {
        try
        {
            var want = _config.GetServerProfileName();
            var have = File.Exists(ProfileMarkerPath) ? File.ReadAllText(ProfileMarkerPath).Trim() : "";
            if (string.Equals(want, have, StringComparison.OrdinalIgnoreCase)) return false;
            Log.Info("Update", $"URL database profile changed ({(have.Length > 0 ? have : "unknown")} -> {want}) "
                               + "— downloading it now instead of waiting for the next cycle.");
            return true;
        }
        catch { return false; }
    }

    private static void RememberProfile(string profile)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ProfileMarkerPath)!);
            File.WriteAllText(ProfileMarkerPath, profile);
        }
        catch { }
    }

    private void AdoptManualUpstreamDns()
    {
        try
        {
            if (!_config.AutoSetSystemDns) return;
            var manual = SystemDnsManager.DetectManualUpstream();
            if (string.IsNullOrWhiteSpace(manual)) return;
            if (string.Equals(manual, _config.UpstreamDns, StringComparison.Ordinal)) return;

            Log.Info("DnsMgr", $"This machine resolves through {manual}, set by hand — forwarding there "
                               + $"instead of {_config.UpstreamDns} so local and company names keep working.");
            _config.UpstreamDns = manual;
        }
        catch (Exception ex) { Log.Debug("DnsMgr", $"Adopting the manual DNS failed: {ex.Message}"); }
    }

    private Timer? _httpFilterRetry;

    private void StartHttpFilterRetry()
    {
        Log.Warn("HttpFilter", "The address filter could not take its port — the browser proxy policy "
                               + "stays as it is and the filter keeps retrying every 30 s.");
        _httpFilterRetry?.Dispose();
        _httpFilterRetry = new Timer(_ =>
        {
            if (_stopping || _httpFilter == null) return;
            try
            {
                if (_httpFilter.IsRunning) { StopHttpFilterRetry(); return; }
                if (!_httpFilter.Start(_config.HttpFilterPort)) return;
                _browserProxy.Apply(_httpFilter.ActivePort);
                Log.Info("HttpFilter", $"Address filter came up on 127.0.0.1:{_httpFilter.ActivePort}.");
                StopHttpFilterRetry();
            }
            catch (Exception ex) { Log.Debug("HttpFilter", $"retry: {ex.Message}"); }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    private void StopHttpFilterRetry()
    {
        try { _httpFilterRetry?.Dispose(); } catch { }
        _httpFilterRetry = null;
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
                if (ok) RememberProfile(profile);

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

        if (DohGuard.HasPendingSnapshot())
        {
            try { _doh.Restore(); } catch (Exception ex)
            { Log.Error("Service", $"DoH policy restore failed: {ex.Message}"); }
        }

        try { _dnsLeak.Remove(); } catch (Exception ex)
        { Log.Error("Service", $"removing the foreign DNS block failed: {ex.Message}"); }

        if (!_config.Enabled || !_config.BlockQuic)
        {
            try { _quic.Remove(); } catch { }
        }

        if (_config.Enabled)
        {
            Log.Info("Service", "Browser proxy policy left in place — the module is only restarting "
                              + "and a running browser would otherwise stop filtering until it is "
                              + "restarted. The PAC falls back to DIRECT while nothing is listening.");
        }
        else
        {
            try { _browserProxy.Restore(); } catch (Exception ex)
            { Log.Error("Service", $"restoring the browser proxy policy failed: {ex.Message}"); }
        }

        StopHttpFilterRetry();
        try { _httpFilter?.Stop(); } catch { }
        _httpFilter = null;

        try { _connMon?.Stop(); } catch { }
        _connMon = null;
        try { _adBlock?.Stop(); } catch { }
        _adBlock = null;
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
