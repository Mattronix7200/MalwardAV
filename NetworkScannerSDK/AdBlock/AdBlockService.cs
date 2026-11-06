namespace Malward.NetworkScanner.AdBlock;

public sealed class AdBlockVerdict
{
    public bool Blocked;
    public string Rule = "";
    public string List = "";
    public string Detection = "Ads.Blocked";
    public string? Redirect;
}

public sealed class AdBlockService : IDisposable
{
    private readonly object _lock = new();
    private AdRuleStore? _store;
    private AdListState _state = new();
    private CancellationTokenSource? _cts;
    private FileSystemWatcher? _watcher;
    private Timer? _reloadDebounce;
    private HashSet<string> _bypass = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan UpdateInterval = TimeSpan.FromHours(12);

    public bool Enabled { get; private set; }
    public bool HttpFiltering { get; private set; }
    public AdCosmeticOptions Cosmetics { get; } = new();
    public AdRuleStore? Store => _store;
    public string GenericCss => _store?.GenericCss ?? "";
    public AdRuleStats Stats => _store?.Stats ?? new AdRuleStats();
    public bool IsLoaded => _store?.IsLoaded == true;
    public AdListState State { get { lock (_lock) return _state; } }

    public long BlockedRequests;
    public long CosmeticInjections;

    public void Start(bool enabled, bool httpFiltering)
    {
        Enabled = enabled;
        HttpFiltering = httpFiltering;
        if (!enabled) { Stop(); return; }

        lock (_lock)
        {
            _state = AdListStore.LoadState();
            RebuildBypass();
        }

        var zegar = System.Diagnostics.Stopwatch.StartNew();
        LoadStore();
        zegar.Stop();

        if (IsLoaded)
            Log.Info("AdBlock", $"Filter engine ready in {zegar.ElapsedMilliseconds} ms from the "
                              + "database already on disk — no waiting for downloads.");
        else
            Log.Info("AdBlock", "No rule database on disk yet — the lists are being downloaded and "
                              + "compiled in the background. Address and DNS blocking already work; "
                              + "hiding rules and scriptlets start once the build finishes.");

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        _ = MaintainAsync(_cts.Token);
        WatchSubscriptions();
    }

    private void WatchSubscriptions()
    {
        try
        {
            Directory.CreateDirectory(AdListStore.RootDir);
            _watcher?.Dispose();
            _watcher = new FileSystemWatcher(AdListStore.RootDir,
                Path.GetFileName(AdListStore.StatePath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                EnableRaisingEvents = true,
            };
            _watcher.Changed += (_, _) => ScheduleReload();
            _watcher.Created += (_, _) => ScheduleReload();
            _watcher.Renamed += (_, _) => ScheduleReload();
        }
        catch (Exception ex)
        {
            Log.Warn("AdBlock", $"Cannot watch {AdListStore.StatePath}: {ex.Message}");
        }
    }

    private void ScheduleReload()
    {
        _reloadDebounce?.Dispose();
        _reloadDebounce = new Timer(_ => _ = ReloadFromDiskAsync(), null, 1500, Timeout.Infinite);
    }

    private async Task ReloadFromDiskAsync()
    {
        try
        {
            if (AdListStore.IsOwnWrite(AdListStore.ReadStateRaw())) return;

            var fresh = AdListStore.LoadState();
            bool forced = fresh.LastUpdateUnix == 0;
            lock (_lock) { _state = fresh; RebuildBypass(); }
            Log.Info("AdBlock", forced
                ? "Subscriptions changed — refreshing lists from their servers."
                : "Subscriptions changed — rebuilding the rule database.");
            await RebuildAsync(fresh, forced, null, CancellationToken.None);
        }
        catch (Exception ex) { Log.Warn("AdBlock", $"Reload after a change failed: {ex.Message}"); }
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        _cts = null;
        try { _watcher?.Dispose(); } catch { }
        _watcher = null;
        try { _reloadDebounce?.Dispose(); } catch { }
        _reloadDebounce = null;
        lock (_lock) { _store?.Dispose(); _store = null; }
    }

    public void Dispose() => Stop();

    private void UnloadStore()
    {
        lock (_lock)
        {
            _store?.Dispose();
            _store = null;
        }
        ReleaseMemory();
    }

    private async Task<AdRuleStats?> RebuildAsync(AdListState state, bool forceDownload,
                                                  Action<string>? progress, CancellationToken ct)
    {
        bool unloaded = false;
        try
        {
            return await AdListStore.RefreshAsync(state, forceDownload, progress, ct,
                beforePublish: () => { UnloadStore(); unloaded = true; });
        }
        finally { if (unloaded || !IsLoaded) LoadStore(); }
    }

    private void LoadStore()
    {
        try
        {
            var fresh = new AdRuleStore(AdListStore.DatabaseDir);
            fresh.Load();
            lock (_lock)
            {
                _store?.Dispose();
                _store = fresh;
            }
            if (fresh.IsLoaded)
                Log.Info("AdBlock", $"Rule database loaded: {fresh.Stats.BlockDomains} browser domains, "
                                    + $"{fresh.Stats.BlockDomainsDns} DNS domains, "
                                    + $"{fresh.Stats.NetworkRules} URL rules, "
                                    + $"{fresh.Stats.CosmeticGeneric + fresh.Stats.CosmeticSpecific} hiding rules, "
                                    + $"{fresh.Stats.Scriptlets} scriptlets.");
            ReleaseMemory();
        }
        catch (Exception ex) { Log.Warn("AdBlock", $"Failed to load the rule database: {ex.Message}"); }
    }

    private const long WorkingSetCeilingBytes = 32L * 1024 * 1024;

    private static void ReleaseMemory()
    {
        try
        {
            long freed = Malward.Engine.Util.MemoryTrim.AfterLongRun();
            if (freed > 4 * 1024 * 1024)
                Log.Debug("AdBlock", $"Working set trimmed by {freed / 1024 / 1024} MB.");
        }
        catch { }
    }

    private static void ReleaseMemoryIfLarge()
    {
        try
        {
            using var self = System.Diagnostics.Process.GetCurrentProcess();
            self.Refresh();
            if (self.WorkingSet64 > WorkingSetCeilingBytes) ReleaseMemory();
        }
        catch { }
    }

    private async Task MaintainAsync(CancellationToken ct)
    {
        try
        {
            var state = State;
            if (AdListStore.NeedsRebuild(state) || !IsLoaded)
            {
                var zegar = System.Diagnostics.Stopwatch.StartNew();
                await RebuildAsync(state, forceDownload: false, null, ct);
                zegar.Stop();
                Log.Info("AdBlock", $"First build finished after {zegar.Elapsed.TotalSeconds:F0} s "
                                  + $"({state.Lists.Count(l => l.Enabled)} lists). "
                                  + $"Engine ready: {IsLoaded}.");
            }

            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMinutes(1), ct);
                if (AdListStore.UpdateDue(State, UpdateInterval))
                {
                    await RebuildAsync(State, forceDownload: true, null, ct);
                    continue;
                }
                ReleaseMemoryIfLarge();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Warn("AdBlock", $"Update loop stopped: {ex.Message}"); }
    }

    public Task<AdRuleStats?> RefreshNowAsync(bool forceDownload, Action<string>? progress = null)
        => RebuildAsync(State, forceDownload, progress, CancellationToken.None);

    public void ApplySubscriptions(AdListState state)
    {
        lock (_lock)
        {
            _state = state;
            RebuildBypass();
        }
        AdListStore.SaveState(state);
    }

    private void RebuildBypass()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in AdListCatalog.Hosts()) set.Add(h);
        foreach (var s in _state.Lists)
            if (s.IsUrl)
                try { set.Add(new Uri(s.Url).Host); } catch { }
        foreach (var h in StaticBypass) set.Add(h);
        _bypass = set;
    }

    private static readonly string[] StaticBypass =
    {
        "localhost", "127.0.0.1",
        "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com",
        "login.microsoftonline.com", "login.live.com", "login.windows.net",
        "accounts.google.com", "appleid.apple.com",
        "pkobp.pl", "ipko.pl", "mbank.pl", "ing.pl", "santander.pl", "bankmillennium.pl",
        "aliorbank.pl", "pekao.com.pl", "credit-agricole.pl", "bnpparibas.pl", "citibank.pl",
        "paypal.com", "stripe.com", "przelewy24.pl", "payu.pl", "blik.com",
        "gov.pl", "epuap.gov.pl", "obywatel.gov.pl", "podatki.gov.pl", "zus.pl",
    };

    public bool IsBypassed(string host)
    {
        if (string.IsNullOrEmpty(host)) return true;
        var h = AdRuleHash.NormalizeHost(host);
        var set = _bypass;
        foreach (var suffix in AdRuleHash.Suffixes(h))
            if (set.Contains(suffix)) return true;
        return false;
    }

    public bool ShouldInspect(string host)
        => Enabled && HttpFiltering && IsLoaded && !IsBypassed(host)
           && !AdCaptcha.IsChallengeHost(host);

    public bool CanInspectForThreats(string host)
        => !IsBypassed(host) && !AdCaptcha.IsChallengeHost(host);

    public bool IsBlockedDomainForDns(string host, out string listName)
    {
        listName = "";
        var store = _store;
        if (!Enabled || store == null || !store.IsLoaded) return false;

        return store.IsBlockedDomain(host, dnsLayer: true, withStubHosts: !HttpFiltering, out listName);
    }

    public bool IsAllowedDomain(string host)
    {
        var store = _store;
        return store != null && store.IsLoaded && store.IsAllowedDomain(host);
    }

    public List<AdReplaceRule> ReplaceRulesFor(string url, string host, string? docHost,
                                               AdResourceType type)
    {
        var store = _store;
        if (store == null || !store.IsLoaded) return new List<AdReplaceRule>();
        try { return store.GetReplaceRules(url, host, docHost, type); }
        catch { return new List<AdReplaceRule>(); }
    }

    public AdBlockVerdict Decide(string url, string host, string? docHost, AdResourceType type)
    {
        var verdict = new AdBlockVerdict();
        var store = _store;
        if (!Enabled || store == null || !store.IsLoaded) return verdict;
        if (IsBypassed(host)) return verdict;
        if (AdCaptcha.IsChallenge(url, host)) return verdict;

        if (store.ShouldBlockRequest(url, host, docHost, type, out var rule, out var redirect, out var list))
        {
            verdict.Blocked = true;
            verdict.Rule = rule;
            verdict.List = list;
            verdict.Redirect = redirect;
            verdict.Detection = DetectionName(list);
            Interlocked.Increment(ref BlockedRequests);
        }
        return verdict;
    }

    private static string DetectionName(string list)
    {
        if (string.IsNullOrEmpty(list)) return "Ads.Blocked";
        var l = list.ToLowerInvariant();
        if (l.Contains("phish")) return "Phishing.List";
        if (l.Contains("malware") || l.Contains("badware") || l.Contains("urlhaus")
            || l.Contains("botnet") || l.Contains("ransom")) return "Malware.List";
        if (l.Contains("scam") || l.Contains("fraud") || l.Contains("fake")) return "Scam.List";
        if (l.Contains("track") || l.Contains("privacy") || l.Contains("spy")
            || l.Contains("telemetr")) return "Tracking.Blocked";
        if (l.Contains("coin") || l.Contains("crypto") || l.Contains("mining")) return "CoinMiner.List";
        return "Ads.Blocked";
    }
}
