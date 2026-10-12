using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Malward.AppGUI.Services;
using Microsoft.Web.WebView2.Core;
using MessageBox = System.Windows.MessageBox;
using Application = System.Windows.Application;

namespace Malward.AppGUI;

public partial class AppHost
{
    private EngineBridge? _engine;
    private SettingsBridge? _settings;
    private GuiSettingsStore? _guiSettings;
    private DbVersionStore? _dbVersions;
    private ScanStatsStore? _statsStore;
    private ScanHistoryStore? _historyStore;
    private ITray? _tray;
    private ResidentServiceController? _resident;
    private ResidentSettingsStore? _residentSettings;
    private HipsAlertWatcher? _hipsAlerts;
    private ResidentQuarantineStore? _residentQuarantine;
    private ResidentIpc? _residentIpc;
    private NetworkServiceController? _network;
    private NetworkSettingsStore? _networkSettings;
    private NetworkIpc? _networkIpc;
    private readonly BackupEngineClient _backupClient = new();
    private readonly BackupSettingsStore _backupSettings = new();
    private UiTimer? _backupSchedTimer;
    private bool _backupRunning;
    private System.Diagnostics.Process? _backupWatchProc;

    private ScanProgressForm? _miniScan;

    private bool _miniScanUserDismissed;

    private readonly bool _scannerEdition = IsScannerOnlyEdition();

    private readonly bool _fwAvailable = IsFwManagerAvailable();

    private Malward.FWManager.FirewallEventListener? _fwListener;
    private Malward.FWManager.TemporaryRuleManager? _fwTempRules;

    private string? _pendingScheduledScanMode;
    private readonly List<string> _pendingScheduledScanFolders = new();
    private UiTimer? _residentWatchdog;
    private UiTimer? _ipcTimer;
    private AlertForm? _alertAsk;
    private AlertForm? _alertAuto;
    private AssetPack? _assets;
    private CoreWebView2Environment? _webEnv;
    private string? _engineDir;

    private static readonly string _appDataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward");
    private CancellationTokenSource? _scanCts;
    private VerificationResult? _verify;
    private bool _bootPushed;

    private bool _scanActive;
    private string _scanTarget = "";
    private string _scanMode = "quick";
    private bool _runningMemoryScan;

    private string? _fsFollowupTarget;
    private string _fsFollowupMode = "quick";

    private List<string>? _fsFollowupFolders;

    private (long encrypted, long blocked, long safe, long cloud, long threats,
             long system, long skipped, long filesTotal) _scanPhaseTotals;
    private bool _updateInProgress;
    private UiTimer? _netTimer;
    private UiTimer? _autoUpdateTimer;
    private UiTimer? _trayHealthTimer;
    private static readonly HttpClient _netHttp = CreateNetHttp();

    private static readonly JsonSerializerOptions _jsCamel = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
    };

    private static HttpClient CreateNetHttp()
    {
        var h = Malward.Engine.Cloud.CertPinning.Handler(
            Malward.Engine.Config.Settings.DefaultServerCertPinSha256);
        return new HttpClient(h) { Timeout = TimeSpan.FromSeconds(2.5) };
    }

    public bool HostMode { get; set; }
    public Action? OnOpenUi;

    private void OpenUiOrRestore()
    {
        if (WebMode) { OpenInBrowser(); return; }
        if (HostMode && OnOpenUi != null) OnOpenUi();
        else _tray?.Restore();
    }

    public AppHost()
    {
    }

    private bool _initStarted;

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private ITray CreateTray()
    {
        if (WebMode) return new Win32Tray(TrayIconPath());
        return CreateWindowsFormsTray();
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private ITray CreateWindowsFormsTray() => _host!.CreateWindowsFormsTray();

    private static string? TrayIconPath()
    {
        try
        {
            var p = Path.Combine(AppContext.BaseDirectory, "Resources", "icon.ico");
            if (File.Exists(p)) return p;
            p = Path.Combine(AppContext.BaseDirectory, "icon.ico");
            if (File.Exists(p)) return p;
            return Environment.ProcessPath;
        }
        catch { return null; }
    }

    internal async System.Threading.Tasks.Task ShellLoadedAsync()
    {
        if (_initStarted) return;
        _initStarted = true;

        _progressTimer = new UiTimer { Interval = TimeSpan.FromMilliseconds(80) };
        _progressTimer.Tick += (_, _) => FlushScanProgress();
        _progressTimer.Start();

        var args = Environment.GetCommandLineArgs();
        _startHidden = args.Any(a => string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));

        if (HostMode) _startHidden = true;

        if (WebMode) _startHidden = true;

        int idx = Array.FindIndex(args, a => string.Equals(a, "--scheduled-scan", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
        {
            _startHidden = true;
            _pendingScheduledScanMode = (idx + 1 < args.Length) ? args[idx + 1] : "quick";
            for (int i = idx + 2; i < args.Length - 1; i++)
            {
                if (string.Equals(args[i], "--folder", StringComparison.OrdinalIgnoreCase))
                    _pendingScheduledScanFolders.Add(args[++i]);
            }
        }

        var scanArgs = new System.Collections.Generic.List<string>();
        for (int si = 0; si < args.Length - 1; si++)
            if (string.Equals(args[si], "--scan", StringComparison.OrdinalIgnoreCase))
                scanArgs.Add(args[si + 1]);
        if (scanArgs.Count > 0)
            ScanInbox.Append(scanArgs);
        if (_startHidden) Shell.HideToTray();

        if (!HostMode && !WebMode)
        {
            var revealFallback = new UiTimer { Interval = TimeSpan.FromSeconds(10) };
            revealFallback.Tick += (_, _) => { revealFallback.Stop(); RevealWindow(); };
            revealFallback.Start();
        }

        try
        {
            _tray = CreateTray();

            if (WebMode)
            {
                _tray.RestoreOverride = () => Ui.Send(() => OpenInBrowser());
                _tray.MenuEnabled = false;
            }
            _tray.OnOpen = () => Ui.Send(OpenUiOrRestore);
            _tray.OnScan = () => Ui.Send(() => { OpenUiOrRestore(); if (!HostMode) Navigate("#/scan/picker"); });
            _tray.OnQuarantine = () => Ui.Send(() => { OpenUiOrRestore(); if (!HostMode) Navigate("#/quarantine"); });
            _tray.OnUpdate = () => Ui.Send(() => { OpenUiOrRestore(); if (!HostMode) Navigate("#/update"); });

            if (HostMode) _tray.RestoreOverride = () => Ui.Send(() => OnOpenUi?.Invoke());
            _tray.OnExit = () => Ui.Send(() => { if (HostMode) Shell.Shutdown(); else TryExitWithConfirmation(); });

            _tray.GetIsDarkTheme = () => ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");
            _tray.OnToggleProtection = want => Ui.Send(() =>
            {
                if (_resident == null) return;
                _ = Task.Run(async () =>
                {
                    if (want) { SetResidentWanted(true);  await _resident.EnableAsync();  }
                    else      { SetResidentWanted(false); await _resident.DisableAsync(); }
                    Ui.Send(PushProtectionStatus);
                });
            });
            _tray.OnToggleNetworkProtection = want => Ui.Send(() =>
            {
                if (_network == null) return;
                _ = Task.Run(async () =>
                {
                    try { _networkSettings?.Merge(new JsonObject { ["enabled"] = want }); } catch { }
                    if (want) await _network.EnableAsync();
                    else      await _network.DisableAsync();
                    Ui.Send(PushProtectionStatus);
                });
            });

            _tray.OnQuickScanBg = () => Ui.Send(StartQuickScanInBackground);
            _tray.OnUpdateBg    = () => Ui.Send(StartUpdateInBackground);

            _tray.OnFullScan   = () => Ui.Send(() => { _tray.Restore(); PostToJs("tray.scan", new { mode = "full" }); });
            _tray.OnCustomScan = () => Ui.Send(() => { _tray.Restore(); PostToJs("tray.scan", new { mode = "custom" }); });

            _tray.OnToggleBackup = want => Ui.Send(() =>
            {
                BackupSetEnabled(want);
                SyncWatchProcess();
                PushProtectionStatus();
                PostToJs("backup.status.refresh", new { });
            });
            _tray.OnToggleSnapshots = want => Ui.Send(() =>
            {
                try { _backupSettings.Merge(new JsonObject { ["on_file_change"] = want }); } catch { }
                SyncWatchProcess();
                PushProtectionStatus();
                PostToJs("backup.status.refresh", new { });
            });
            _tray.OnToggleRemovable = want => Ui.Send(() =>
            {
                try { _residentSettings?.Merge(new JsonObject { ["scan_removable"] = want }); } catch { }
                PushProtectionStatus();
                PostToJs("resident.removable.state", new { enabled = want });
            });
        }
        catch { }

        try
        {
            _assets = LoadAssetPack();
            byte[]? slownikEnWstepny = null;
            _assets?.TryGet("i18n/en.json", out slownikEnWstepny);
            Loc.Init(slownikEnWstepny, Loc.ReadLang(_appDataDir));
            if (_assets != null)
            {
                _tray?.ApplyBusyFrames(n => _assets.TryGet("assets/" + n, out var d) ? d : null);
                _tray?.ApplyMenuLogo(n  => _assets.TryGet("assets/" + n, out var d) ? d : null);
                _tray?.ApplyMenuIcons(n => _assets.TryGet("assets/" + n, out var d) ? d : null);
                _tray?.ApplyHealthIcons(n => _assets.TryGet("assets/" + n, out var d) ? d : null);
            }

            if (!await InitWebViewAsync()) return;

            _verify = FileVerification.Verify();
            if (_verify.HasCritical)
            {
                ShowCriticalReinstall(_verify);
                return;
            }
            _engineDir = _verify.EngineDir!;

            if (MustAbortStartForEnvironment(_engineDir)) return;
            MigrateGuiData(_engineDir);
            _engine = new EngineBridge(_verify.MalscanPath!);

            _settings = new SettingsBridge(_appDataDir);

            SettingsBridge.UseProfileDefaults(DefaultProfileSection("scanner"));

            try { _settings.Sanitize(); } catch { }
            _guiSettings = new GuiSettingsStore(_appDataDir);
            _dbVersions = new DbVersionStore(_appDataDir);
            _statsStore = new ScanStatsStore(Path.Combine(_appDataDir, "data", "scan-stats.json"));
            _historyStore = new ScanHistoryStore(_appDataDir);

            var rsExe = ResidentServiceController.FindShieldHost();
            if (rsExe != null) _resident = new ResidentServiceController(rsExe);
            _residentSettings = new ResidentSettingsStore(_appDataDir);
            _residentQuarantine = new ResidentQuarantineStore(_appDataDir);
            _residentIpc = new ResidentIpc(_appDataDir);

            StartScanRequestPoller();

            if (!_scannerEdition)
            {
                StartResidentWatchdog();
                StartIpcPoller();
                StartTrayHealthTimer();
                HookEventCentre();
                StartHipsAlerts();
            }
            StartWebUiIfRequested();

            CleanupFinishedUpdate();

            StartBackgroundScan();

            var netExe = NetworkServiceController.FindNetmonitor();
            if (netExe != null) _network = new NetworkServiceController(netExe);
            _networkSettings = new NetworkSettingsStore(_appDataDir);
            _networkIpc = new NetworkIpc(_appDataDir);

            SeedDefaultProfileOnFirstRun();

            var bkExe = BackupServiceController.FindBkmonitor();
            if (bkExe != null)
            {
                _ = Task.Run(async () =>
                {
                    try { await BackupServiceController.CleanupLegacyAsync(); } catch { }

                    try { await RunBootBackupOnceAsync(); } catch { }
                    Ui.Send(() =>
                    {
                        StartBackupScheduler();
                        SyncWatchProcess();
                    });
                });
            }
            else
            {
                PostToJs("engine.log", new { level = "warn",
                    msg = "BackupEngine: nie znaleziono bkmonitor.exe (kopia zapasowa nieaktywna)" });
            }

            if (bkExe != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromMinutes(5));
                        await RunFirstRunPrebackupAsync((_, __) => { });
                    }
                    catch { }
                });
            }

            ReconcileGuiAutostart();
            HookEngineEvents();

            if (WebMode)
            {
                _bootPushed = true;
                await PushInitialState();
                StartIdleMemoryTrim();
                if (!string.IsNullOrEmpty(_pendingScheduledScanMode))
                {
                    var trybSkanu = _pendingScheduledScanMode;
                    _pendingScheduledScanMode = null;
                    Ui.Send(() => StartScheduledScan(trybSkanu, _pendingScheduledScanFolders.ToList()));
                }
                return;
            }

            await ShowWebViewPageAsync();
        }
        catch (Exception ex)
        {
            CrashLog.Write("gui-init", ex, null);
        }
    }

    private const uint WM_DROPFILES = 0x0233;
    private const uint WM_COPYDATA = 0x004A;
    private const uint WM_COPYGLOBALDATA = 0x0049;
    private const uint MSGFLT_ALLOW = 1;

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct CHANGEFILTERSTRUCT
    {
        public uint cbSize;
        public uint ExtStatus;
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, uint msg, uint action,
        ref CHANGEFILTERSTRUCT changeInfo);

    internal static List<string> PathsFromDrop(System.Windows.IDataObject? data)
    {
        var wynik = new List<string>();
        try
        {
            if (data?.GetDataPresent(System.Windows.DataFormats.FileDrop) != true) return wynik;
            if (data.GetData(System.Windows.DataFormats.FileDrop) is not string[] dropped) return wynik;
            foreach (var p in dropped)
                if (!string.IsNullOrWhiteSpace(p) && File.Exists(p)) wynik.Add(p);
        }
        catch { }
        return wynik;
    }

    private string WebViewInitContext()
    {
        try
        {
            return $"[args={string.Join(' ', Environment.GetCommandLineArgs().Skip(1))}] "
                 + $"[pid={Environment.ProcessId}] [startHidden={_startHidden}] "
                 + $"[visible={Shell.IsVisible}] [hwnd=0x{WindowHandle.ToInt64():X}] ";
        }
        catch { return "[kontekst niedostepny] "; }
    }

    private EngineBridge.ScanProgress? _pendingProgress;
    private UiTimer? _progressTimer;

    private void FlushScanProgress()
    {
        var p = System.Threading.Interlocked.Exchange(ref _pendingProgress, null);
        if (p == null) return;
        PostToJs("scan.progress", new
        {
            done = p.Done, total = p.Total, pct = p.Pct,
            state = p.State, current = p.File,
        });
        TryUpdateMiniScanPopup((int)p.Pct, (int)p.Done, p.File);
    }

    private bool _uiReady;
    private int _webviewReloads;

    private void StartReadyWatchdog()
    {
        var wd = new UiTimer { Interval = TimeSpan.FromSeconds(12) };
        wd.Tick += (_, _) =>
        {
            if (_uiReady || _webviewReloads >= 2) { wd.Stop(); return; }
            _webviewReloads++;
            ReloadWebViewContent();
        };
        wd.Start();
    }

    private static IEnumerable<string> ModuleSearchDirs()
    {
        yield return AppContext.BaseDirectory;
        string? d = null;
        try { d = Services.EngineLocator.GuiExeDir; } catch { }
        if (!string.IsNullOrEmpty(d)) yield return d!;
        try { d = Services.EngineLocator.EngineDir(); } catch { d = null; }
        if (!string.IsNullOrEmpty(d)) yield return d!;
    }

    private static bool ModuleExists(string fileName)
    {
        foreach (var d in ModuleSearchDirs())
        {
            try { if (!string.IsNullOrEmpty(d) && File.Exists(Path.Combine(d, fileName))) return true; }
            catch { }
        }
        return false;
    }

    private static bool SandboxHelperAvailable()
    {
        try
        {
            foreach (var d in ModuleSearchDirs())
            {
                if (string.IsNullOrEmpty(d)) continue;
                if (File.Exists(Path.Combine(d, "sandbox", "sbhelper", "SBHelper.exe"))) return true;
                if (File.Exists(Path.Combine(d, "sandbox", "SBHelper.exe"))) return true;
            }
        }
        catch { }
        return false;
    }

    private string EditionJson()
    {
        static string B(bool v) => v ? "true" : "false";

        string lang = "pl";
        try { lang = Loc.ReadLang(_appDataDir) == "en" ? "en" : "pl"; } catch { }

        return "{\"scannerOnly\":" + B(_scannerEdition) +
               ",\"lang\":\"" + lang + "\"" +
               ",\"modules\":{\"resident\":" + B(ModuleExists("mwshield.exe")) +
               ",\"network\":" + B(ModuleExists("netmonitor.exe")) +
               ",\"backup\":" + B(ModuleExists("bkmonitor.exe")) +
               ",\"firewall\":" + B(_fwAvailable) +
               ",\"sandbox\":" + B(SandboxHelperAvailable()) + "}}";
    }

    private static bool IsFwManagerAvailable()
    {
        try { return ModuleExists("Malward.FWManager.dll"); }
        catch { return true; }
    }

    private static bool IsScannerOnlyEdition()
    {
        try
        {
            string[] modules = { "Malward.FWManager.dll", "bkmonitor.exe", "netmonitor.exe", "mwshield.exe" };
            foreach (var m in modules)
                if (ModuleExists(m)) return false;
            return true;
        }
        catch { return false; }
    }

    private Microsoft.Web.WebView2.Core.CoreWebView2? _cw;

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private async Task<bool> InitWebViewAsync()
    {
        if (WebMode) return true;
        Microsoft.Web.WebView2.Core.CoreWebView2? cw = null;
        try
        {
                CreateWebViewControl();
                var userData = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Malward", "WebView2");
                Directory.CreateDirectory(userData);
                var env = await CoreWebView2Environment.CreateAsync(null, userData);
                _webEnv = env;
            try
                {
                    await WebView!.EnsureCoreWebView2Async(env);
                }
                catch (System.Runtime.InteropServices.COMException ex1)
                {
                    CrashLog.Write("WebView2Init.retry", ex1, WebViewInitContext());
                    await Task.Delay(500);
                    await WebView!.EnsureCoreWebView2Async(env);
                    CrashLog.Write("WebView2Init.retry", null, "second attempt succeeded");
                }

                cw = WebView!.CoreWebView2;

                try
                {
                    await cw.AddScriptToExecuteOnDocumentCreatedAsync(
                        "window.__MALWARD_EDITION__ = " + EditionJson() + ";");
                }
                catch { }

                cw.Settings.AreDevToolsEnabled = false;
                cw.Settings.AreDefaultContextMenusEnabled = false;
                cw.Settings.IsStatusBarEnabled = false;
                cw.Settings.AreBrowserAcceleratorKeysEnabled = false;
                cw.Settings.IsZoomControlEnabled = false;

                cw.ProcessFailed += OnWebViewProcessFailed;

                _assets = LoadAssetPack();

            byte[]? slownikEn = null;
                _assets?.TryGet("i18n/en.json", out slownikEn);
                Loc.Init(slownikEn, Loc.ReadLang(_appDataDir));
                if (_assets != null)
                {
                    cw.AddWebResourceRequestedFilter("https://malward.local/*",
                        CoreWebView2WebResourceContext.All);
                    cw.WebResourceRequested += OnWebResourceRequested;

                    _tray?.ApplyBusyFrames(name =>
                        _assets.TryGet("assets/" + name, out var d) ? d : null);

                _tray?.ApplyMenuLogo(name =>
                        _assets.TryGet("assets/" + name, out var d) ? d : null);

                _tray?.ApplyMenuIcons(name =>
                        _assets.TryGet("assets/" + name, out var d) ? d : null);

                _tray?.ApplyHealthIcons(name =>
                        _assets.TryGet("assets/" + name, out var d) ? d : null);
                }
                else
                {
                    var wwwroot = Path.Combine(AppContext.BaseDirectory, "assets");
                    cw.SetVirtualHostNameToFolderMapping(
                        "malward.local", wwwroot, CoreWebView2HostResourceAccessKind.Allow);
                }

                cw.WebMessageReceived += OnWebMessage;
            _cw = cw;
            return true;
        }
        catch (Exception ex)
        {
            CrashLog.Write("WebView2Init", ex, WebViewInitContext());
            if (WebView?.CoreWebView2 != null) return true;
            if (_startHidden || !Shell.IsVisible) { Shell.Shutdown(); return false; }
            Shell.Alert($"Błąd inicjalizacji WebView2:\n{ex}", "Malward");
            Shell.Shutdown();
            return false;
        }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private Task ShowWebViewPageAsync()
    {
        var cw = _cw;
            cw!.DOMContentLoaded += async (_, __) =>
            {
                if (_bootPushed) return;
                _bootPushed = true;
                await PushInitialState();

                if (!string.IsNullOrEmpty(_pendingScheduledScanMode))
                {
                    var mode = _pendingScheduledScanMode;
                    _pendingScheduledScanMode = null;
                    Ui.Send(() => StartScheduledScan(mode, _pendingScheduledScanFolders.ToList()));
                }
            };

            WebView!.Source = new Uri("https://malward.local/index.html");
            StartReadyWatchdog();

            if (HostMode || _startHidden) SetWebViewBackground(true);
        return Task.CompletedTask;
    }

    private void OnWebViewProcessFailed(object? sender, CoreWebView2ProcessFailedEventArgs e)
    {
        Ui.Post(() =>
        {
            try
            {
                PostToJs("engine.log", new { level = "warn",
                    msg = $"WebView2 ProcessFailed: {e.ProcessFailedKind} — przeładowuję GUI." });
            }
            catch { }
            if (_webviewReloads >= 4) return;
            _webviewReloads++;
            ReloadWebViewContent();
        });
    }

    private void ReloadWebViewContent()
    {
        _bootPushed = false;
        _uiReady = false;
        try { WebView?.CoreWebView2?.Reload(); }
        catch
        {
            try { WebView!.Source = new Uri("https://malward.local/index.html"); } catch { }
        }
    }

    private readonly List<ScanResultRecord> _currentScanResults = new();

    private readonly List<(string Location, string Reason)> _repairFailures = new();

    private sealed record ScanResultRecord(string Path, string Detection, string Source);

    private void HookEngineEvents()
    {
        if (_engine == null) return;
        _engine.OnProgress += p =>
        {
            System.Threading.Volatile.Write(ref _pendingProgress, p);
        };
        _engine.OnLine += l =>
        {
            if (l.Verdict == "MALWARE")
            {
                _statsStore?.IncDetections(1);
                lock (_currentScanResults)
                    _currentScanResults.Add(new ScanResultRecord(l.Path, l.Detection ?? "Malware", l.Source));
            }
            PostToJs("scan.line", new
            {
                verdict = l.Verdict, source = l.Source,
                detection = l.Detection, path = l.Path, error = l.Error,

                entry = l.ArchiveEntry,

                display = l.ArchiveDisplay
            });
        };

        _engine.OnSkip += s =>
        {
            if (s.Category is "system" or "skipped") return;

            PostToJs("scan.skip", new
            {
                category = s.Category,
                path = s.Path,
                source = s.Source,
                reason = s.Reason
            });
        };
        _engine.OnDone += s =>
        {
            _statsStore?.AddFromScan(s.FilesTotal, s.Cloud);

            bool isMidPhase = _fsFollowupTarget != null;

            if (isMidPhase)
            {
                _scanPhaseTotals.encrypted += s.Encrypted;
                _scanPhaseTotals.blocked   += s.Blocked;
                _scanPhaseTotals.safe      += s.Safe;
                _scanPhaseTotals.cloud     += s.Cloud;
                _scanPhaseTotals.threats   += s.Threats;
                _scanPhaseTotals.system    += s.System;
                _scanPhaseTotals.skipped   += s.Skipped;
                _scanPhaseTotals.filesTotal += s.FilesTotal;

                var fsTarget = _fsFollowupTarget!;
                var fsMode = _fsFollowupMode;
                var fsFolders = _fsFollowupFolders;
                _fsFollowupTarget = null;
                _fsFollowupFolders = null;
                _scanActive = true;
                _scanStartedUtc = DateTime.UtcNow;
                _scanTarget = fsFolders?.Count > 1 ? string.Join(", ", fsFolders) : fsTarget;
                _scanMode = fsMode;
                _tray?.SetBusy(BusyKind.Scan);
                PostScanStarted(_scanTarget, fsMode);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        if (fsFolders != null && fsFolders.Count > 1)
                            await RunFoldersAsOneScanAsync(fsTarget, fsFolders,
                                                           _scanCts?.Token ?? CancellationToken.None);
                        else
                            await _engine!.RunScanAsync(fsTarget, _scanCts?.Token ?? CancellationToken.None);
                    }
                    catch (Exception ex)
                    { PostToJs("engine.log", new { level = "error", msg = $"scan: {ex.Message}" }); }
                    finally { _scanActive = false; _tray?.SetBusy(BusyKind.None); TrimMemoryNow("scan"); }
                });
                return;
            }

            var combined = (
                encrypted: _scanPhaseTotals.encrypted + s.Encrypted,
                blocked:   _scanPhaseTotals.blocked   + s.Blocked,
                safe:      _scanPhaseTotals.safe      + s.Safe,
                cloud:     _scanPhaseTotals.cloud     + s.Cloud,
                threats:   _scanPhaseTotals.threats   + s.Threats,
                system:    _scanPhaseTotals.system    + s.System,
                skipped:   _scanPhaseTotals.skipped   + s.Skipped,
                filesTotal:_scanPhaseTotals.filesTotal+ s.FilesTotal
            );
            _scanPhaseTotals = default;
            List<ScanResultRecord> results;
            lock (_currentScanResults)
            {
                results = _currentScanResults.ToList();
                _currentScanResults.Clear();
            }

            int historyThreats = (int)Math.Max(combined.threats, results.Count);
            _historyStore?.Append(new ScanHistoryEntry(
                UnixTimeSec: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Target: _scanTarget, Mode: _scanMode,
                FilesTotal: combined.filesTotal, Threats: historyThreats, Blocked: combined.blocked,
                System: combined.system, Encrypted: combined.encrypted,
                Time: s.TimeText ?? "", Bytes: s.BytesText ?? "",
                Detections: results.Select(r => new HistoryDetection(r.Path, r.Detection, r.Source)).ToList()));

            var stats = _statsStore?.Read() ?? new ScanStatsData(0, 0, 0);
            _scanActive = false;
            _tray?.SetBusy(BusyKind.None);

            List<(string Location, string Reason)> regFails;
            lock (_repairFailures) { regFails = _repairFailures.ToList(); _repairFailures.Clear(); }
            if (regFails.Count > 0)
                PostToJs("repair.failures", new { items = regFails.Select(f => new { location = f.Location, reason = f.Reason }) });

            int threatCount = (int)Math.Min(int.MaxValue, combined.threats);
            Ui.Send(() =>
            {
                if (_miniScan != null && !_miniScan.IsDisposed)
                {
                    _miniScan.SetMode(threatCount > 0
                        ? ScanProgressForm.Mode.FinishedThreats
                        : ScanProgressForm.Mode.FinishedClean,
                        subject: null, threats: threatCount);
                }
            });

            PostToJs("scan.done", new
            {
                encrypted = combined.encrypted, blocked = combined.blocked, safe = combined.safe,
                cloud = combined.cloud, threats = combined.threats, system = combined.system,
                skipped = combined.skipped, filesTotal = combined.filesTotal,
                time = s.TimeText, bytes = s.BytesText,

                totals = new
                {
                    scanned = stats.FilesScanned,
                    cloud = stats.CloudAnalyzed,
                    detections = stats.TotalDetections
                }
            });

            TriggerAutoSystemRepair();

            if (_deepCleanRebootPending)
            {
                _deepCleanRebootPending = false;
                ShowActionPopup(Loc.T("Zalecany restart komputera"),
                    "Głębokie czyszczenie i pełny skan zostały zakończone. Restart usunie ewentualne pozostałości działające w pamięci. Zrestartować teraz?",
                    "Uruchom ponownie", () => RebootSystem(),
                    "Nie teraz", () => { },
                    autoDismissSec: 0, iconPng: AssetBytes("fixedwindows.png"));
            }
        };
        _engine.OnUpdatePhase += ph =>
        {
            PostToJs("update.phase", new
            {
                phase = ph.Phase, status = ph.Status,
                bytes = ph.BytesDownloaded, total = ph.BytesTotal,
                pct = ph.OverallPct * 100,
                msg = ph.Message
            });
        };
        _engine.OnError += msg => PostToJs("engine.log", new { level = "error", msg });
        _engine.OnRawLine += line =>
        {
            PostToJs("engine.log", new { level = "info", msg = line });

            if (line.StartsWith("REGFAIL\t", StringComparison.Ordinal))
            {
                var loc = TsvField(line, "location=");
                var why = TsvField(line, "reason=");
                if (!string.IsNullOrEmpty(loc))
                    lock (_repairFailures) _repairFailures.Add((loc, why ?? ""));
            }
        };
    }

    private sealed record RepairFailure(
        [property: System.Text.Json.Serialization.JsonPropertyName("path")] string Path,
        [property: System.Text.Json.Serialization.JsonPropertyName("detection")] string Detection,
        [property: System.Text.Json.Serialization.JsonPropertyName("action")] string Action,
        [property: System.Text.Json.Serialization.JsonPropertyName("detail")] string Detail,
        [property: System.Text.Json.Serialization.JsonPropertyName("reboot")] bool Reboot,
        [property: System.Text.Json.Serialization.JsonPropertyName("needsAdmin")] bool NeedsAdmin);

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>Would running the repair as administrator plausibly change the outcome?</summary>
    /// <remarks>
    /// Files under Windows, System32, SysWOW64, WinSxS and Installer are owned by TrustedInstaller
    /// and a normal user cannot replace them, so the engine returns access-denied and the list just
    /// showed "errors 2". Those two facts - a protected location, or the words of a permission
    /// error - are what earns the UAC prompt; everything else (file in use, missing) would not be
    /// helped by elevation and must not pretend otherwise.
    /// </remarks>
    private static bool RepairNeedsElevation(string path, string? detail)
    {
        var d = (detail ?? "").ToLowerInvariant();
        if (d.Contains("access") && d.Contains("denied")) return true;
        if (d.Contains("odmowa") || d.Contains("odmow")) return true;
        if (d.Contains("unauthorizedaccess")) return true;

        string[] chronione =
        {
            @"\windows\system32\", @"\windows\syswow64\", @"\windows\winsxs\",
            @"\windows\installer\", @"\windows\servicing\", @"\program files\",
            @"\program files (x86)\",
        };
        var p = (path ?? "").ToLowerInvariant().Replace('/', '\\');
        return chronione.Any(k => p.Contains(k, StringComparison.Ordinal));
    }

    private async Task PushInitialState()
    {
        bool elevated = IsElevated();
        PostToJs("admin.status", new { elevated });

        if (_verify != null)
        {
            var ev = _verify.Issues.Select(i => new {
                file = i.File, message = i.Description, critical = i.Critical
            }).ToList();
            PostToJs("verify.issues", new { issues = ev });
        }

        var gs = _guiSettings?.Read() ?? new GuiSettings();
        PostToJs("gui.settings.data", new { theme = gs.Theme, lang = gs.Lang, autoUpdateEnabled = gs.AutoUpdateEnabled, autoUpdateMinutes = gs.AutoUpdateMinutes, lastUpdateCheckUnix = gs.LastUpdateCheckUnix, guiMode = gs.GuiMode, webUiUrl = WebUiUrl });

        try
        {
            var s = _settings!.Read();
            PostToJs("settings.data", new { settings = JsonNode.Parse(s.ToJsonString())! });
        }
        catch (Exception ex) { PostToJs("engine.log", new { level = "error", msg = $"settings load: {ex.Message}" }); }

        var stats = _statsStore?.Read() ?? new ScanStatsData(0, 0, 0);
        PostToJs("stats", new
        {
            scanned = stats.FilesScanned,
            cloud = stats.CloudAnalyzed,
            detections = stats.TotalDetections
        });

        if (!_scannerEdition) PushProtectionStatus();

        _ = Task.Run(async () =>
        {
            var (ok, error) = await CheckServerAsync(_settings?.Read());
            PostToJs("network.status", new { online = ok, error });
        });
        StartNetworkTimer();
        StartAutoUpdateTimer();

        await Task.CompletedTask;
    }

    private static async Task<(bool ok, string? error)> CheckServerAsync(JsonObject? settings)
    {
        var ip = settings?["server_ip"]?.GetValue<string>() ?? "83.168.95.69";
        int port = settings?["server_port"]?.GetValue<int>() ?? 5000;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2.5));
            var uri = new Uri($"https://{ip}:{port}/");
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            using var resp = await _netHttp.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);

            _ = resp.StatusCode;
            return (true, null);
        }
        catch (TaskCanceledException) { return (false, "timeout"); }
        catch (HttpRequestException ex) { return (false, ex.Message); }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private void StartNetworkTimer()
    {
        _netTimer?.Stop();
        _netTimer = new UiTimer { Interval = TimeSpan.FromSeconds(30) };
        _netTimer.Tick += async (_, _) =>
        {
            var (ok, err) = await CheckServerAsync(_settings?.Read());
            PostToJs("network.status", new { online = ok, error = err });
        };
        _netTimer.Start();
    }

    private void StartAutoUpdateTimer()
    {
        _autoUpdateTimer?.Stop();
        var gs = _guiSettings?.Read() ?? new GuiSettings();
        if (!gs.AutoUpdateEnabled) return;
        int minutes = Math.Max(15, gs.AutoUpdateMinutes);
        _autoUpdateTimer = new UiTimer { Interval = TimeSpan.FromMinutes(minutes) };
        _autoUpdateTimer.Tick += async (_, _) =>
        {
            try
            {
                var us = new UpdateService(_settings?.Read(), _engineDir!, _scannerEdition);
                await us.UpdateAllAsync(_ => { });
            }
            catch {  }
        };
        _autoUpdateTimer.Start();

        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(8));
            if (_updateInProgress || _scanActive) return;
            try
            {
                Ui.Send(() => PostToJs("engine.log", new { level = "info", msg = "Aktualizacja startowa: sprawdzanie baz…" }));
                var us = new UpdateService(_settings?.Read(), _engineDir!, _scannerEdition);
                await us.UpdateAllAsync(_ => { });
                Ui.Send(() => PostToJs("engine.version.refresh", new { }));
            }
            catch {  }
        });
    }

    private static void MigrateGuiData(string engineDir)
    {
        try
        {
            var srcDir = Path.Combine(engineDir, "data");
            var dstDir = Path.Combine(_appDataDir, "data");
            if (!Directory.Exists(srcDir)) return;
            Directory.CreateDirectory(dstDir);
            string[] files = { "scan-stats.json", "scan-history.json", "gui-settings.json" };
            foreach (var fn in files)
            {
                var src = Path.Combine(srcDir, fn);
                var dst = Path.Combine(dstDir, fn);
                if (File.Exists(src) && !File.Exists(dst))
                    try { File.Copy(src, dst); } catch { }
            }
        }
        catch {  }
    }

    private void ShowCriticalReinstall(VerificationResult verify)
    {
        var msg = Loc.T("Brak krytycznych plików Malward:") + "\n\n" +
                  string.Join("\n", verify.Issues.Where(i => i.Critical).Select(i => $"  • {i.File}: {i.Description}")) +
                  "\n\n" + Loc.T("Wymagana reinstalacja programu.");
        Shell.Alert(msg, Loc.T("Malward — brak komponentów"));
        Shell.Shutdown();
    }

    private void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            if (e.AdditionalObjects is { Count: > 0 })
            {
                var zUpuszczenia = new List<string>();
                foreach (var obiekt in e.AdditionalObjects)
                    if (obiekt is CoreWebView2File plik && !string.IsNullOrWhiteSpace(plik.Path))
                        zUpuszczenia.Add(plik.Path);

                var istniejace = zUpuszczenia.Where(File.Exists).ToList();
                if (istniejace.Count > 0)
                {
                    PostToJs("tools.analyze.dropped", new { paths = istniejace });
                }
                else
                {
                    CrashLog.Write("drop", null,
                        $"dropped objects carried no existing path; got {zUpuszczenia.Count} "
                        + $"of {e.AdditionalObjects.Count} object(s)");
                    PostToJs("toast", new { level = "warn",
                        msg = "Nie udało się odczytać ścieżek upuszczonych plików — użyj „Dodaj pliki”." });
                }
                return;
            }

            var json = e.WebMessageAsJson;
            if (string.IsNullOrEmpty(json)) return;
            var node = JsonNode.Parse(json) as JsonObject;
            if (node == null) return;
            var type = node["type"]?.GetValue<string>();
            if (string.IsNullOrEmpty(type)) return;
            HandleMessage(type!, node);
        }
        catch (Exception ex)
        {
            try { CrashLog.Write("bridge", ex, e.WebMessageAsJson); } catch { }
            try { PostToJs("engine.log", new { level = "error", msg = $"bridge: {ex.Message}" }); } catch { }
        }
    }

    private async void HandleMessage(string type, JsonObject data)
    {
        if (type.StartsWith("firewall.", StringComparison.Ordinal))
        {
            if (!_fwAvailable) return;
            if (HandleFirewallMessage(type, data)) return;
        }

        if (type.StartsWith("events.", StringComparison.Ordinal) && ObsluzKomunikatZdarzen(type, data))
            return;
        if (type.StartsWith("ui.", StringComparison.Ordinal) && ObsluzKomunikatInterfejsu(type))
            return;

        switch (type)
        {
            case "window.minimize":
                Shell.Minimize();
                break;
            case "window.close":

                if (_scannerEdition && !_scanActive && !_updateInProgress)
                {
                    TryExitWithConfirmation();
                }
                else if (_tray != null)
                {
                    Shell.HideToTray();
                    _tray.NotifyBalloon("Malward",
                        _scannerEdition
                            ? "Zadanie trwa w tle. Kliknij ikonę aby otworzyć."
                            : "Działa w tle. Kliknij ikonę aby otworzyć.");
                }
                else Shell.Shutdown();
                break;
            case "window.drag":
                Shell.StartDrag();
                break;
            case "app.exit":
                TryExitWithConfirmation();
                break;

            case "app.openUrl":
                {
                    var url = data["url"]?.GetValue<string>() ?? "";
                    if (Uri.TryCreate(url, UriKind.Absolute, out var uri)
                        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
                    {
                        try
                        {
                            Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
                        }
                        catch (Exception ex) { CrashLog.Write("openUrl", ex, url); }
                    }
                }
                break;

            case "tools.analyze.drop":
                {
                    var dropped = new List<string>();
                    try
                    {
                        if (data["paths"] is JsonArray arr)
                            foreach (var n in arr)
                            {
                                var p = n?.GetValue<string>();

                                if (!string.IsNullOrWhiteSpace(p) && File.Exists(p)) dropped.Add(p!);
                            }
                    }
                    catch (Exception ex) { CrashLog.Write("drop", ex, "parsing dropped paths"); }

                    if (dropped.Count > 0)
                    {
                        PostToJs("tools.analyze.dropped", new { paths = dropped });
                    }
                    else
                    {
                        var typy  = data["types"]?.GetValue<string>() ?? "";
                        var nazwy = data["names"]?.GetValue<string>() ?? "";
                        CrashLog.Write("drop", null,
                            $"drop carried no usable paths; dataTransfer types=[{typy}] names=[{nazwy}]");
                    }
                }
                break;

            case "ui.ready":

                _uiReady = true;
                Ui.Send(RevealWindow);

                if (WebMode)
                {
                    PostToJs("ui.mode", new { mode = "web" });
                    Ui.Post(() => { _ = PushInitialState(); });
                }
                break;

            case "ui.taskbar":
                {
                    var ts = data["state"]?.GetValue<string>() ?? "none";
                    var val = 0.0;
                    try { val = data["value"]?.GetValue<double>() ?? 0; } catch { }
                    Ui.Send(() =>
                    {
                        Shell.SetTaskbarProgress(ts, val);
                    });
                    break;
                }

            case "engine.scan":
                {
                    var target = data["target"]?.GetValue<string>() ?? "";
                    var mode = data["mode"]?.GetValue<string>() ?? "quick";
                    if (string.IsNullOrEmpty(target) || _engine == null) return;
                    if (_updateInProgress)
                    {
                        PostToJs("toast", new { msg = "Aktualizacja trwa — poczekaj na jej zakończenie." });
                        return;
                    }
                    if (_scanActive)
                    {
                        if (!QueueBackgroundScan(target, mode, data))
                            PostToJs("toast", new { msg = "Skanowanie już trwa — zobacz „Aktywne zadania skanera”." });
                        return;
                    }

                    bool memoryEnabled = false;
                    var jsPayloadMs = data["memoryScan"];
                    if (jsPayloadMs != null)
                    {
                        try { memoryEnabled = jsPayloadMs.GetValue<bool>(); } catch { }
                    }
                    else
                    {
                        try
                        {
                            var stj = _settings?.Read();
                            memoryEnabled = stj?["memory_scan"]?.GetValue<bool>() ?? false;
                        } catch { }
                    }

                    _scanCts?.Dispose();
                    _scanCts = new CancellationTokenSource();
                    var ct = _scanCts.Token;
                    _scanActive = true;
                    _scanStartedUtc = DateTime.UtcNow;
                    lock (_currentScanResults) _currentScanResults.Clear();
                    _tray?.SetBusy(BusyKind.Scan);

                    bool profileRun = mode is "quick" or "full";
                    if (memoryEnabled && mode != "memory" && !profileRun)
                    {
                        var pendingTargets = ExpandScanTargets(target, mode, data);
                        _fsFollowupTarget = pendingTargets[0];
                        _fsFollowupFolders = pendingTargets.Count > 1 ? pendingTargets : null;
                        _fsFollowupMode = mode;
                        _runningMemoryScan = true;
                        _scanTarget = "[procesy w pamięci]";
                        _scanMode = "memory";
                        PostScanStarted(_scanTarget, _scanMode);
                        _ = Task.Run(async () =>
                        {
                            try { await _engine!.RunScanMemoryAsync(ct); }
                            catch (Exception ex)
                            { PostToJs("engine.log", new { level = "error", msg = $"memory-scan: {ex.Message}" }); }
                            finally { _runningMemoryScan = false; }

                        }, ct);
                    }
                    else
                    {
                        string? profile = mode is "quick" or "full" ? mode : null;
                        string? planFile = null;
                        var targets = profile != null ? new List<string>() : ExpandScanTargets(target, mode, data);

                        if (profile == null && targets.Count > 1)
                        {
                            planFile = WriteCustomPlan(targets);
                            targets = new List<string>();
                        }

                        _scanTarget = profile == "full" ? "wszystkie dyski"
                                    : profile == "quick" ? "szybki skan"
                                    : targets.Count > 1 ? string.Join(", ", targets) : target;
                        _scanMode = mode;
                        PostScanStarted(_scanTarget, mode);
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                if (profile != null || planFile != null)
                                    await _engine!.RunScanAsync(target, ct, profile, planFile);
                                else
                                    foreach (var t in targets)
                                    {
                                        if (ct.IsCancellationRequested) break;
                                        await _engine!.RunScanAsync(t, ct);
                                    }
                            }
                            catch (Exception ex)
                            { PostToJs("engine.log", new { level = "error", msg = $"scan: {ex.Message}" }); }
                            finally
                            {
                                _scanActive = false; _tray?.SetBusy(BusyKind.None);
                                if (planFile != null) { try { File.Delete(planFile); } catch { } }
                            }
                        }, ct);
                    }
                    break;
                }
            case "backup.initial.answer":
                AnswerInitialBackup(data["choice"]?.GetValue<string>() ?? "background");
                break;

            case "backup.initial.cancel":
                CancelInitialBackup();
                break;

            case "scan.tasks.read":
                PostToJs("scan.tasks.data", new { items = CollectScanTasks() });
                break;

            case "scan.tasks.cancel":
                CancelScanTask(data["id"]?.GetValue<string>() ?? "");
                break;

            case "scan.tasks.attach":
                AttachToScanTask(data["id"]?.GetValue<string>() ?? "");
                break;

            case "engine.scan.cancel":
                if (_engine != null) await _engine.CancelScanAsync();
                _scanCts?.Cancel();
                _scanActive = false;
                _fsFollowupTarget = null;
                _fsFollowupFolders = null;
                _runningMemoryScan = false;
                _tray?.SetBusy(BusyKind.None);
                break;
            case "engine.repair.batch":
                {
                    if (_engine == null) return;
                    var items = data["items"]?.AsArray();
                    if (items == null) return;
                    var actions = items.Select(n => new {
                        path = n!["path"]?.GetValue<string>() ?? "",
                        action = n!["action"]?.GetValue<string>() ?? "quarantine",
                        detection = n!["detection"]?.GetValue<string>() ?? "",

                        entry = n!["entry"]?.GetValue<string>() ?? "",
                    }).Where(x => !string.IsNullOrEmpty(x.path)).ToList();
                    bool elevatedRun = data["elevated"]?.GetValue<bool>() ?? false;
                    _ = Task.Run(async () =>
                    {
                        int ok = 0, fail = 0, done = 0;
                        var exclusionsToAdd = new List<string>();
                        var failures = new List<RepairFailure>();

                        Dictionary<string, Services.EngineBridge.RepairOutcome>? elevatedResults = null;
                        if (elevatedRun)
                        {
                            try
                            {
                                elevatedResults = await _engine!.RunRepairBatchElevatedAsync(
                                    actions.Where(x => x.action is not ("ignore" or "exclude"))
                                           .Select(x => (x.action, x.path, x.detection, x.entry)).ToList());
                            }
                            catch (Exception ex)
                            {
                                CrashLog.Write("repair", ex, "elevated batch");
                            }
                        }

                        foreach (var a in actions)
                        {
                            try
                            {
                                Services.EngineBridge.RepairOutcome outcome;
                                if (elevatedResults != null && elevatedResults.TryGetValue(a.path, out var got))
                                    outcome = got;
                                else
                                    outcome = await _engine!.RunRepairDetailedAsync(
                                        a.action, a.path, a.detection, a.entry);

                                if (outcome.Ok) ok++;
                                else
                                {
                                    fail++;
                                    failures.Add(new RepairFailure(a.path, a.detection, a.action,
                                        outcome.Detail, outcome.RebootRequired,
                                        RepairNeedsElevation(a.path, outcome.Detail)));
                                }
                                if (a.action == "exclude") exclusionsToAdd.Add(a.path);
                            }
                            catch (Exception ex)
                            {
                                fail++;
                                failures.Add(new RepairFailure(a.path, a.detection, a.action,
                                    ex.Message, false, RepairNeedsElevation(a.path, ex.Message)));
                            }
                            done++;

                            PostToJs("repair.batchProgress", new { done, total = actions.Count });
                        }

                        if (exclusionsToAdd.Count > 0 && _settings != null)
                        {
                            try
                            {
                                var s = _settings.Read();
                                var ex = s["exceptions"]?.AsArray() ?? new JsonArray();
                                foreach (var p in exclusionsToAdd)
                                    if (!ex.Any(n => n!.GetValue<string>() == p)) ex.Add(p);
                                s["exceptions"] = ex;
                                _settings.Write((JsonObject)s);
                            }
                            catch { }
                        }
                        bool canElevate = !elevatedRun && !IsElevated()
                                          && failures.Any(f => (bool)f.GetType().GetProperty("needsAdmin")!
                                                                   .GetValue(f)!);
                        PostToJs("repair.batchResult", new { ok, fail, total = actions.Count,
                                                             failures, canElevate,
                                                             items = elevatedRun ? null : items });
                    });
                    break;
                }
            case "engine.scan.memory":
                {
                    if (_engine == null) return;
                    _scanCts?.Dispose();
                    _scanCts = new CancellationTokenSource();
                    _scanActive = true;
                    _scanStartedUtc = DateTime.UtcNow;
                    _scanMode = "memory";
                    _scanTarget = "[procesy w pamięci]";
                    _runningMemoryScan = true;
                    _tray?.SetBusy(BusyKind.Scan);
                    lock (_currentScanResults) _currentScanResults.Clear();
                    PostScanStarted(_scanTarget, _scanMode);
                    _ = Task.Run(async () =>
                    {
                        try { await _engine!.RunScanMemoryAsync(_scanCts.Token); }
                        catch (Exception ex)
                        { PostToJs("engine.log", new { level = "error", msg = $"memory-scan: {ex.Message}" }); }
                        finally { _runningMemoryScan = false; _scanActive = false; _tray?.SetBusy(BusyKind.None); TrimMemoryNow("scan"); }
                    }, _scanCts.Token);
                    break;
                }
            case "engine.scan.is-active":
                PostToJs("scan.is-active", new { active = _scanActive, target = _scanTarget, mode = _scanMode, token = _scanToken });
                break;
            case "engine.update":
                if (_engineDir == null) return;

                if (_scanActive || ResidentServiceController.ScanInProgress())
                {
                    PostToJs("update.done", new { success = false, error = "Skanowanie w toku — poczekaj na jego zakończenie." });
                    return;
                }
                if (_updateInProgress) return;
                _updateInProgress = true;
                _tray?.SetBusy(BusyKind.Update);
                _ = Task.Run(async () =>
                {
                    bool wasResidentRunning = false, wasNetworkRunning = false;
                    string? pauseError = null;
                    try
                    {
                        wasResidentRunning = _resident != null && _resident.IsRunning();
                        wasNetworkRunning  = _network  != null && _network.State()  == "running";
                        if (wasResidentRunning)
                        {
                            PostToJs("update.bytes", new { phase = "modules", status = "busy", msg = "Pauzuję ochronę rezydentną na czas aktualizacji…" });

                            try
                            {
                                var (sok, serr) = await _resident!.StopAsync();
                                if (!sok) pauseError = serr ?? "Nie udało się wstrzymać ochrony rezydentnej.";
                            }
                            catch (Exception ex) { pauseError = ex.Message; }
                        }
                        if (pauseError == null && wasNetworkRunning) { PostToJs("update.bytes", new { phase = "modules", status = "busy", msg = "Pauzuję osłonę sieciową na czas aktualizacji…" }); try { await _network!.StopAsync();  } catch { } }
                    }
                    catch (Exception ex) { pauseError ??= ex.Message; }

                    if (pauseError != null)
                    {
                        PostToJs("update.done", new { success = false, error = pauseError });
                        _tray?.SetBusy(BusyKind.None);
                        _updateInProgress = false;
                        try { if (_resident != null) await _resident.EnsureHostRunningAsync(); } catch { }
                        Ui.Send(PushProtectionStatus);
                        return;
                    }

                    try
                    {
                        var us = new UpdateService(_settings?.Read(), _engineDir, _scannerEdition);
                        var summary = await us.UpdateAllAsync(ev =>
                        {
                            PostToJs("update.bytes", new {
                                phase = ev.Phase,
                                component = ev.Component,
                                status = ev.Status,
                                downloaded = ev.Downloaded,
                                total = ev.Total,
                                pct = ev.OverallPct * 100,
                                speedBps = ev.SpeedBps,
                                etaSec = ev.EtaSec,
                                msg = ev.Message,
                            });
                        });

                        await RunFirstRunPrebackupAsync((status, msg) =>
                            PostToJs("update.bytes", new { phase = "prebackup", component = "prebackup", status, msg }));

                        PostToJs("update.done", new { success = true, changed = summary.ChangedFiles });
                        _verify = FileVerification.Verify();
                        var iv = _verify.Issues.Select(i => new {
                            file = i.File, message = i.Description, critical = i.Critical
                        }).ToList();
                        PostToJs("verify.issues", new { issues = iv });

                        try
                        {
                            var s = ScanScheduleStore.Read(_appDataDir);
                            if (s.Enabled && string.Equals(s.Trigger, "afterupdate", StringComparison.OrdinalIgnoreCase))
                            {
                                Ui.Send(() =>
                                    StartScheduledScan(s.Mode, s.Folders.ToList()));
                            }
                        }
                        catch { }
                    }
                    catch (Exception ex)
                    {
                        PostToJs("update.done", new { success = false, error = ex.Message });
                    }
                    finally
                    {
                        _tray?.SetBusy(BusyKind.None);
                        _updateInProgress = false;

                        try
                        {
                            if ((wasResidentRunning || wasNetworkRunning) && _resident != null)
                                await _resident.EnsureHostRunningAsync();
                        }
                        catch { }
                        Ui.Send(PushProtectionStatus);
                    }
                });
                break;
            case "engine.version":
                if (_engine == null) return;
                _ = Task.Run(async () =>
                {
                    var v = await _engine!.RunVersionAsync();

                    string guiVer;
                    try
                    {
                        var asm = System.Reflection.Assembly.GetExecutingAssembly();
                        var infoAttr = System.Reflection.CustomAttributeExtensions
                            .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm);
                        guiVer = infoAttr?.InformationalVersion?.Split('+')[0]
                                 ?? asm.GetName().Version?.ToString(3) ?? "—";
                    }
                    catch { guiVer = "—"; }

                    string EffMTime(string vdebName, string overlayName)
                    {
                        var t = EffectiveDbWriteTime(vdebName, overlayName);
                        return t.HasValue ? t.Value.ToString("yyyy-MM-dd HH:mm") : "—";
                    }

                    var dataDir = Path.Combine(_appDataDir, "data");
                    var vpsPath = Path.Combine(dataDir, "vps.vdeb");
                    var wlPath  = Path.Combine(dataDir, "rf-whitelist.vdeb");
                    var vpsMTime = EffMTime("vps.vdeb", "vps-overlay.txt");
                    var wlMTime  = EffMTime("rf-whitelist.vdeb", "rf-whitelist-overlay.txt");

                    string vpsDbVer = _dbVersions?.VpsVersion(vpsPath) ?? "—";
                    string wlDbVer  = _dbVersions?.WhitelistVersion(wlPath) ?? "—";

                    (int count, string mtime) ExtraListInfo(string fileName)
                    {
                        try
                        {
                            var p = Path.Combine(dataDir, fileName);
                            if (!File.Exists(p)) return (0, "—");
                            int n = 0;
                            foreach (var ln in File.ReadLines(p))
                            {
                                var t = ln.Trim();
                                if (t.Length > 0 && !t.StartsWith('#')) n++;
                            }
                            return (n, File.GetLastWriteTime(p).ToString("yyyy-MM-dd HH:mm"));
                        }
                        catch { return (0, "—"); }
                    }
                    var botIp = ExtraListInfo("vps-ex01.vdeb");
                    var cert  = ExtraListInfo("vps-ex02.vdeb");
                    var urlCache = ExtraListInfo("vps-ex03.vdeb");
                    var byod  = ExtraListInfo("vps-ex04.vdeb");

                    string ExtraListVersion(string key, string fileName)
                    {
                        var p = Path.Combine(dataDir, fileName);
                        return _dbVersions?.ExtraVersion(key, p) ?? "";
                    }
                    string botIpVer = ExtraListVersion("botip", "vps-ex01.vdeb");
                    string certVer = ExtraListVersion("cert", "vps-ex02.vdeb");
                    string urlCacheVer = ExtraListVersion("urlcache", "vps-ex03.vdeb");
                    string byodVer = ExtraListVersion("byod", "vps-ex04.vdeb");

                    var urlsPath  = Path.Combine(dataDir, "urls.vdeb");
                    string urlsVer = File.Exists(urlsPath)
                        ? (_dbVersions?.UrlsVersion(urlsPath) ?? "-") : "-";
                    int urlsCount = UrlDatabaseEntryCount(urlsPath);
                    string urlsMTime = File.Exists(urlsPath)
                        ? File.GetLastWriteTime(urlsPath).ToString("yyyy-MM-dd HH:mm") : "-";

                    PostToJs("version", new { raw = v, gui = guiVer, vpsMTime, whitelistMTime = wlMTime,
                                              vpsDbVersion = vpsDbVer, whitelistDbVersion = wlDbVer,
                                              botIpCount = botIp.count, botIpMTime = botIp.mtime,
                                              certCount = cert.count, certMTime = cert.mtime,
                                              urlsDbVersion = urlsVer, urlsCount, urlsMTime,
                                              urlCacheCount = urlCache.count, urlCacheMTime = urlCache.mtime,
                                              byodCount = byod.count, byodMTime = byod.mtime,
                                              botIpDbVersion = botIpVer, certDbVersion = certVer,
                                              urlCacheDbVersion = urlCacheVer, byodDbVersion = byodVer });
                });
                break;
            case "engine.quarantine.list":
                if (_engine == null) return;
                _ = Task.Run(async () =>
                {
                    var items = await _engine!.RunQuarantineListAsync();

                    var resident = _residentQuarantine?.Read() ?? new List<QuarantineItem>();
                    var merged = items.Concat(resident).ToList();
                    PostToJs("quarantine.list", new { items = merged });
                });
                break;
            case "engine.quarantine.restore":
                {
                    if (_engine == null) return;
                    var id = data["id"]?.GetValue<string>() ?? "";
                    var dest = data["destPath"]?.GetValue<string>();
                    _ = Task.Run(async () =>
                    {
                        bool ok = ResidentQuarantineStore.IsResidentId(id)
                            ? (_residentQuarantine?.Restore(id, dest) ?? false)
                            : await _engine!.RunQuarantineRestoreAsync(id, dest);
                        PostToJs("quarantine.restored", new { id, ok });
                    });
                    break;
                }
            case "engine.quarantine.extract":
                {
                    if (_engine == null) return;
                    var id      = data["id"]?.GetValue<string>() ?? "";
                    var destDir = data["destPath"]?.GetValue<string>() ?? "";

                    var hint    = data["name"]?.GetValue<string>();
                    _ = Task.Run(async () =>
                    {
                        string? path = ResidentQuarantineStore.IsResidentId(id)
                            ? _residentQuarantine?.Extract(id, destDir, hint)
                            : await _engine!.RunQuarantineExtractAsync(id, destDir, hint);
                        PostToJs("quarantine.extracted", new { id, ok = path != null, path });
                    });
                    break;
                }
            case "engine.quarantine.delete":
                {
                    if (_engine == null) return;
                    var id = data["id"]?.GetValue<string>() ?? "";
                    _ = Task.Run(async () =>
                    {
                        bool ok = ResidentQuarantineStore.IsResidentId(id)
                            ? (_residentQuarantine?.Delete(id) ?? false)
                            : await _engine!.RunQuarantineDeleteAsync(id);
                        PostToJs("quarantine.deleted", new { id, ok });
                    });
                    break;
                }
            case "engine.quarantine.report":
                {
                    var id      = data["id"]?.GetValue<string>() ?? "";
                    var comment = data["comment"]?.GetValue<string>() ?? "";
                    var det     = data["detection"]?.GetValue<string>() ?? "";
                    var orig    = data["path"]?.GetValue<string>() ?? "";
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var przygotowane = await QuarantineReportBlobAsync(id);
                            var blob = przygotowane.Blob;
                            if (blob == null)
                            {
                                PostToJs("quarantine.report.result", new { ok = false, error = przygotowane.Reason });
                                return;
                            }
                            var us = new UpdateService(_settings?.Read(), _engineDir!, _scannerEdition);
                            var ver = System.Reflection.Assembly.GetExecutingAssembly()
                                          .GetName().Version?.ToString() ?? "";
                            try
                            {
                                var r = await us.ReportFalsePositiveAsync(blob.Value.Path, det, orig, comment, ver);
                                PostToJs("quarantine.report.result", new { ok = r.Ok, id = r.Id, error = r.Error });
                            }
                            finally
                            {
                                if (blob.Value.Temporary)
                                    try { File.Delete(blob.Value.Path); } catch { }
                            }
                        }
                        catch (Exception ex)
                        {
                            PostToJs("quarantine.report.result", new { ok = false, error = ex.Message });
                        }
                    });
                    break;
                }
            case "engine.quarantine.restoreMany":
                {
                    if (_engine == null) return;
                    var ids = data["ids"]?.AsArray().Select(n => n!.GetValue<string>()).ToList() ?? new();
                    _ = Task.Run(async () =>
                    {
                        int ok = 0, fail = 0, done = 0;
                        foreach (var id in ids)
                        {
                            try
                            {
                                bool r = ResidentQuarantineStore.IsResidentId(id)
                                    ? (_residentQuarantine?.Restore(id, null) ?? false)
                                    : await _engine!.RunQuarantineRestoreAsync(id, null);
                                if (r) ok++; else fail++;
                            }
                            catch { fail++; }
                            done++;

                            PostToJs("quarantine.batchProgress",
                                new { action = "restore", done, total = ids.Count });
                        }
                        PostToJs("quarantine.batchResult", new { action = "restore", ok, fail, total = ids.Count });
                    });
                    break;
                }
            case "engine.quarantine.deleteMany":
                {
                    if (_engine == null) return;
                    var ids = data["ids"]?.AsArray().Select(n => n!.GetValue<string>()).ToList() ?? new();
                    _ = Task.Run(async () =>
                    {
                        int ok = 0, fail = 0, done = 0;
                        foreach (var id in ids)
                        {
                            try
                            {
                                bool r = ResidentQuarantineStore.IsResidentId(id)
                                    ? (_residentQuarantine?.Delete(id) ?? false)
                                    : await _engine!.RunQuarantineDeleteAsync(id);
                                if (r) ok++; else fail++;
                            }
                            catch { fail++; }
                            done++;
                            PostToJs("quarantine.batchProgress",
                                new { action = "delete", done, total = ids.Count });
                        }
                        PostToJs("quarantine.batchResult", new { action = "delete", ok, fail, total = ids.Count });
                    });
                    break;
                }
            case "settings.read":
                {
                    if (_settings == null) return;
                    var s = _settings.Read();
                    var node = JsonNode.Parse(s.ToJsonString())!.AsObject();

                    try
                    {
                        var shield = _residentSettings?.Read();

                        if (shield != null) StripMalwardExclusions(shield);
                        var excl = shield?["exclusions"] as JsonArray;
                        if (excl == null || excl.Count == 0)
                        {
                            excl = DefaultShieldExclusions();
                            try { _residentSettings?.Merge(new JsonObject { ["exclusions"] = JsonNode.Parse(excl.ToJsonString()) }); }
                            catch { }

                            try
                            {
                                var engExc = node["exceptions"] as JsonArray;
                                if (engExc == null || engExc.Count == 0)
                                {
                                    var paths = new JsonArray();
                                    foreach (var it in excl)
                                    {
                                        string sc = it?["scope"]?.GetValue<string>() ?? "both";
                                        string pth = it?["path"]?.GetValue<string>() ?? "";
                                        if (!string.IsNullOrWhiteSpace(pth) && (sc == "scanner" || sc == "both")) paths.Add(pth);
                                    }
                                    node["exceptions"] = JsonNode.Parse(paths.ToJsonString());
                                    _settings.Write(node);
                                }
                            }
                            catch { }
                        }
                        node["exclusions"] = JsonNode.Parse(excl.ToJsonString());
                    }
                    catch { }
                    PostToJs("settings.data", new { settings = (JsonNode)node });
                    break;
                }
            case "settings.write":
                {
                    try
                    {
                        if (_settings == null) { PostToJs("settings.saved", new { ok = false, error = "settings null" }); return; }
                        var payload = data["data"];
                        if (payload != null && JsonNode.Parse(payload.ToJsonString()) is JsonObject obj)
                        {
                            if (obj["exclusions"] is JsonArray exclArr)
                            {
                                SyncExclusionsToShield(exclArr);

                                var scannerPaths = new JsonArray();
                                foreach (var e in exclArr)
                                {
                                    string scope = e?["scope"]?.GetValue<string>() ?? "both";
                                    string path  = e?["path"]?.GetValue<string>() ?? "";
                                    if (!string.IsNullOrWhiteSpace(path) && (scope == "scanner" || scope == "both"))
                                        scannerPaths.Add(path);
                                }
                                obj["exceptions"] = scannerPaths;
                                obj.Remove("exclusions");   
                            }
                            _settings.Write(obj);
                        }
                        PostToJs("settings.saved", new { ok = true });
                    }
                    catch (Exception ex) { PostToJs("settings.saved", new { ok = false, error = ex.Message }); }
                    break;
                }
            case "settings.export":
                ExportSettings();
                break;
            case "settings.import":
                ImportSettings();
                break;
            case "settings.restore":
                RestoreDefaultSettings();
                break;
            case "db.bundle.download":
                {
                    if (_engineDir == null) { PostToJs("db.bundle.done", new { ok = false, error = "Brak katalogu silnika." }); break; }
                    if (_updateInProgress || _scanActive)
                    { PostToJs("db.bundle.done", new { ok = false, error = "Trwa aktualizacja lub skanowanie — spróbuj ponownie za chwilę." }); break; }
                    bool doImport = data?["import"]?.GetValue<bool>() ?? true;
                    string zipDest = Path.Combine(_appDataDir, "data", "malward-databases.zip");
                    var bundleSvc = new UpdateService(_settings?.Read(), _engineDir, _scannerEdition);
                    _updateInProgress = true;
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var dl = await bundleSvc.DownloadBundleAsync(zipDest, ev => PostToJs("db.bundle.progress", new
                            {
                                status = ev.Status, downloaded = ev.Downloaded, total = ev.Total,
                                pct = ev.OverallPct * 100, speedBps = ev.SpeedBps, etaSec = ev.EtaSec, message = ev.Message,
                            }));
                            PostToJs("db.bundle.done", new { ok = dl.Error == null, path = zipDest, bytes = dl.Bytes, error = dl.Error });
                            if (dl.Error != null || !doImport) return;
                            await ImportBundleWithShieldsPausedAsync(bundleSvc, zipDest);
                        }
                        catch (Exception ex) { PostToJs("db.bundle.done", new { ok = false, error = ex.Message }); }
                        finally { _updateInProgress = false; }
                    });
                }
                break;

            case "db.import":
                {
                    if (_engineDir == null) { PostToJs("db.import.done", new { ok = false, error = "Brak katalogu silnika." }); break; }

                    if (_updateInProgress || _scanActive)
                    { PostToJs("db.import.done", new { ok = false, error = "Trwa aktualizacja lub skanowanie — spróbuj ponownie za chwilę." }); break; }
                    string? wybranyZip = Picker.OpenFile(Loc.T("Wybierz archiwum ZIP z bazami danych"),
                                                         "Archiwum ZIP (*.zip)|*.zip", mustExist: true);
                    if (wybranyZip == null)
                    { PostToJs("db.import.done", new { ok = false, canceled = true, error = (string?)null }); break; }
                    string zipPath = wybranyZip;
                    var importSvc = new UpdateService(_settings?.Read(), _engineDir, _scannerEdition);
                    _ = Task.Run(async () =>
                    {
                        try { await ImportBundleWithShieldsPausedAsync(importSvc, zipPath); }
                        catch (Exception ex) { PostToJs("db.import.done", new { ok = false, error = ex.Message }); }
                    });
                }
                break;

            case "settings.profile.apply":
                ApplySecurityProfile(data?["profile"]?.GetValue<string>());
                break;
            case "system.deepclean":
                RunDeepClean();
                break;
            case "system.reboot":
                RebootSystem();
                break;
            case "shell.contextmenu.read":
                PostToJs("shell.contextmenu.state", new { enabled = ShellContextMenuService.IsRegistered() });
                break;
            case "shell.contextmenu.set":
                {
                    bool on = data?["enabled"]?.GetValue<bool>() ?? false;

                    try
                    {
                        var g0 = _guiSettings?.Read() ?? new GuiSettings();
                        _guiSettings?.Write(g0 with { ContextMenu = on });
                    }
                    catch { }

                    var (ok, err) = ShellContextMenuService.Set(on);
                    PostToJs("shell.contextmenu.result", new
                    {
                        ok,
                        enabled = ShellContextMenuService.IsRegistered(),
                        error = ok ? null : err,
                    });
                    break;
                }
            case "sysrepair.scan":
                {
                    string? enabledCsv = data?["enabled"]?.GetValue<string>();
                    _ = Task.Run(() =>
                    {
                        var items = RunSysRepair(new[] { "sysrepair", "scan" }
                            .Concat(string.IsNullOrEmpty(enabledCsv) ? Array.Empty<string>() : new[] { enabledCsv }).ToArray());
                        PostToJs("sysrepair.items", new { items });
                    });
                    break;
                }
            case "sysrepair.repair":
                {
                    string ids = data?["ids"]?.GetValue<string>() ?? "";
                    if (string.IsNullOrWhiteSpace(ids)) { PostToJs("sysrepair.repaired", new { fixedCount = 0, total = 0, results = Array.Empty<object>() }); break; }
                    _ = Task.Run(() =>
                    {
                        var raw = RunSysRepairRaw(new[] { "sysrepair", "fix", ids });
                        var results = new List<object>();
                        int fixedCount = 0, total = 0;
                        foreach (var line in raw)
                        {
                            if (line.StartsWith("SYSREPAIR-FIX\t", StringComparison.Ordinal))
                            {
                                var f = ParseKv(line);
                                bool ok = f.GetValueOrDefault("ok") == "1";
                                if (ok) fixedCount++;
                                total++;
                                results.Add(new { id = f.GetValueOrDefault("id"), ok, error = f.GetValueOrDefault("error") });
                            }
                        }
                        PostToJs("sysrepair.repaired", new { fixedCount, total, results });

                        if (fixedCount > 0)
                        {
                            PostToJs("toast", new { level = "ok",
                                msg = $"Naprawa systemu: przywrócono {fixedCount} zmienion{(fixedCount == 1 ? "e" : "ych")} ustawie{(fixedCount == 1 ? "nie" : "ń")} systemow{(fixedCount == 1 ? "e" : "ych")}." });
                        }
                    });
                    break;
                }
            case "gui.settings.read":
                {
                    var gs = _guiSettings?.Read() ?? new GuiSettings();

                    if (gs.ActiveProfile == null && _guiSettings != null)
                    {
                        gs = gs with { ActiveProfile = "medium" };
                        _guiSettings.Write(gs);
                        CrashLog.Write("profile", null, "no stored profile -> set to 'medium'");
                    }
                    PostToJs("gui.settings.data", new { theme = gs.Theme, lang = gs.Lang, autoUpdateEnabled = gs.AutoUpdateEnabled, autoUpdateMinutes = gs.AutoUpdateMinutes, lastUpdateCheckUnix = gs.LastUpdateCheckUnix, activeProfile = gs.ActiveProfile,
                        autostart = gs.Autostart, contextMenu = gs.ContextMenu,
                        guiMode = gs.GuiMode, webUiUrl = WebUiUrl });
                    break;
                }
            case "gui.settings.write":
                {
                    try
                    {
                        var theme = data["theme"]?.GetValue<string>() ?? "auto";
                        var lang = data["lang"]?.GetValue<string>() ?? "pl";
                        var auto = data["autoUpdateEnabled"]?.GetValue<bool>() ?? true;
                        var mins = Math.Max(15, data["autoUpdateMinutes"]?.GetValue<int>() ?? 60);

                        var existing = _guiSettings?.Read() ?? new GuiSettings();
                        long last = data["lastUpdateCheckUnix"]?.GetValue<long>() ?? existing.LastUpdateCheckUnix;

                        string? prof = data.ContainsKey("activeProfile")
                            ? data["activeProfile"]?.GetValue<string>()
                            : existing.ActiveProfile;

                        string trybGui = data.ContainsKey("guiMode")
                            ? (data["guiMode"]?.GetValue<string>() == "web" ? "web" : "window")
                            : existing.GuiMode;
                        _guiSettings?.Write(new GuiSettings(theme, lang, auto, mins, last, prof,
                            Autostart: data.ContainsKey("autostart") ? data["autostart"]?.GetValue<bool?>() : existing.Autostart,
                            ContextMenu: data.ContainsKey("contextMenu") ? data["contextMenu"]?.GetValue<bool?>() : existing.ContextMenu,
                            GuiMode: trybGui));

                        if (!string.Equals(prof, existing.ActiveProfile, StringComparison.Ordinal))
                            CrashLog.Write("profile", null,
                                $"profile saved: '{existing.ActiveProfile ?? "(none)"}' -> '{prof ?? "(none)"}'");
                        PostToJs("gui.settings.saved", new { ok = true });
                        StartAutoUpdateTimer();
                    }
                    catch (Exception ex) { PostToJs("gui.settings.saved", new { ok = false, error = ex.Message }); }
                    break;
                }
            case "stats.read":
                {
                    var s = _statsStore?.Read() ?? new ScanStatsData(0, 0, 0);
                    PostToJs("stats", new { scanned = s.FilesScanned, cloud = s.CloudAnalyzed, detections = s.TotalDetections });
                    break;
                }
            case "history.read":
                {
                    var h = _historyStore?.Read() ?? new List<ScanHistoryEntry>();
                    PostToJs("history.data", new { entries = h.AsEnumerable().Reverse().ToList() });
                    break;
                }
            case "history.clear":
                {
                    _historyStore?.Clear();
                    PostToJs("history.data", new { entries = new List<ScanHistoryEntry>() });
                    break;
                }
            case "network.check":
                _ = Task.Run(async () =>
                {
                    var (ok, error) = await CheckServerAsync(_settings?.Read());
                    PostToJs("network.status", new { online = ok, error });
                });
                break;
            case "dialog.pick.folder":
                {
                    var folderSkanu = Picker.PickFolder(Loc.T("Wybierz folder do skanowania"));
                    PostToJs("dialog.pick.folder.result", new { ok = folderSkanu != null, path = folderSkanu });
                    break;
                }
            case "dialog.pick.file":
                {
                    var plikWyjatku = Picker.OpenFile(Loc.T("Wybierz plik do dodania do wyjątków"));
                    PostToJs("dialog.pick.file.result", new { ok = plikWyjatku != null, path = plikWyjatku });
                    break;
                }
            case "dialog.pick.path":
                {
                    var kind = data["kind"]?.GetValue<string>() ?? "folder";

                    var target = data["target"]?.GetValue<string>();
                    if (kind == "file")
                    {
                        var wybrany = Picker.OpenFile(Loc.T("Wybierz plik"));
                        PostToJs("dialog.pick.path.result", new { ok = wybrany != null, path = wybrany, kind = "file", target });
                    }
                    else
                    {
                        var wybrany = Picker.PickFolder(Loc.T("Wybierz folder"));
                        PostToJs("dialog.pick.path.result", new { ok = wybrany != null, path = wybrany, kind = "folder", target });
                    }
                    break;
                }

            case "protection.status":
                PushProtectionStatus();
                break;

            case "protection.enable":
                if (_resident == null)
                {
                    PostToJs("protection.result", new { ok = false, error = "Brak mwshield.exe — reinstalacja wymagana." });
                    break;
                }
                _ = Task.Run(async () =>
                {
                    SetResidentWanted(true);
                    var (ok, err) = await _resident.EnableAsync();
                    Ui.Send(() =>
                    {
                        PostToJs("protection.result", new { ok, error = err, action = "enable" });
                        PushProtectionStatus();
                    });
                });
                break;

            case "protection.disable":
                if (_resident == null) { PushProtectionStatus(); break; }
                _ = Task.Run(async () =>
                {
                    SetResidentWanted(false);
                    var (ok, err) = await _resident.DisableAsync();
                    Ui.Send(() =>
                    {
                        PostToJs("protection.result", new { ok, error = err, action = "disable" });
                        PushProtectionStatus();
                    });
                });
                break;

            case "resident.settings.read":
                {
                    var obj = _residentSettings?.Read() ?? new JsonObject();
                    PostToJs("resident.settings.data", new { settings = (JsonNode)obj });
                    break;
                }

            case "resident.settings.write":
                {
                    try
                    {
                        if (_residentSettings == null) { PostToJs("resident.settings.saved", new { ok = false, error = "brak magazynu" }); break; }
                        var payload = data["data"];
                        if (payload != null && JsonNode.Parse(payload.ToJsonString()) is JsonObject obj)
                        {
                            _residentSettings.Merge(obj);

                            Loc.Refresh(_appDataDir);
                            if (obj["autostart"] is JsonNode an)
                            {
                                try { ApplyGuiAutostart(an.GetValue<bool>()); } catch { }
                            }
                        }

                        _ = Task.Run(() =>
                        {
                            bool restarted = _resident != null && _resident.State() == "running";
                            Ui.Send(() =>
                            {
                                PostToJs("resident.settings.saved", new { ok = true, restarted });
                                PushProtectionStatus();
                            });
                        });
                    }
                    catch (Exception ex) { PostToJs("resident.settings.saved", new { ok = false, error = ex.Message }); }
                    break;
                }

            case "protection.network.status":
                PushProtectionStatus();
                break;

            case "protection.network.enable":
                {
                    if (_network == null) { PushProtectionStatus(); break; }
                    _ = Task.Run(async () =>
                    {
                        try { _networkSettings?.Merge(new JsonObject { ["enabled"] = true }); } catch { }
                        var (ok, err) = await _network.EnableAsync();
                        Ui.Send(() =>
                        {
                            if (!ok) PostToJs("toast", new { level = "error", msg = $"Osłona sieciowa: {err}" });
                            PushProtectionStatus();
                        });
                    });
                    break;
                }

            case "protection.network.disable":
                {
                    if (_network == null) { PushProtectionStatus(); break; }
                    _ = Task.Run(async () =>
                    {
                        try { _networkSettings?.Merge(new JsonObject { ["enabled"] = false }); } catch { }
                        var (ok, err) = await _network.DisableAsync();
                        Ui.Send(() =>
                        {
                            if (!ok) PostToJs("toast", new { level = "error", msg = $"Osłona sieciowa: {err}" });
                            PushProtectionStatus();
                        });
                    });
                    break;
                }

            case "network.settings.read":
                {
                    var obj = _networkSettings?.Read() ?? new JsonObject();
                    PostToJs("network.settings.data", new { settings = (JsonNode)obj });
                    break;
                }

            case "network.settings.write":
                {
                    try
                    {
                        if (_networkSettings == null) { PostToJs("network.settings.saved", new { ok = false, error = "brak magazynu" }); break; }
                        var payload = data["data"];
                        if (payload != null && JsonNode.Parse(payload.ToJsonString()) is JsonObject obj)
                        {
                            _networkSettings.Merge(obj);

                            try
                            {
                                var g = obj["firewall_prompt_granularity"]?.GetValue<string>();

                                if (!string.IsNullOrEmpty(g) && _fwAvailable) SetFirewallGranularity(g!);
                            }
                            catch { }
                        }

                        _ = Task.Run(() =>
                        {
                            bool restarted = _network != null && _network.State() == "running";
                            Ui.Send(() =>
                            {
                                PostToJs("network.settings.saved", new { ok = true, restarted });
                                PushProtectionStatus();
                            });
                        });
                    }
                    catch (Exception ex) { PostToJs("network.settings.saved", new { ok = false, error = ex.Message }); }
                    break;
                }

            case "resident.removable.read":
                {
                    bool en = false;
                    try
                    {
                        var s = _residentSettings?.Read();
                        if (s?["scan_removable"] is JsonNode n) en = n.GetValue<bool>();
                    }
                    catch { }
                    PostToJs("resident.removable.state", new { enabled = en });
                    break;
                }

            case "resident.removable.write":
                {
                    bool en = false;
                    try { en = data["enabled"]?.GetValue<bool>() ?? false; } catch { }

                    try { _residentSettings?.Merge(new JsonObject { ["scan_removable"] = en }); } catch { }
                    PostToJs("resident.removable.state", new { enabled = en });
                    break;
                }

            case "backup.status":
                {
                    _ = Task.Run(async () =>
                    {
                        var s = await _backupClient.StatusAsync();
                        Ui.Send(() =>
                        {
                            if (s == null)
                            {
                                PostToJs("backup.status.data", new
                                {
                                    available = _backupClient.IsAvailable,
                                    is_admin = ElevationCheck.IsAdministrator,
                                    error = _backupClient.LastError ?? "Brak odpowiedzi bkmonitor.exe",
                                    running = _backupRunning,
                                });
                                return;
                            }
                            PostToJs("backup.status.data", new
                            {
                                available = true,
                                bkf_path = s.BkfPath,
                                bkf_size = s.BkfSize,
                                snap_count = s.SnapCount,
                                schedule = s.Schedule,
                                next_fire = s.NextFire,
                                compression_mode = s.CompressionMode,
                                on_file_change = s.OnFileChange,
                                watch_folders = s.WatchFolders,
                                enabled = BackupIsEnabled(),
                                running = _backupRunning,
                            });
                        });
                    });
                    break;
                }

            case "backup.snapshot.list":
                {
                    _ = Task.Run(async () =>
                    {
                        var list = await _backupClient.SnapshotListAsync() ?? new();
                        Ui.Send(() => PostToJs("backup.snapshot.list.data", new
                        {
                            snapshots = list.Select(s => new { snap_id = s.SnapId, timestamp = s.Timestamp, size = s.Size, trigger = s.Trigger }).ToArray(),
                        }));
                    });
                    break;
                }

            case "backup.snapshot.files":
                {
                    string snapId = data?["snap_id"]?.GetValue<string>() ?? "";
                    if (string.IsNullOrEmpty(snapId)) { PostToJs("backup.snapshot.files.data", new { snap_id = "", files = Array.Empty<object>() }); break; }
                    _ = Task.Run(async () =>
                    {
                        var files = await _backupClient.SnapshotFilesAsync(snapId) ?? new();
                        Ui.Send(() => PostToJs("backup.snapshot.files.data", new
                        {
                            snap_id = snapId,
                            files = files.Select(f => new { path = f.Path, size = f.Size, mtime = f.Mtime }).ToArray(),
                        }));
                    });
                    break;
                }

            case "backup.restore":
                {
                    string snapId = data?["snap_id"]?.GetValue<string>() ?? "";
                    string? target = data?["target"]?.GetValue<string>();
                    var paths = new List<string>();
                    try { if (data?["paths"] is JsonArray arr) foreach (var n in arr) { var s = n?.GetValue<string>(); if (!string.IsNullOrEmpty(s)) paths.Add(s); } } catch { }
                    _ = Task.Run(async () =>
                    {
                        var result = await _backupClient.RestoreAsync(snapId, paths, target);
                        Ui.Send(() => PostToJs("backup.restore.done", new
                        {
                            ok = result != null, restored = result?.Restored ?? 0, failed = result?.Failed ?? 0,
                            error = result == null ? _backupClient.LastError : null,
                        }));
                    });
                    break;
                }

            case "backup.force":
                {
                    _ = RunManualBackupAsync();
                    break;
                }

            case "backup.delete":
                {
                    string snapId = data?["snap_id"]?.GetValue<string>() ?? "";
                    if (string.IsNullOrEmpty(snapId)) break;
                    _ = Task.Run(async () =>
                    {
                        var ok = await WithWatchPausedAsync(() => _backupClient.DeleteAsync(snapId));
                        Ui.Send(() => PostToJs("backup.delete.done", new { ok, error = ok ? null : _backupClient.LastError }));
                    });
                    break;
                }

            case "backup.delete.all":
                {
                    _ = Task.Run(async () =>
                    {
                        int deleted = 0, failed = 0;
                        await WithWatchPausedAsync(async () =>
                        {
                            var snaps = await _backupClient.SnapshotListAsync() ?? new();
                            foreach (var s in snaps)
                            {
                                if (await _backupClient.DeleteAsync(s.SnapId)) deleted++; else failed++;
                            }
                            return true;
                        });
                        Ui.Send(() => PostToJs("backup.delete.done",
                            new { ok = failed == 0, all = true, deleted, failed,
                                  error = failed == 0 ? null : $"nie udało się usunąć {failed} punktów" }));
                    });
                    break;
                }

            case "backup.export":
                {
                    string snapId = data?["snap_id"]?.GetValue<string>() ?? "";
                    if (string.IsNullOrEmpty(snapId)) break;
                    var outPath = Picker.SaveFile(Loc.T("Eksportuj punkt kopii zapasowej"),
                        "Malward Backup (*.mwbk)|*.mwbk|Wszystkie pliki (*.*)|*.*",
                        $"malward-backup-{DateTime.Now:yyyyMMdd-HHmm}.mwbk");
                    if (outPath == null) { PostToJs("backup.export.done", new { ok = false, cancelled = true }); break; }
                    _ = Task.Run(async () =>
                    {
                        var ok = await _backupClient.ExportAsync(snapId, outPath);
                        Ui.Send(() => PostToJs("backup.export.done", new { ok, path = outPath, error = ok ? null : _backupClient.LastError }));
                    });
                    break;
                }

            case "backup.import":
                {
                    var inPath = Picker.OpenFile(Loc.T("Importuj punkt kopii zapasowej"),
                        "Malward Backup (*.mwbk)|*.mwbk|Wszystkie pliki (*.*)|*.*");
                    if (inPath == null) { PostToJs("backup.import.done", new { ok = false, cancelled = true }); break; }
                    _ = Task.Run(async () =>
                    {
                        var n = await WithWatchPausedAsync(() => _backupClient.ImportAsync(inPath));
                        Ui.Send(() => PostToJs("backup.import.done", new { ok = n > 0, imported = n, error = n > 0 ? null : _backupClient.LastError }));
                    });
                    break;
                }

            case "backup.state.read":
                {
                    PostToJs("backup.state.data", new
                    {
                        available = _backupClient.IsAvailable,
                        enabled = BackupIsEnabled(),
                        running = _backupRunning,
                    });
                    break;
                }

            case "backup.enable":
                {
                    if (!_backupClient.IsAvailable) { PostToJs("backup.state.data", new { available = false, enabled = false }); break; }
                    BackupSetEnabled(true);
                    StartBackupScheduler();
                    SyncWatchProcess();
                    PostToJs("backup.state.data", new { available = true, enabled = true, running = _backupRunning });

                    _ = RunManualBackupAsync(initialIfEmpty: true);
                    break;
                }

            case "backup.disable":
                {
                    BackupSetEnabled(false);
                    StopBackupScheduler();
                    SyncWatchProcess();
                    PostToJs("backup.state.data", new { available = _backupClient.IsAvailable, enabled = false, running = _backupRunning });
                    break;
                }

            case "backup.pick.folder":
                {
                    string? folder = Picker.PickFolder(Loc.T("Wybierz folder"));
                    PostToJs("backup.pick.folder.data", new { folder, purpose = data?["purpose"]?.GetValue<string>() ?? "" });
                    break;
                }

            case "backup.settings.read":
                {
                    var obj = _backupSettings.Read();
                    PostToJs("backup.settings.data", new { settings = (JsonNode)obj });
                    break;
                }

            case "backup.settings.write":
                {
                    try
                    {
                        var payload = data?["data"];
                        if (payload != null && JsonNode.Parse(payload.ToJsonString()) is JsonObject obj)
                        {
                            _backupSettings.Merge(obj);

                            if (BackupIsEnabled()) StartBackupScheduler();
                            SyncWatchProcess();
                            PostToJs("backup.settings.saved", new { ok = true });
                        }
                        else PostToJs("backup.settings.saved", new { ok = false, error = "bad payload" });
                    }
                    catch (Exception ex) { PostToJs("backup.settings.saved", new { ok = false, error = ex.Message }); }
                    break;
                }

            case "scan.schedule.read":
                {
                    var s = ScanScheduleStore.Read(_appDataDir);
                    PostToJs("scan.schedule.data", new { schedule = s });
                    break;
                }

            case "scan.schedule.write":
                {
                    try
                    {
                        var s = new ScanScheduleStore.Schedule
                        {
                            Enabled = data["enabled"]?.GetValue<bool>() ?? true,
                            Mode    = data["mode"]?.GetValue<string>() ?? "quick",
                            Trigger = data["trigger"]?.GetValue<string>() ?? "logon",
                            Day     = data["day"]?.GetValue<string>() ?? "MON",
                            Time    = data["time"]?.GetValue<string>() ?? "03:00",
                            Folders = (data["folders"] as JsonArray)?.Select(n => n?.GetValue<string>() ?? "")
                                       .Where(s => !string.IsNullOrWhiteSpace(s)).ToList() ?? new List<string>(),
                        };
                        ScanScheduleStore.Write(_appDataDir, s);
                        var malscan = EngineLocator.FindMalscan();
                        var (ok, err) = await ScanScheduler.ApplyAsync(s, malscan);
                        PostToJs("scan.schedule.saved", new { ok, error = err });
                    }
                    catch (Exception ex) { PostToJs("scan.schedule.saved", new { ok = false, error = ex.Message }); }
                    break;
                }

            case "scan.schedule.disable":
                {
                    try
                    {
                        var s = ScanScheduleStore.Read(_appDataDir);
                        s.Enabled = false;
                        ScanScheduleStore.Write(_appDataDir, s);
                        await ScanScheduler.DisableAsync();
                        PostToJs("scan.schedule.saved", new { ok = true });
                    }
                    catch (Exception ex) { PostToJs("scan.schedule.saved", new { ok = false, error = ex.Message }); }
                    break;
                }

            case "sandbox.settings.read":
                {
                    JsonNode? s = null;
                    try
                    {
                        var p = Path.Combine(_appDataDir, "data", "sandbox-settings.json");
                        if (File.Exists(p)) s = JsonNode.Parse(File.ReadAllText(p));
                    }
                    catch { }

                    try
                    {
                        var obj = s as JsonObject ?? new JsonObject();
                        string? saved = obj["helper"]?.GetValue<string>();
                        if (string.IsNullOrWhiteSpace(saved) || !File.Exists(saved))
                        {
                            var detected = DetectSandboxHelper();
                            if (detected != null) { obj["helper"] = detected; s = obj; }
                        }
                    }
                    catch { }
                    PostToJs("sandbox.settings.data", new { settings = s });
                    break;
                }
            case "sandbox.settings.write":
                {
                    try
                    {
                        var dir = Path.Combine(_appDataDir, "data");
                        Directory.CreateDirectory(dir);
                        File.WriteAllText(Path.Combine(dir, "sandbox-settings.json"), data.ToJsonString());
                    }
                    catch (Exception ex) { PostToJs("engine.log", new { level = "error", msg = $"sandbox settings: {ex.Message}" }); }
                    break;
                }
            case "sandbox.pick.exe":
                {
                    var exePiaskownicy = Picker.OpenFile(Loc.T("Wybierz plik EXE do uruchomienia w piaskownicy"),
                        "Pliki wykonywalne (*.exe)|*.exe|Wszystkie pliki (*.*)|*.*");
                    PostToJs("sandbox.pick.exe.data", new { ok = exePiaskownicy != null, path = exePiaskownicy });
                    break;
                }
            case "sandbox.pick.helper":
                {
                    var pomocnik = Picker.OpenFile(Loc.T("Wskaż SBHelper.exe (kontroler piaskownicy)"),
                        "SBHelper.exe|SBHelper.exe|Pliki wykonywalne (*.exe)|*.exe");
                    PostToJs("sandbox.pick.helper.data", new { ok = pomocnik != null, path = pomocnik });
                    break;
                }
            case "tools.analyze.pick":
                {
                    var doAnalizy = Picker.OpenFiles(Loc.T("Wybierz pliki do analizy w chmurze"),
                                                     "Wszystkie pliki (*.*)|*.*");
                    PostToJs("tools.analyze.pick.data",
                             new { ok = doAnalizy != null, paths = doAnalizy ?? Array.Empty<string>() });
                    break;
                }
            case "sandbox.module.status":
                {
                    var (helper, _, qemu, disk) = SandboxModuleState();
                    PostToJs("sandbox.module.state", new
                    {
                        available = helper != null, qemu, disk,
                        installed = helper != null && qemu && disk,
                    });
                    break;
                }
            case "sandbox.module.install":
                {
                    _ = InstallSandboxModuleAsync();
                    break;
                }
            case "sandbox.launch":
                {
                    var snapshot = data.DeepClone()?.AsObject();
                    _ = LaunchSandboxAsync(snapshot);
                    break;
                }
            case "tools.analyze.send":
                {
                    string path = data["path"]?.GetValue<string>() ?? "";
                    _ = ToolsAnalyzeAsync(path);
                    break;
                }
            case "dialog.tree.list":
                {
                    string path = data?["path"]?.GetValue<string>() ?? "";
                    _ = Task.Run(() =>
                    {
                        var nodes = new List<object>();
                        try
                        {
                            if (string.IsNullOrEmpty(path))
                            {
                                foreach (var d in DriveInfo.GetDrives())
                                {
                                    if (!d.IsReady) continue;
                                    if (d.DriveType is not (DriveType.Fixed or DriveType.Removable or DriveType.Network)) continue;
                                    string label = string.IsNullOrWhiteSpace(d.VolumeLabel)
                                        ? d.RootDirectory.FullName
                                        : $"{d.VolumeLabel} ({d.Name.TrimEnd('\\')})";
                                    nodes.Add(new { path = d.RootDirectory.FullName, name = label, hasChildren = true });
                                }
                            }
                            else
                            {
                                foreach (var sub in Directory.EnumerateDirectories(path))
                                {
                                    var info = new DirectoryInfo(sub);

                                    if ((info.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0) continue;
                                    bool hasKids = false;
                                    try { hasKids = Directory.EnumerateDirectories(sub).Any(); } catch { }
                                    nodes.Add(new { path = sub, name = info.Name, hasChildren = hasKids });
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            PostToJs("dialog.tree.data", new { path, nodes = Array.Empty<object>(), error = ex.Message });
                            return;
                        }
                        PostToJs("dialog.tree.data", new { path, nodes });
                    });
                    break;
                }
            case "program.update.check":
                {
                    _ = Task.Run(async () =>
                    {
                        var svc = ProgramUpdates();
                        var r = await svc.CheckAsync();
                        PostToJs("program.update.state", new
                        {
                            available = r.Available,
                            current   = r.CurrentVersion,
                            version   = r.Release?.Version,
                            notes     = r.Release?.Notes,
                            released  = r.Release?.Released,
                            size      = r.Release?.Size ?? 0,
                            error     = r.Error,
                        });
                    });
                    break;
                }
            case "program.update.cancel":
                {
                    CancelProgramUpdate();
                    break;
                }
            case "program.update.install":
                {
                    _ = Task.Run(async () => await InstallProgramUpdateAsync());
                    break;
                }
            case "hips.read":
                {
                    _ = Task.Run(() =>
                    {
                        string dir = Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                            "Malward", "data");
                        string catalog = "", state = "", events = "";
                        try { catalog = File.ReadAllText(Path.Combine(dir, "hips-catalog.json")); } catch { }
                        try { state = File.ReadAllText(Path.Combine(dir, "hips-rules.json")); } catch { }
                        try
                        {
                            var ev = Path.Combine(dir, "hips-events.jsonl");
                            if (File.Exists(ev))
                            {
                                var all = File.ReadAllLines(ev);
                                var take = Math.Min(80, all.Length);
                                var recent = new string[take];
                                for (int i = 0; i < take; i++) recent[i] = all[all.Length - 1 - i];
                                events = string.Join('\n', recent);
                            }
                        }
                        catch { }
                        PostToJs("hips.data", new { catalog, state, events });
                    });
                    break;
                }
            case "hips.write":
                {
                    var payload = data?["data"]?.ToJsonString() ?? "";
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            string dir = Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                "Malward", "data");
                            Directory.CreateDirectory(dir);
                            File.WriteAllText(Path.Combine(dir, "hips-rules.json"), payload);

                            PostToJs("hips.saved", new { ok = true });
                        }
                        catch (Exception ex) { PostToJs("hips.saved", new { ok = false, error = ex.Message }); }
                    });
                    break;
                }
            case "hips.undo":
                {
                    var record = data?["data"]?.ToJsonString() ?? "";
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            string dir = Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                "Malward", "data");
                            Directory.CreateDirectory(dir);
                            string resultPath = Path.Combine(dir, "hips-undo-result.json");
                            try { File.Delete(resultPath); } catch { }
                            File.WriteAllText(Path.Combine(dir, "hips-undo-request.json"), record);

                            for (int i = 0; i < 40 && !File.Exists(resultPath); i++)
                                await Task.Delay(250);

                            if (!File.Exists(resultPath))
                            {
                                PostToJs("hips.undone", new
                                {
                                    ok = false,
                                    message = "Usługa ochrony rezydentnej nie odpowiedziała. Sprawdź, czy jest uruchomiona.",
                                });
                                return;
                            }

                            var node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(resultPath));
                            PostToJs("hips.undone", new
                            {
                                ok = node?["ok"]?.GetValue<bool>() ?? false,
                                message = node?["message"]?.GetValue<string>() ?? "",
                            });
                        }
                        catch (Exception ex)
                        {
                            PostToJs("hips.undone", new { ok = false, message = ex.Message });
                        }
                    });
                    break;
                }
            case "repair.reveal":
                {
                    string loc = data?["location"]?.GetValue<string>() ?? "";
                    try { RevealLocation(loc); }
                    catch (Exception ex) { PostToJs("toast", new { level = "warn", msg = $"Nie udało się otworzyć: {ex.Message}" }); }
                    break;
                }
            case "app.autostart.read":
                {
                    PostToJs("app.autostart.state", new { enabled = AutostartTaskExists() });
                    break;
                }
            case "app.autostart.write":
                {
                    bool en = data["enabled"]?.GetValue<bool>() ?? true;
                    string? blad = null;
                    try { blad = ApplyGuiAutostart(en); }
                    catch (Exception ex) { blad = ex.Message; }

                    try
                    {
                        var g0 = _guiSettings?.Read() ?? new GuiSettings();
                        _guiSettings?.Write(g0 with { Autostart = en });
                    }
                    catch { }

                    bool stan = AutostartTaskExists();

                    PostToJs("app.autostart.state", new { enabled = stan, error = stan == en ? null : (blad ?? "operacja nie powiodła się") });
                    break;
                }
            case "resident.autorestore.set":
                {
                    bool en = data["enabled"]?.GetValue<bool>() ?? true;
                    try { _residentSettings?.Merge(new JsonObject { ["auto_restore_ransomware"] = en }); } catch { }
                    break;
                }
            case "system.hardening.get":
                {
                    _ = Task.Run(async () =>
                    {
                        var st = await Malward.AppGUI.Services.SystemHardening.GetAsync();
                        PostToJs("system.hardening", new
                        {
                            secureBoot = st.SecureBoot, bitlocker = st.BitLocker,
                            bootBackup = st.BootBackupPresent,
                        });
                    });
                    break;
                }
            case "boot.status.get":
                {
                    _ = Task.Run(async () =>
                    {
                        var raw = _backupClient != null ? await _backupClient.BootStatusJsonAsync() : null;
                        PostToJs("boot.status", new
                        {
                            ok = raw != null,
                            result = raw != null ? System.Text.Json.Nodes.JsonNode.Parse(raw) : null,
                            error = _backupClient?.LastError,
                        });
                    });
                    break;
                }
            case "boot.backup.now":
                {
                    _ = Task.Run(async () =>
                    {
                        var raw = _backupClient != null ? await _backupClient.BootBackupJsonAsync() : null;
                        PostToJs("boot.backup.done", new
                        {
                            ok = raw != null,
                            result = raw != null ? System.Text.Json.Nodes.JsonNode.Parse(raw) : null,
                            error = _backupClient?.LastError,
                        });
                    });
                    break;
                }
            case "boot.restore":
                {
                    bool all = data["all"]?.GetValue<bool>() ?? true;
                    int? drive = data["drive"] != null ? data["drive"]!.GetValue<int>() : (int?)null;
                    _ = Task.Run(async () =>
                    {
                        var raw = _backupClient != null ? await _backupClient.BootRestoreJsonAsync(drive, all) : null;
                        PostToJs("boot.restore.done", new
                        {
                            ok = raw != null,
                            result = raw != null ? System.Text.Json.Nodes.JsonNode.Parse(raw) : null,
                            error = _backupClient?.LastError,
                        });
                    });
                    break;
                }

            default:
                PostToJs("engine.log", new { level = "warn", msg = $"Unknown message: {type}" });
                break;
        }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private bool HandleFirewallMessage(string type, JsonObject data)
    {
        switch (type)
        {
            case "firewall.connections.list":
                {
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            var rows = Malward.FWManager.ConnectionEnumerator.EnumerateTcp()
                                .Select(c => new
                                {
                                    pid = c.Pid, name = c.ProcessName, path = c.ImagePath,
                                    local = $"{c.LocalAddress}:{c.LocalPort}",
                                    remote = $"{c.RemoteAddress}:{c.RemotePort}",
                                    state = c.State, protocol = c.Protocol,
                                    icon = c.IconDataUrl, critical = c.IsSystemCritical,
                                }).ToList();
                            PostToJs("firewall.connections.data", new { rows });
                        }
                        catch (Exception ex)
                        { PostToJs("firewall.connections.data", new { rows = new object[0], error = ex.Message }); }
                    });
                    break;
                }
            case "firewall.services.list":
                {
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            var rows = Malward.FWManager.ServiceEnumerator.EnumerateAll()
                                .Select(s => new
                                {
                                    name = s.Name, displayName = s.DisplayName,
                                    status = s.Status, startType = s.StartType,
                                    blocked = s.BlockedByMalward,
                                }).ToList();
                            PostToJs("firewall.services.data", new { rows });
                        }
                        catch (Exception ex)
                        { PostToJs("firewall.services.data", new { rows = new object[0], error = ex.Message }); }
                    });
                    break;
                }
            case "firewall.service.block":
                {
                    try
                    {
                        string name = data["service"]?.GetValue<string>() ?? "";
                        if (string.IsNullOrWhiteSpace(name))
                        { PostToJs("toast", new { level = "error", msg = "Brak nazwy usługi." }); break; }
                        string ruleName = $"Malward Block service — {name}";
                        var (ok, err) = Malward.FWManager.FirewallRules.Add(new Malward.FWManager.FirewallRule
                        {
                            Name = ruleName,
                            ApplicationName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe"),
                            ServiceName = name,
                            Description = $"Malward — blokada usługi {name}",
                            Protocol = 256, Direction = 2, Allow = false, Enabled = true,
                            Grouping = "Malward",
                        });
                        PostToJs("toast", new { level = ok ? "info" : "error",
                            msg = ok ? $"Zablokowano usługę {name}." : $"Błąd: {err}" });
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.process.kill":
                {
                    int pid = 0;
                    try { pid = data["pid"]?.GetValue<int>() ?? 0; } catch { }
                    if (pid <= 4) { PostToJs("toast", new { level = "error", msg = "Nie można zakończyć tego procesu." }); break; }

                    string? procName = null;
                    try { using var pp = System.Diagnostics.Process.GetProcessById(pid); procName = pp.ProcessName; }
                    catch { }
                    if (Malward.FWManager.SystemCriticalProcesses.IsCritical(pid, (procName ?? "") + ".exe"))
                    {
                        PostToJs("toast", new { level = "error",
                            msg = $"Proces systemowy ({procName ?? pid.ToString()}) jest chroniony — jego zakończenie spowodowałoby crash Windows." });
                        break;
                    }
                    try
                    {
                        using var p = System.Diagnostics.Process.GetProcessById(pid);
                        p.Kill(entireProcessTree: true);
                        PostToJs("toast", new { level = "info", msg = $"Zakończono PID {pid}." });
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = $"Kill: {ex.Message}" }); }
                    break;
                }
            case "firewall.process.block":
                {
                    string? path = null;
                    try { path = data["path"]?.GetValue<string>(); } catch { }
                    if (string.IsNullOrEmpty(path)) { PostToJs("toast", new { level = "error", msg = "Brak ścieżki procesu." }); break; }
                    var rule = $"Malward block: {System.IO.Path.GetFileName(path)}";
                    var (ok, err) = Malward.FWManager.FirewallRules.BlockProgram(path, rule);
                    PostToJs("toast", new { level = ok ? "info" : "error", msg = ok ? $"Zablokowano {Path.GetFileName(path)}." : $"Błąd: {err}" });
                    break;
                }
            case "firewall.rules.list":
                {
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            var rules = Malward.FWManager.FirewallRules.List()

                                .Where(r => !(r.Grouping ?? "").Equals("Malward-Self", StringComparison.OrdinalIgnoreCase)
                                            && !(r.Name ?? "").StartsWith("Malward Self-Allow", StringComparison.OrdinalIgnoreCase))
                                .Select(r => new
                                {
                                    name = r.Name, app = r.ApplicationName, allow = r.Allow,
                                    direction = r.Direction, enabled = r.Enabled,
                                    protocol = r.Protocol, localPorts = r.LocalPorts, remotePorts = r.RemotePorts,
                                    service = r.ServiceName, remoteAddresses = r.RemoteAddresses,
                                    grouping = r.Grouping,
                                }).ToList();
                            PostToJs("firewall.rules.data", new { rules });
                        }
                        catch (Exception ex)
                        { PostToJs("firewall.rules.data", new { rules = new object[0], error = ex.Message }); }
                    });
                    break;
                }
            case "firewall.rule.delete":
                {
                    string name = data["name"]?.GetValue<string>() ?? "";
                    if (string.IsNullOrEmpty(name)) { PostToJs("toast", new { level = "error", msg = "Brak nazwy reguły." }); break; }
                    var (ok, err) = Malward.FWManager.FirewallRules.Remove(name);
                    PostToJs("toast", new { level = ok ? "info" : "error", msg = ok ? "Usunięto regułę." : $"Błąd: {err}" });
                    break;
                }
            case "firewall.profile.get":
                {
                    var s = Malward.FWManager.FirewallProfile.GetState();
                    PostToJs("firewall.profile.data", new
                    {
                        current = s.CurrentProfileTypes,
                        domain = s.DomainEnabled, @private = s.PrivateEnabled, @public = s.PublicEnabled,
                    });
                    break;
                }
            case "firewall.profile.set":
                {
                    string p = data["profile"]?.GetValue<string>() ?? "";
                    bool enabled = data["enabled"]?.GetValue<bool>() ?? true;
                    int code = p switch
                    {
                        "domain"  => Malward.FWManager.FirewallProfile.NET_FW_PROFILE2_DOMAIN,
                        "private" => Malward.FWManager.FirewallProfile.NET_FW_PROFILE2_PRIVATE,
                        "public"  => Malward.FWManager.FirewallProfile.NET_FW_PROFILE2_PUBLIC,
                        _ => 0,
                    };
                    if (code == 0) { PostToJs("toast", new { level = "error", msg = "Nieznany profil." }); break; }
                    var (ok, err) = Malward.FWManager.FirewallProfile.SetProfileEnabled(code, enabled);
                    PostToJs("toast", new { level = ok ? "info" : "error", msg = ok ? "Profil zaktualizowany." : $"Błąd: {err}" });
                    break;
                }
            case "firewall.power.read":
                {
                    var st = ReadFirewallPower();
                    PostToJs("firewall.power.state", new
                    {
                        available = st.available, serviceRunning = st.serviceRunning, enabled = st.enabled,
                    });
                    break;
                }
            case "firewall.power.set":
                {
                    bool on = data["on"]?.GetValue<bool>() ?? true;
                    var (ok, err) = Malward.FWManager.FirewallProfile.SetAllProfilesEnabled(on);
                    var st = ReadFirewallPower();
                    PostToJs("firewall.power.state", new
                    {
                        available = st.available, serviceRunning = st.serviceRunning,
                        enabled = st.enabled, error = ok ? null : err,
                    });
                    break;
                }

            case "firewall.master.get":
                {
                    int domain  = Malward.FWManager.FirewallProfile.GetDefaultOutboundAction(Malward.FWManager.FirewallProfile.NET_FW_PROFILE2_DOMAIN);
                    int priv    = Malward.FWManager.FirewallProfile.GetDefaultOutboundAction(Malward.FWManager.FirewallProfile.NET_FW_PROFILE2_PRIVATE);
                    int pub     = Malward.FWManager.FirewallProfile.GetDefaultOutboundAction(Malward.FWManager.FirewallProfile.NET_FW_PROFILE2_PUBLIC);
                    bool blocking = domain == 0 && priv == 0 && pub == 0;

                    string stored = "interactive";
                    try { stored = _networkSettings?.Read()?["firewall_mode"]?.GetValue<string>() ?? "interactive"; } catch { }
                    string mode = !blocking ? "off" : (stored == "block" ? "block" : "interactive");
                    string gran = "ip";
                    try { gran = _networkSettings?.Read()?["firewall_prompt_granularity"]?.GetValue<string>() ?? "app"; } catch { }
                    PostToJs("firewall.master.state", new { blockMode = blocking, mode, granularity = gran });
                    break;
                }
            case "firewall.master.set":
                {
                    string mode = data["mode"]?.GetValue<string>()
                                  ?? ((data["blockMode"]?.GetValue<bool>() ?? false) ? "interactive" : "off");
                    bool blocking = mode is "block" or "interactive";

                    if (blocking) EnsureMalwardFirewallAllowRules();
                    try { _networkSettings?.Merge(new JsonObject { ["firewall_mode"] = mode }); } catch { }
                    var (ok, err) = Malward.FWManager.FirewallProfile.SetMasterBlockMode(blocking);
                    PostToJs("toast", new
                    {
                        level = ok ? "info" : "error",
                        msg = ok
                            ? mode switch
                            {
                                "block"       => "Pełna blokada WŁĄCZONA — internet odcięty, bez monitorowania.",
                                "interactive" => "Tryb interaktywny WŁĄCZONY — Malward zapyta przy każdej nowej blokadzie.",
                                _             => "Zapora wyłączona — domyślne zezwalanie na ruch wychodzący.",
                            }
                            : $"Błąd: {err}",
                    });
                    PostToJs("firewall.master.state", new { blockMode = blocking, mode });

                    if (ok)
                    {
                        if (mode == "interactive") StartFirewallListener();
                        else StopFirewallListener();
                    }
                    break;
                }
            case "firewall.granularity.set":
                {
                    string g = data["granularity"]?.GetValue<string>() ?? "app";

                    if (!string.Equals(g, "ip", StringComparison.OrdinalIgnoreCase)) g = "app";
                    try { _networkSettings?.Merge(new JsonObject { ["firewall_prompt_granularity"] = g }); } catch { }
                    try { if (_fwListener != null) _fwListener.Granularity = g; } catch { }
                    break;
                }
            case "firewall.rule.add":
                {
                    try
                    {
                        var rule = new Malward.FWManager.FirewallRule
                        {
                            Name             = data["name"]?.GetValue<string>() ?? "",
                            Description      = data["description"]?.GetValue<string>(),
                            ApplicationName  = data["application"]?.GetValue<string>(),
                            ServiceName      = data["service"]?.GetValue<string>(),
                            Protocol         = data["protocol"]?.GetValue<int>() ?? 256,
                            LocalPorts       = data["localPorts"]?.GetValue<string>(),
                            RemotePorts      = data["remotePorts"]?.GetValue<string>(),
                            LocalAddresses   = data["localAddresses"]?.GetValue<string>(),
                            RemoteAddresses  = data["remoteAddresses"]?.GetValue<string>(),
                            Direction        = data["direction"]?.GetValue<int>() ?? 2,
                            Allow            = data["allow"]?.GetValue<bool>() ?? false,
                            Enabled          = data["enabled"]?.GetValue<bool>() ?? true,
                            Profiles         = data["profiles"]?.GetValue<int>() ?? 0x7FFFFFFF,
                            Grouping         = "Malward",
                        };
                        if (string.IsNullOrWhiteSpace(rule.Name))
                        { PostToJs("toast", new { level = "error", msg = "Nazwa reguły jest wymagana." }); break; }
                        var (ok, err) = Malward.FWManager.FirewallRules.Add(rule);
                        PostToJs("toast", new { level = ok ? "info" : "error",
                            msg = ok ? "Reguła dodana." : $"Błąd: {err}" });
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.rule.enable":
                {
                    string name = data["name"]?.GetValue<string>() ?? "";
                    bool en    = data["enabled"]?.GetValue<bool>() ?? true;
                    var (ok, err) = Malward.FWManager.FirewallRules.SetEnabled(name, en);
                    PostToJs("toast", new { level = ok ? "info" : "error",
                        msg = ok ? (en ? "Reguła włączona." : "Reguła wyłączona.") : $"Błąd: {err}" });
                    break;
                }
            case "firewall.rules.deleteAllMalward":
                {
                    int n = Malward.FWManager.FirewallRules.DeleteAllMalwardPrefixed();
                    PostToJs("toast", new { level = "info", msg = $"Usunięto {n} reguł Malward." });
                    break;
                }
            case "firewall.lolbins.import":
                {
                    try
                    {
                        bool extended = data["extended"]?.GetValue<bool>() ?? false;
                        var (created, skipped, err) = Malward.FWManager.FirewallRules.AddLolbinHardening(extended);
                        if (err != null && created == 0)
                            PostToJs("toast", new { level = "error", msg = $"LOLBin: {err}" });
                        else
                            PostToJs("toast", new { level = "info",
                                msg = $"LOLBin hardening ({(extended ? "rozszerzone" : "zalecane")}): dodano {created} reguł (pominięto {skipped})." });
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.folder.rule":
                {
                    try
                    {
                        string folder = data["folder"]?.GetValue<string>() ?? "";
                        string name   = data["name"]?.GetValue<string>() ?? "Folder rule";
                        bool allow    = data["allow"]?.GetValue<bool>() ?? false;
                        int dir       = data["direction"]?.GetValue<int>() ?? 2;
                        if (string.IsNullOrWhiteSpace(folder))
                        { PostToJs("toast", new { level = "error", msg = "Brak folderu." }); break; }
                        var (created, err) = Malward.FWManager.FirewallRules.BlockOrAllowFolder(folder, name, allow, dir);
                        if (created == 0)
                            PostToJs("toast", new { level = "error", msg = $"Brak .exe w folderze. {err}" });
                        else
                            PostToJs("toast", new { level = "info", msg = $"Folder rule: dodano {created} reguł." });
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }

            case "firewall.event.allow":
                {
                    try
                    {
                        string path = data["appPath"]?.GetValue<string>() ?? "";
                        string svc  = data["serviceName"]?.GetValue<string>() ?? "";
                        string dir  = data["direction"]?.GetValue<string>() ?? "OUT";
                        int direction = dir == "IN" ? 1 : 2;
                        if (string.IsNullOrWhiteSpace(path))
                        { PostToJs("toast", new { level = "error", msg = "Brak ścieżki aplikacji." }); break; }
                        string name = $"Malward Allow — {System.IO.Path.GetFileName(path)} ({dir})";
                        var (ok, err) = Malward.FWManager.FirewallRules.Add(new Malward.FWManager.FirewallRule
                        {
                            Name = name,
                            ApplicationName = path,
                            ServiceName = string.IsNullOrEmpty(svc) ? null : svc,
                            Description = "Malward — Allow (z popupu blokady)",
                            Protocol = 256, Direction = direction, Allow = true, Enabled = true,
                            Grouping = "Malward",
                        });
                        if (!ok) PostToJs("toast", new { level = "error", msg = $"Allow: {err}" });
                        else
                        {
                            PostToJs("toast", new { level = "info", msg = $"Zezwolono: {System.IO.Path.GetFileName(path)}" });
                            _fwListener?.Snooze(path, dir, TimeSpan.FromSeconds(15));
                            _fwListener?.MarkAppDecided(path);
                        }
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.event.block":
                {
                    try
                    {
                        string path = data["appPath"]?.GetValue<string>() ?? "";
                        string dir  = data["direction"]?.GetValue<string>() ?? "OUT";
                        int direction = dir == "IN" ? 1 : 2;
                        if (string.IsNullOrWhiteSpace(path))
                        { PostToJs("toast", new { level = "error", msg = "Brak ścieżki." }); break; }
                        string name = $"Malward Block — {System.IO.Path.GetFileName(path)} ({dir})";
                        var (ok, err) = Malward.FWManager.FirewallRules.BlockProgram(path, name);
                        if (!ok) PostToJs("toast", new { level = "error", msg = $"Block: {err}" });
                        else
                        {
                            PostToJs("toast", new { level = "info", msg = $"Zablokowano: {System.IO.Path.GetFileName(path)}" });

                            _fwListener?.Snooze(path, dir, TimeSpan.FromSeconds(15));
                            _fwListener?.MarkAppDecided(path);
                        }
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.event.ignore":
                {
                    string path = data["appPath"]?.GetValue<string>() ?? "";
                    string dir  = data["direction"]?.GetValue<string>() ?? "OUT";
                    _fwListener?.Snooze(path, dir, TimeSpan.FromMinutes(5));
                    PostToJs("toast", new { level = "info", msg = "Pominięto (5 min ciszy)." });
                    break;
                }
            case "firewall.event.allowTemp":
                {
                    try
                    {
                        string path  = data["appPath"]?.GetValue<string>() ?? "";
                        int minutes  = data["minutes"]?.GetValue<int>() ?? 15;
                        string dir   = data["direction"]?.GetValue<string>() ?? "OUT";
                        int direction = dir == "IN" ? 1 : 2;
                        if (string.IsNullOrWhiteSpace(path))
                        { PostToJs("toast", new { level = "error", msg = "Brak ścieżki." }); break; }
                        _fwTempRules ??= new Malward.FWManager.TemporaryRuleManager();
                        var (ok, name, err) = _fwTempRules.AddAllowTemporary(path, TimeSpan.FromMinutes(minutes), direction);
                        if (!ok) PostToJs("toast", new { level = "error", msg = $"Allow Temp: {err}" });
                        else
                        {
                            PostToJs("toast", new { level = "info", msg = $"Tymczasowa zgoda na {minutes} min: {System.IO.Path.GetFileName(path)}" });
                            _fwListener?.Snooze(path, dir, TimeSpan.FromMinutes(minutes));
                        }
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.event.wildcard":
                {
                    try
                    {
                        string path = data["appPath"]?.GetValue<string>() ?? "";
                        bool allow  = data["allow"]?.GetValue<bool>() ?? true;
                        if (string.IsNullOrWhiteSpace(path))
                        { PostToJs("toast", new { level = "error", msg = "Brak ścieżki." }); break; }
                        string? folder = System.IO.Path.GetDirectoryName(path);
                        if (string.IsNullOrWhiteSpace(folder))
                        { PostToJs("toast", new { level = "error", msg = "Brak folderu nadrzędnego." }); break; }
                        string baseName = (allow ? "Malward Allow folder" : "Malward Block folder") + " — " + System.IO.Path.GetFileName(folder);
                        var (created, err) = Malward.FWManager.FirewallRules.BlockOrAllowFolder(folder, baseName, allow, 2);
                        if (created == 0)
                            PostToJs("toast", new { level = "error", msg = $"Wildcard: 0 reguł. {err}" });
                        else
                            PostToJs("toast", new { level = "info", msg = $"Wildcard ({(allow ? "Allow" : "Block")}): dodano {created} reguł." });
                        _fwListener?.Snooze(path, "OUT", TimeSpan.FromSeconds(20));
                    }
                    catch (Exception ex) { PostToJs("toast", new { level = "error", msg = ex.Message }); }
                    break;
                }
            case "firewall.events.start":
                StartFirewallListener();
                break;
            case "firewall.events.stop":
                StopFirewallListener();
                break;

            default:
                return false;
        }
        return true;
    }

    private void StartFirewallListener()
    {
        if (!_fwAvailable) return;
        try
        {
            if (_fwListener != null) return;

            string fwLogDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward", "logs");
            string fwLog = Path.Combine(fwLogDir, "fw-listener.log");
            try { Directory.CreateDirectory(fwLogDir); } catch { }
            void LogFw(string m)
            {
                try { File.AppendAllText(fwLog, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {m}{Environment.NewLine}"); } catch { }
                try { System.Diagnostics.Debug.WriteLine(m); } catch { }
            }
            _fwListener = new Malward.FWManager.FirewallEventListener(LogFw);

            try
            {
                var g = _networkSettings?.Read()?["firewall_prompt_granularity"]?.GetValue<string>();
                _fwListener.Granularity = string.IsNullOrEmpty(g) ? "app" : g!;
            }
            catch { }
            LogFw("=== Start request ===");
            _fwListener.BlockedConnectionDetected += info =>
            {
                try
                {
                    string appPath0 = info.AppPath ?? "";
                    _ = Task.Run(async () =>
                    {
                        string? det = string.IsNullOrEmpty(appPath0) ? null : await MalwareVerdictCachedAsync(appPath0);
                        try { Ui.Post((() => HandleBlockedConnection(info, det))); }
                        catch { }
                    });
                }
                catch { }
            };
            bool ok = _fwListener.Start();
            if (!ok) { _fwListener = null; PostToJs("toast", new { level = "error",
                msg = "Nie udało się uruchomić nasłuchu zdarzeń zapory (Security log)." }); }
        }
        catch (Exception ex)
        { PostToJs("toast", new { level = "error", msg = "FwListener: " + ex.Message }); }
    }

    private void StopFirewallListener()
    {
        try
        {
            _fwListener?.Stop();
            _fwListener?.Dispose();
            _fwListener = null;
        }
        catch { }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private void SetFirewallGranularity(string granularity)
    {
        try { if (_fwListener != null) _fwListener.Granularity = granularity; } catch { }
    }

    private static string ResolvePublisher(string path)
    {
        if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path)) return "";
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);

            string subj = cert.Subject ?? "";
            int idx = subj.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";
            int start = idx + 3;
            int end = subj.IndexOf(',', start);
            string cn = end < 0 ? subj.Substring(start) : subj.Substring(start, end - start);
            return cn.Trim('"', ' ');
        }
        catch { return ""; }
    }

    private static JsonArray DefaultShieldExclusions()
    {
        var arr = new JsonArray();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string? p)
        {
            if (string.IsNullOrWhiteSpace(p) || !seen.Add(p)) return;
            arr.Add(new JsonObject { ["path"] = p, ["scope"] = "both" });
        }

        try
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string progFiles   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string defPD = Path.Combine(programData, "Microsoft", "Windows Defender");
            string defPF = Path.Combine(progFiles, "Windows Defender");
            if (Directory.Exists(defPD)) Add(defPD);
            if (Directory.Exists(defPF)) Add(defPF);
        }
        catch { }

        foreach (var dir in FindEdgeUserDataDirs()) Add(dir);

        try
        {
            string mwData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward");
            if (Directory.Exists(mwData)) Add(mwData);
            string mwInstall = Path.GetDirectoryName(
                Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "";
            if (!string.IsNullOrEmpty(mwInstall) && Directory.Exists(mwInstall)) Add(mwInstall);
        }
        catch { }

        return arr;
    }

    private static IEnumerable<string> FindEdgeUserDataDirs()
    {
        var results = new List<string>();
        try
        {
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string usersRoot = Path.Combine(Path.GetPathRoot(systemDir) ?? @"C:\", "Users");
            if (!Directory.Exists(usersRoot)) return results;

            foreach (var profile in Directory.GetDirectories(usersRoot))
            {
                var name = Path.GetFileName(profile);
                if (name.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Default User", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("All Users", StringComparison.OrdinalIgnoreCase)) continue;

                var ud = Path.Combine(profile, "AppData", "Local", "Microsoft", "Edge", "User Data");
                if (Directory.Exists(ud)) results.Add(ud);
            }
        }
        catch { }
        return results;
    }

    private void SyncExclusionsToShield(JsonArray exclArr)
    {
        if (_residentSettings == null) return;
        try
        {
            var current = _residentSettings.Read();
            string before = (current?["exclusions"] as JsonArray)?.ToJsonString() ?? "[]";
            string after  = exclArr.ToJsonString();
            if (string.Equals(before, after, StringComparison.Ordinal)) return;
            _residentSettings.Merge(new JsonObject { ["exclusions"] = JsonNode.Parse(after) });
        }
        catch { }
    }

    private static AssetPack? LoadAssetPack()
    {
        var target = Path.Combine(_appDataDir, "data", "assets.vdeb");
        byte[]? embedded = null;
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using var res = asm.GetManifestResourceStream("Malward.AppGUI.assets.vdeb");
            if (res != null)
            {
                using var buf = new MemoryStream();
                res.CopyTo(buf);
                embedded = buf.ToArray();
            }
        }
        catch (Exception ex) { CrashLog.Write("assets", ex, "reading the embedded asset pack"); }

        if (embedded != null)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                var tmp = target + ".tmp";
                File.WriteAllBytes(tmp, embedded);
                File.Move(tmp, target, overwrite: true);
            }
            catch (Exception ex)
            {
                CrashLog.Write("assets", ex, $"refreshing {target}; the embedded pack is used regardless");
            }

            var fromExe = AssetPack.TryLoadBytes(embedded);
            if (fromExe != null)
            {
                var ver = System.Reflection.Assembly.GetExecutingAssembly()
                              .GetName().Version?.ToString() ?? "?";
                CrashLog.Write("assets", null,
                    $"interface loaded from the embedded pack: {fromExe.Count} entries, product {ver}");
                return fromExe;
            }
        }

        var pack = AssetPack.TryLoad(target);
        if (pack != null) return pack;

        pack = AssetPack.TryLoad(Path.Combine(AppContext.BaseDirectory, "assets.vdeb"));
        if (pack != null) return pack;

        return AssetPack.TryLoadFolder(Path.Combine(AppContext.BaseDirectory, "assets"));
    }

    private void OnWebResourceRequested(object? sender, CoreWebView2WebResourceRequestedEventArgs e)
    {
        try
        {
            if (_assets == null) return;
            var uri = new Uri(e.Request.Uri);

            string rel = uri.AbsolutePath.TrimStart('/');
            if (string.IsNullOrEmpty(rel)) rel = "index.html";

            if (!_assets.TryGet(rel, out var data))
            {
                if (rel.StartsWith("assets/", StringComparison.OrdinalIgnoreCase))
                    _assets.TryGet(rel["assets/".Length..], out data);
                else
                    _assets.TryGet("assets/" + rel, out data);
            }

            if (data == null) return;
            var ms = new MemoryStream(data, writable: false);
            var ct = AssetPack.ContentTypeFor(rel);

            var resp = WebView!.CoreWebView2.Environment.CreateWebResourceResponse(
                ms, 200, "OK", $"Content-Type: {ct}\r\nCache-Control: no-store, must-revalidate");
            e.Response = resp;
        }
        catch {  }
    }

    private bool _revealed;

    private bool _closed;
    private bool _startHidden;

    private bool _webBackgrounded;

    private void SetWebViewBackground(bool background)
    {
        if (_webBackgrounded == background) return;
        CoreWebView2? cw;
        try { cw = WebView?.CoreWebView2; } catch { cw = null; }
        if (cw == null) return;
        try
        {
            cw.MemoryUsageTargetLevel = background
                ? CoreWebView2MemoryUsageTargetLevel.Low
                : CoreWebView2MemoryUsageTargetLevel.Normal;
            _webBackgrounded = background;
        }
        catch {  }
    }

    private void RecomposeWebView()
    {
        try
        {
            WebView!.Visibility = Visibility.Collapsed;
            Ui.Post((() =>
            {
                try
                {
                    WebView!.Visibility = Visibility.Visible;
                    WebView!.InvalidateVisual();
                }
                catch { }
            }));
        }
        catch { }
    }

    private void RevealWindow()
    {
        if (WebMode) return;
        if (_revealed) return;

        if (_closed) return;
        _revealed = true;

        if (_startHidden)
        {
            Shell.SplashCollapse();
            return;
        }

        Shell.Reveal();
        Shell.SplashFadeOut();
    }

    private void TryUpdateMiniScanPopup(int pct, int done, string? file)
    {
        Ui.Send(() =>
        {
            bool hidden = !Shell.IsVisible || Shell.IsMinimized;
            if (!hidden)
            {
                CloseMiniScanPopup();
                return;
            }

            if (_miniScanUserDismissed) return;
            if (_miniScan == null || _miniScan.IsDisposed) CreateMiniScanPopup();
            _miniScan?.UpdateProgress(pct, done, file);
        });
    }

    private void CloseMiniScanPopup()
    {
        try { if (_miniScan != null && !_miniScan.IsDisposed) _miniScan.Close(); } catch { }
        _miniScan = null;

        _miniScanUserDismissed = false;
    }

    private void HandleRemovableEvents(List<ResidentIpc.RemovableEvent> events)
    {
        Ui.Send(() =>
        {
            foreach (var ev in events)
            {
                var t = ev.Type.ToLowerInvariant();
                if (t == "removable.started")
                {
                    EnsureMiniScanPopup();
                    _miniScan?.SetMode(ScanProgressForm.Mode.RemovableRunning, ev.Root, threats: 0);
                }
                else if (t == "removable.progress")
                {
                    EnsureMiniScanPopup();
                    _miniScan?.UpdateRemovableProgress(ev.Pct, ev.Done, ev.Total, ev.File, ev.Root);
                }
                else if (t == "removable.finished")
                {
                    EnsureMiniScanPopup();
                    _miniScan?.SetMode(ScanProgressForm.Mode.RemovableFinished, ev.Root, ev.Threats);
                }
            }
        });
    }

    private void EnsureMiniScanPopup()
    {
        _miniScanUserDismissed = false;
        EnsureMiniScanPopupCore();
    }

    private void EnsureMiniScanPopupCore()
    {
        if (_miniScan != null && !_miniScan.IsDisposed) return;
        CreateMiniScanPopup();
    }

    private void CreateMiniScanPopup()
    {
        if (WebMode) return;

        bool dark = ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");
        _miniScan = new ScanProgressForm(dark, _assets);
        _miniScan.OnOpenMainWindow = () => Ui.Send(() => RestoreToScanViewIfActive());
        _miniScan.FormClosed += (_, _) => { _miniScan = null; _miniScanUserDismissed = true; };
        _miniScan.Show();
    }

    private const string AutostartTaskName = "MalwardGuiAutostart";

    private static string? ApplyGuiAutostart(bool enable)
    {
        try
        {
            const string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(runKey, writable: true);
            if (key?.GetValue("Malward") != null)
                key.DeleteValue("Malward", throwOnMissingValue: false);
        }
        catch { }

        if (enable)
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exe)) return "nie udało się ustalić ścieżki programu";
            string user = WindowsIdentity.GetCurrent().Name;

            var (ok, err) = RunSchtasks(
                "/Create", "/F",
                "/TN", AutostartTaskName,
                "/SC", "ONLOGON",
                "/RL", "HIGHEST",
                "/RU", user, "/IT",
                "/TR", $"\"{exe}\" --tray");
            if (ok) return null;

            var (ok2, err2) = RunSchtasks(
                "/Create", "/F",
                "/TN", AutostartTaskName,
                "/SC", "ONLOGON",
                "/RU", user, "/IT",
                "/TR", $"\"{exe}\" --tray");
            if (ok2) return null;

            return string.IsNullOrWhiteSpace(err2) ? err : err2;
        }

        var (delOk, delErr) = RunSchtasks("/Delete", "/F", "/TN", AutostartTaskName);

        return delOk || !AutostartTaskExists() ? null : delErr;
    }

    private void ReconcileGuiAutostart()
    {
        _ = Task.Run(() =>
        {
            try
            {
                var g0 = _guiSettings?.Read() ?? new GuiSettings();
                if (_scannerEdition)
                {
                    if (AutostartTaskExists()) ApplyGuiAutostart(false);
                    if (g0.Autostart != false)
                        try { _guiSettings?.Write(g0 with { Autostart = false }); } catch { }
                    return;
                }
                bool? want = g0.Autostart;
                if (want == null)
                {
                    try { _guiSettings?.Write(g0 with { Autostart = true }); } catch { }
                    want = true;
                }
                if (want == false)
                {
                    if (AutostartTaskExists()) ApplyGuiAutostart(false);
                    return;
                }
                if (AutostartTaskExists()) return;
                ApplyGuiAutostart(true);
            }
            catch { }
        });
    }

    private static bool AutostartTaskExists()
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe")
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            psi.ArgumentList.Add("/Query");
            psi.ArgumentList.Add("/TN");
            psi.ArgumentList.Add(AutostartTaskName);
            using var p = Process.Start(psi);
            if (p == null) return false;
            p.WaitForExit(5000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    private static (bool ok, string? error) RunSchtasks(params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p == null) return (false, "nie udało się uruchomić harmonogramu zadań");

            var err = p.StandardError.ReadToEnd();
            var outp = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(8000)) { try { p.Kill(true); } catch { } return (false, "harmonogram zadań nie odpowiedział"); }
            if (p.ExitCode == 0) return (true, null);

            var tresc = (err + " " + outp).Trim();
            return (false, tresc.Length > 0 ? tresc : $"harmonogram zadań zwrócił kod {p.ExitCode}");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private string ResidentFlagPath => Path.Combine(_appDataDir, "data", "resident-enabled.flag");

    private bool ResidentModuleWanted()
    {
        MigrateResidentFlagOnce();
        return ResidentServiceController.ModuleEnabled();
    }

    private void SetResidentWanted(bool on)
    {
        ResidentServiceController.SetModuleEnabled(on);

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ResidentFlagPath)!);
            if (on) File.WriteAllText(ResidentFlagPath, "1");
            else if (File.Exists(ResidentFlagPath)) File.Delete(ResidentFlagPath);
        }
        catch { }
    }

    private bool _residentFlagMigrated;

    private void MigrateResidentFlagOnce()
    {
        if (_residentFlagMigrated) return;
        _residentFlagMigrated = true;
        try
        {
            if (ResidentServiceController.ModuleFlagPresent()) return;
            ResidentServiceController.SetModuleEnabled(File.Exists(ResidentFlagPath));
        }
        catch { }
    }

    private void StartTrayHealthTimer()
    {
        _trayHealthTimer?.Stop();
        _trayHealthTimer = new UiTimer { Interval = TimeSpan.FromMinutes(10) };
        _trayHealthTimer.Tick += (_, _) => RefreshTrayHealth();
        _trayHealthTimer.Start();
        RefreshTrayHealth();
    }

    private volatile bool _reconfiguringModules;

    private int _residentDownTicks;

    private void StartResidentWatchdog()
    {
        _residentWatchdog?.Stop();
        _residentWatchdog = new UiTimer { Interval = TimeSpan.FromSeconds(15) };
        _residentWatchdog.Tick += async (_, _) =>
        {
            SyncBackgroundScan();
            if (_resident == null) return;
            if (_reconfiguringModules) { _residentDownTicks = 0; return; }
            if (!ResidentModuleWanted()) { _residentDownTicks = 0; return; }
            try
            {
                if (_resident.State() != "running")
                {
                    if (++_residentDownTicks < 2) return;
                    _residentDownTicks = 0;
                    await _resident.EnableAsync();
                    PushProtectionStatus();
                }
                else _residentDownTicks = 0;
            }
            catch { }
        };
        _residentWatchdog.Start();
    }

    private (long Len, long Mtime) _scanReqLast = (-1, -1);
    private int  _scanReqStableTicks;
    private bool _scanReqCollecting;
    private UiTimer? _scanReqTimer;

    private long _scanReqFirstSeenTicks;

    private int _scanReqQueuedZgloszone = -1;

    private const int SCAN_REQ_STABLE_TICKS = 3;

    private const int SCAN_REQ_MIN_COLLECT_MS = 2000;

    private void StartScanRequestPoller()
    {
        _scanReqTimer?.Stop();
        _scanReqTimer = new UiTimer { Interval = TimeSpan.FromMilliseconds(350) };
        _scanReqTimer.Tick += (_, _) => CheckContextMenuScanRequest();
        _scanReqTimer.Start();
    }

    private void CheckContextMenuScanRequest()
    {
        try
        {
            var path = ScanInbox.Path;
            if (!File.Exists(path)) { EndCollecting(); return; }

            long len, mtime;
            try { var fi = new FileInfo(path); len = fi.Length; mtime = fi.LastWriteTimeUtc.Ticks; }
            catch { return; }

            var cur = (len, mtime);
            if (cur != _scanReqLast) { _scanReqLast = cur; _scanReqStableTicks = 0; }
            else _scanReqStableTicks++;
            if (_scanReqFirstSeenTicks == 0) _scanReqFirstSeenTicks = Environment.TickCount64;

            if (_scanActive)
            {
                int czeka = CountRequestLines(path);
                if (czeka != _scanReqQueuedZgloszone)
                {
                    _scanReqQueuedZgloszone = czeka;
                    PostToJs("scan.queued", new { count = czeka });
                }
                return;
            }
            if (_scanReqQueuedZgloszone >= 0)
            {
                _scanReqQueuedZgloszone = -1;
                PostToJs("scan.queued", new { count = 0 });
            }

            if (!_scanReqCollecting)
            {
                _scanReqCollecting = true;
                _tray?.Restore();
                PostToJs("ui.navigate", new { hash = "#/scan/progress" });
            }
            PostToJs("scan.collecting", new { count = CountRequestLines(path), done = false });

            if (_scanReqStableTicks < SCAN_REQ_STABLE_TICKS) return;
            if (Environment.TickCount64 - _scanReqFirstSeenTicks < SCAN_REQ_MIN_COLLECT_MS) return;

            var targets = File.ReadAllText(path)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(t => t.Trim().Trim('"'))
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .ToList();
            try { File.Delete(path); } catch { }
            _scanReqLast = (-1, -1);
            _scanReqStableTicks = 0;
            _scanReqFirstSeenTicks = 0;
            EndCollecting();
            if (targets.Count == 0) return;
            StartScheduledScan("custom", targets);

            RestoreToScanViewIfActive();
        }
        catch { }
    }

    private void EndCollecting()
    {
        _scanReqLast = (-1, -1);
        _scanReqStableTicks = 0;
        _scanReqFirstSeenTicks = 0;
        if (!_scanReqCollecting) return;
        _scanReqCollecting = false;
        PostToJs("scan.collecting", new { count = 0, done = true });
    }

    private static int CountRequestLines(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            int n = 0;
            while (sr.ReadLine() is { } line)
                if (!string.IsNullOrWhiteSpace(line)) n++;
            return n;
        }
        catch { return 0; }
    }

    private void StartIpcPoller()
    {
        _ipcTimer?.Stop();
        _ipcTimer = new UiTimer { Interval = TimeSpan.FromMilliseconds(1200) };
        _ipcTimer.Tick += (_, _) =>
        {
            TriggerAutoSystemRepair();

            if (_residentIpc == null) return;

            var (events, removable, restored) = _residentIpc.DrainAll();
            if (events.Count > 0) { ShowAlerts(events); TrackReinfection(events); }

            bool notif = ResidentNotificationsOn();
            if (notif && removable.Count > 0) HandleRemovableEvents(removable);

            if (notif && restored.Count > 0) ShowRestoredFilesPopup(restored);

            var act = _residentIpc.ReadActivityJson();
            if (act != null)
            {
                PostRawActivity(act);
                AccumulateResidentScanned(act);
            }

            if (_networkIpc != null)
            {
                var netEvents = _networkIpc.DrainEvents();
                if (netEvents.Count > 0)
                {
                    var ipBlocks = netEvents.Where(e =>
                        string.Equals(e.Type, "block", StringComparison.OrdinalIgnoreCase)
                        && string.Equals(e.Source, "dangerous-ip", StringComparison.OrdinalIgnoreCase)).ToList();
                    if (ipBlocks.Count > 0) ShowMaliciousIpAlerts(ipBlocks);
                }
                var netAct = _networkIpc.ReadActivityJson();
                if (netAct != null) PostNetworkActivity(netAct);
            }
        };
        _ipcTimer.Start();
    }

    private void ShowRestoredFilesPopup(IReadOnlyList<ResidentIpc.RestoredEvent> batch)
    {
        if (WebMode)
        {
            foreach (var r in batch)
                EventCentre.Report("behavior", r.Title, r.Detection, null, r.FilePath, r.Body);
            PostToJs("events.changed", new { pending = EventCentre.PendingCount() });
            return;
        }

        void Build()
        {
            try
            {
                var wpisy = batch.Select(r => new RichInfoPopupForm.Entry(
                        Title: string.IsNullOrEmpty(r.Title) ? "Zatrzymano atak behawioralny" : r.Title,
                        Detection: string.IsNullOrWhiteSpace(r.Detection) ? "Behaviour.Generic" : r.Detection,
                        Path: string.IsNullOrWhiteSpace(r.FilePath) ? null : System.IO.Path.GetDirectoryName(r.FilePath),
                        File: string.IsNullOrWhiteSpace(r.FilePath) ? null : System.IO.Path.GetFileName(r.FilePath),
                        Process: r.Pid > 0 ? $"PID {r.Pid}" : null,
                        Items: r.Paths,
                        FullPath: string.IsNullOrWhiteSpace(r.FilePath) ? null : r.FilePath,
                        QuarantineIds: BehaviourQuarantineIds(r)))
                    .ToList();
                if (wpisy.Count == 0) return;

                bool decide = false;
                try { decide = _residentSettings?.Read()?["behavior_user_decides"]?.GetValue<bool>() ?? false; } catch { }

                bool wszystkieDymkiem = true;
                foreach (var w in wpisy)
                    if (!ReportDetectionToCentre("behavior", Loc.T("Zatrzymano atak behawioralny"), w, decide))
                        wszystkieDymkiem = false;
                if (wszystkieDymkiem) return;

                bool dark = ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");
                RichInfoPopupForm.Group Grupa() => new()
                {
                    Kind = "behavior",
                    BannerText = Loc.T("Zatrzymano atak behawioralny"),
                    HeaderColor = System.Drawing.Color.FromArgb(0xC0, 0x2A, 0x2A),
                    IconPng = AssetBytes("restoredfiles.png"),
                    LogoPng = AssetBytes("logo.png") ?? AssetBytes("ic-logo.png"),
                    ButtonText = Loc.T("Wyświetl szczegóły zdarzenia"),
                    OnButton = () => OpenHipsEvents(),
                    OnRestore = decide ? e => RestoreBehavioural(e, exclude: false) : null,
                    OnRestoreAndExclude = decide ? e => RestoreBehavioural(e, exclude: true) : null,
                };

                var zywe = RichInfoPopupForm.Live;
                if (zywe != null && wpisy.All(w => zywe.AppendLive("behavior", w))) return;

                RichInfoPopupForm Zbuduj()
                {
                    var g = Grupa();
                    g.Entries.Clear();
                    foreach (var w in wpisy) g.Entries.Add(w);
                    return new RichInfoPopupForm(dark, g, autoDismissSec: 45);
                }

                if (ShieldPopupHub.Report("behavior", "Zatrzymano atak behawioralny", () => Zbuduj()))
                    return;

                Zbuduj().Show();
            }
            catch { }
        }
        if (Ui.HasAccess) Build();
        else Ui.Post((Build));
    }

    private async Task ImportBundleWithShieldsPausedAsync(UpdateService svc, string zipPath)
    {
        if (ResidentServiceController.ScanInProgress())
        {
            PostToJs("db.import.done", new
            {
                ok = false,
                error = "Trwa skanowanie — import baz przerwałby je. Poczekaj na koniec skanowania.",
            });
            return;
        }

        bool wasResidentRunning = false, wasNetworkRunning = false;
        try
        {
            wasResidentRunning = _resident != null && _resident.IsRunning();
            wasNetworkRunning  = _network  != null && _network.State()  == "running";
            if (wasResidentRunning)
            {
                PostToJs("db.import.progress", new { status = "busy", downloaded = 0, total = 0, pct = 0, message = "Pauzuję ochronę rezydentną na czas importu…" });
                try { await _resident!.StopAsync(); } catch { }
            }
            if (wasNetworkRunning) { try { await _network!.StopAsync(); } catch { } }
        }
        catch {  }

        try
        {
            var r = await svc.ImportDatabasesAsync(zipPath, ev => PostToJs("db.import.progress", new
            {
                status = ev.Status, downloaded = ev.Downloaded, total = ev.Total,
                pct = ev.OverallPct, message = ev.Message,
            }));
            PostToJs("db.import.done", new
            {
                ok = r.Error == null, imported = r.Imported,
                uptodate = r.UpToDate, bytes = r.Bytes, error = r.Error,
            });
            if (r.Imported > 0)
            {
                _verify = FileVerification.Verify();
                var iv = _verify.Issues.Select(i => new { file = i.File, message = i.Description, critical = i.Critical }).ToList();
                PostToJs("verify.issues", new { issues = iv });
            }
        }
        finally
        {
            try
            {
                if ((wasResidentRunning || wasNetworkRunning) && _resident != null)
                    await _resident.EnsureHostRunningAsync();
            }
            catch { }
            Ui.Send(PushProtectionStatus);
        }
    }

    private List<string> BehaviourQuarantineIds(ResidentIpc.RestoredEvent r)
    {
        var ids = new List<string>();
        if (string.Equals(r.Action, "delete", StringComparison.OrdinalIgnoreCase)) return ids;
        if (r.Quarantined is { Count: > 0 })
        {
            foreach (var q in r.Quarantined) ids.Add(ResidentQuarantineStore.IdPrefix + q.Stored);
            return ids;
        }
        try
        {
            var since = DateTimeOffset.FromUnixTimeMilliseconds(r.Ts > 0 ? r.Ts : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).AddMinutes(-3);
            foreach (var it in _residentQuarantine?.Read() ?? new List<QuarantineItem>())
            {
                bool samePath = !string.IsNullOrEmpty(r.FilePath) && string.Equals(it.Path, r.FilePath, StringComparison.OrdinalIgnoreCase);
                bool sameDet = !string.IsNullOrEmpty(r.Detection) && string.Equals(it.Detection, r.Detection, StringComparison.OrdinalIgnoreCase)
                               && DateTimeOffset.TryParse(it.Time, out var t) && t >= since;
                if (samePath || sameDet) ids.Add(it.Id);
            }
        }
        catch { }
        return ids;
    }

    private void RestoreBehavioural(RichInfoPopupForm.Entry e, bool exclude)
    {
        _ = Task.Run(() =>
        {
            int ok = 0, total = 0;
            foreach (var id in e.QuarantineIds ?? Array.Empty<string>())
            {
                total++;
                try { if (_residentQuarantine?.Restore(id, null) == true) ok++; } catch { }
            }

            string? excluded = null;
            if (exclude && !string.IsNullOrWhiteSpace(e.FullPath))
            {
                try
                {
                    var cur = _residentSettings?.Read();
                    var arr = (cur?["exclusions"] as JsonArray)?.DeepClone() as JsonArray ?? new JsonArray();
                    bool present = arr.Any(n => string.Equals(n?["path"]?.GetValue<string>(), e.FullPath, StringComparison.OrdinalIgnoreCase));
                    if (!present)
                    {
                        arr.Add(new JsonObject { ["path"] = e.FullPath, ["scope"] = "shield" });
                        SyncExclusionsToShield(arr);
                    }
                    excluded = e.FullPath;
                }
                catch (Exception ex) { CrashLog.Write("behaviour-exclude", ex); }
            }

            Ui.Post((() =>
            {
                string msg = total == 0 ? "Nie ma czego przywracać (pliki zostały usunięte, nie przeniesione do kwarantanny)."
                           : ok == total ? $"Przywrócono {ok} {(ok == 1 ? "plik" : ok < 5 ? "pliki" : "plików")} z kwarantanny."
                           : $"Przywrócono {ok} z {total} plików — reszta pozostała w kwarantannie.";
                if (excluded != null) msg += $" Dodano wyjątek osłony: {excluded}";
                PostToJs("toast", new { level = ok == total ? "ok" : "warn", msg });
                PostToJs("engine.log", new { level = "info", msg });
            }));
        });
    }

    private readonly HashSet<string> _shownIpAlerts = new(StringComparer.OrdinalIgnoreCase);

    private void ShowMaliciousIpAlerts(List<NetworkIpc.NetEvent> events)
    {
        try { var s = _residentSettings?.Read(); if (s?["notifications"] is JsonNode n && !n.GetValue<bool>()) return; }
        catch { }

        if (_shownIpAlerts.Count > 512) _shownIpAlerts.Clear();
        foreach (var ev in events)
        {
            if (!_shownIpAlerts.Add(ev.Target)) continue;

            string procName = ev.Process ?? "";
            string appName  = string.IsNullOrEmpty(procName) ? "Nieznany proces" : System.IO.Path.GetFileName(procName);
            string appPath  = procName;
            System.Drawing.Icon? appIcon = null;
            try
            {
                if (!string.IsNullOrEmpty(procName))
                {
                    var baseName = System.IO.Path.GetFileNameWithoutExtension(procName);
                    foreach (var p in System.Diagnostics.Process.GetProcessesByName(baseName))
                    {
                        try { var fn = p.MainModule?.FileName; if (!string.IsNullOrEmpty(fn)) { appPath = fn!; appName = System.IO.Path.GetFileName(fn); } }
                        catch { }
                        p.Dispose();
                        if (!string.Equals(appPath, procName, StringComparison.Ordinal)) break;
                    }
                    if (System.IO.File.Exists(appPath))
                        appIcon = System.Drawing.Icon.ExtractAssociatedIcon(appPath);
                }
            }
            catch { }

            if (WebMode) { ReportFirewallBlockToCentre(appName, appPath, ev.Target, ev.Detection); return; }
            var info = new FirewallAlertForm.Info(appName, appPath, ev.Target,
                ev.Detection ?? "MaliciousIP@GenericConn");
            var icon = appIcon;
            void Build()
            {
                try
                {
                    bool dark = ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");
                    new FirewallAlertForm(dark, info, AssetBytes("firewall.png"),
                        AssetBytes("logo.png") ?? AssetBytes("ic-logo.png"), icon).Show();
                }
                catch { }
            }
            if (Ui.HasAccess) Build();
            else Ui.Post((Build));
        }
    }

    private void PostNetworkActivity(string json)
    {
        if (!WebMode)
        {
            try
            {
                WebView?.CoreWebView2?.ExecuteScriptAsync(
                    $"window.malward && window.malward.onNetworkActivity && window.malward.onNetworkActivity({json});");
            }
            catch { }
            return;
        }

        try
        {
            var node = JsonNode.Parse(json);
            if (node != null) PushToBrowser("network.activity.raw", node);
        }
        catch { }
    }

    private long _lastShieldScanned    = -1;
    private long _lastShieldCloud      = -1;
    private long _lastShieldDetections = -1;

    private void AccumulateResidentScanned(string activityJson)
    {
        try
        {
            var node = JsonNode.Parse(activityJson);
            if (node == null) return;
            long scanned    = node["scanned"]?.GetValue<long>() ?? -1;

            long cloud      = node["cloud"]?.GetValue<long>() ?? 0;
            long detections = node["detections"]?.GetValue<long>()
                              ?? node["blocked"]?.GetValue<long>() ?? 0;
            if (scanned < 0) return;

            bool rebase = _lastShieldScanned < 0
                          || scanned    < _lastShieldScanned
                          || cloud      < _lastShieldCloud
                          || detections < _lastShieldDetections;
            if (rebase)
            {
                _lastShieldScanned    = scanned;
                _lastShieldCloud      = cloud;
                _lastShieldDetections = detections;
                return;
            }

            long dScanned    = scanned    - _lastShieldScanned;
            long dCloud      = cloud      - _lastShieldCloud;
            long dDetections = detections - _lastShieldDetections;
            _lastShieldScanned    = scanned;
            _lastShieldCloud      = cloud;
            _lastShieldDetections = detections;

            if (dScanned <= 0 && dCloud <= 0 && dDetections <= 0) return;

            if (dScanned > 0 || dCloud > 0)
                _statsStore?.AddFromScan(Math.Max(0, dScanned), Math.Max(0, dCloud));
            if (dDetections > 0)
                _statsStore?.IncDetections(dDetections);

            var s = _statsStore?.Read() ?? new ScanStatsData(0, 0, 0);
            PostToJs("stats", new { scanned = s.FilesScanned, cloud = s.CloudAnalyzed, detections = s.TotalDetections });
        }
        catch { }
    }

    private readonly Dictionary<string, List<DateTime>> _reinfectHits = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastReinfectPromptUtc = DateTime.MinValue;
    private bool _deepCleanRebootPending;

    private void TrackReinfection(List<ResidentIpc.ShieldEvent> events)
    {
        const int threshold = 3;
        var window = TimeSpan.FromMinutes(10);
        var now = DateTime.UtcNow;
        string? trigger = null;
        foreach (var e in events)
        {
            var key = !string.IsNullOrEmpty(e.Detection) ? e.Detection : e.File;
            if (string.IsNullOrEmpty(key)) continue;
            if (!_reinfectHits.TryGetValue(key, out var list)) { list = new(); _reinfectHits[key] = list; }
            list.Add(now);
            list.RemoveAll(t => now - t > window);
            if (list.Count >= threshold) trigger = string.IsNullOrEmpty(e.Detection) ? Path.GetFileName(e.File) : e.Detection;
        }
        if (trigger != null && now - _lastReinfectPromptUtc > window)
        {
            _lastReinfectPromptUtc = now;

            ShowActionPopup(Loc.T("Wykryto uporczywą infekcję"),
                $"To samo zagrożenie ({trigger}) powraca mimo aktywnej ochrony — prawdopodobnie ukryty proces wciąż je odtwarza. "
                + "Zalecane GŁĘBOKIE czyszczenie: naprawa ustawień systemu, usunięcie wpisów autostartu, pełny skan dysku i restart. Wykonać teraz?",
                "Wyczyść teraz", () => RunDeepClean(),
                "Później", () => { },
                autoDismissSec: 0, iconPng: AssetBytes("fixedwindows.png"));
        }
    }

    private void RunDeepClean()
    {
        _ = Task.Run(() =>
        {
            try { RunSysRepairRaw(new[] { "sysrepair", "fix", "all" }); } catch { }
            _deepCleanRebootPending = true;
            Ui.Send(() =>
            {
                PostToJs("toast", new { level = "info", msg = "Głębokie czyszczenie: naprawiono ustawienia systemu, uruchamiam pełny skan dysku…" });
                StartScheduledScan("full", new List<string>());
                RestoreToScanViewIfActive();
            });
        });
    }

    private void RebootSystem()
    {
        try
        {
            Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 8 /c \"Malward: restart po usunięciu zagrożeń\"")
            { UseShellExecute = false, CreateNoWindow = true });
        }
        catch (Exception ex) { PostToJs("toast", new { level = "err", msg = $"Nie udało się zrestartować: {ex.Message}" }); }
    }

    private bool ResidentNotificationsOn()
    {
        try
        {
            var rs = _residentSettings?.Read();
            if (rs?["notifications"] is JsonNode n) return n.GetValue<bool>();
        }
        catch { }
        return true;
    }

    private readonly Dictionary<string, long> _ostatnieAlerty = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan OknoPowtorzenAlertu = TimeSpan.FromSeconds(20);

    private List<ResidentIpc.ShieldEvent> BezPowtorzen(List<ResidentIpc.ShieldEvent> events)
    {
        var teraz = Environment.TickCount64;
        long prog = (long)OknoPowtorzenAlertu.TotalMilliseconds;
        foreach (var k in _ostatnieAlerty.Where(kv => teraz - kv.Value > prog).Select(kv => kv.Key).ToList())
            _ostatnieAlerty.Remove(k);

        var wynik = new List<ResidentIpc.ShieldEvent>();
        foreach (var e in events)
        {
            if (string.Equals(e.Mode, "ask", StringComparison.OrdinalIgnoreCase))
            {
                wynik.Add(e);
                continue;
            }
            var klucz = (e.File ?? "") + "|" + (e.Detection ?? "");
            if (_ostatnieAlerty.TryGetValue(klucz, out var kiedy) && teraz - kiedy <= prog) continue;
            _ostatnieAlerty[klucz] = teraz;
            wynik.Add(e);
        }
        return wynik;
    }

    private void ShowAlerts(List<ResidentIpc.ShieldEvent> events)
    {
        TriggerAutoSystemRepair();

        events = BezPowtorzen(events);
        if (events.Count == 0) return;

        bool dymkiem = ReportShieldToCentre(events);
        if (dymkiem || WebMode) return;

        var ask  = events.Where(e => e.Mode == "ask").ToList();
        var auto = events.Where(e => e.Mode == "auto").ToList();

        var theme = (_guiSettings?.Read().Theme) ?? "auto";

        bool showNotifs = true, sound = true;
        try
        {
            var rs = _residentSettings?.Read();
            if (rs != null)
            {
                if (rs["notifications"] is JsonNode n) showNotifs = n.GetValue<bool>();
                if (rs["notification_sound"] is JsonNode s) sound = s.GetValue<bool>();
            }
        }
        catch { }

        if (!showNotifs) return;

        if (auto.Count > 0)
        {
            ShowAlertWindow("auto", auto, theme, sound);
            NotifyNeutralized(auto);
        }
        if (ask.Count  > 0) ShowAlertWindow("ask",  ask,  theme, sound);
    }

    /// <summary>Taskbar balloon ON TOP of the alert window, only while the app is out of sight.</summary>
    /// <remarks>
    /// It must never be the only notification. Windows drops a NotifyIcon balloon without a word
    /// when notifications are off for the app or Focus Assist is on, and replacing the window with
    /// it left the antivirus silent - the one thing an antivirus may not be. So the window always
    /// shows and this is an extra nudge for a user who is looking at something else.
    /// </remarks>
    private void NotifyNeutralized(List<ResidentIpc.ShieldEvent> items)
    {
        if (_tray == null || items.Count == 0) return;
        if (Shell.IsVisible && !Shell.IsMinimized) return;

        var first = items[0];
        var body = new System.Text.StringBuilder();
        body.Append(Loc.T("Zneutralizowano zarażony plik:")).Append('\n');
        body.Append(first.File).Append('\n');
        body.Append(Loc.F("Infekcja: {0}", first.Detection));
        if (items.Count > 1)
            body.Append('\n').Append(Loc.F("oraz {0} innych", items.Count - 1));

        _tray.NotifyBalloon(Loc.T("Malward — osłona w czasie rzeczywistym"), body.ToString(),
            () => Ui.Send(RestoreToScanViewIfActive));
    }

    private void ShowAlertWindow(string mode, List<ResidentIpc.ShieldEvent> items, string theme, bool sound)
    {
        if (WebMode)
        {
            ReportShieldToCentre(items);
            return;
        }
        if (_residentIpc == null) return;

        bool dark = ResolveDark(theme);
        var formItems = items.Select(e => new AlertForm.Item(e.Id, e.Name, e.File, e.Detection,
            e.Process, e.Action ?? "", e.Source)).ToList();

        ref AlertForm? slot = ref (mode == "ask" ? ref _alertAsk : ref _alertAuto);

        if (slot != null && !slot.IsDisposed)
        {
            slot.AppendItems(formItems);
            return;
        }

        var form = new AlertForm(mode, formItems, dark, _residentIpc, _assets, sound);
        form.OnQuickScan = () => Ui.Send(() =>
        {
            _tray?.Restore();
            Navigate("#/scan/picker");
        });
        form.OnOpenQuarantine = () => Ui.Send(() =>
        {
            _tray?.Restore();
            Navigate("#/quarantine");
        });
        string capturedMode = mode;
        form.FormClosed += (_, _) =>
        {
            if (capturedMode == "ask"  && _alertAsk  == form) _alertAsk  = null;
            if (capturedMode == "auto" && _alertAuto == form) _alertAuto = null;
        };
        slot = form;
        form.Show();
    }

    private void ShowActionPopup(string title, string message, string primaryText, Action primary,
        string? secondaryText = null, Action? secondary = null, int autoDismissSec = 0, byte[]? iconPng = null)
    {
        if (WebMode)
        {
            PostToJs("toast", new { level = "info", msg = $"{title} — {message}" });
            return;
        }

        void Build()
        {
            try
            {
                bool dark = ResolveDark((_guiSettings?.Read()?.Theme) ?? "auto");
                new ActionPopupForm(dark, title, message, primaryText, primary,
                    secondaryText, secondary, autoDismissSec, iconPng).Show();
            }
            catch { }
        }
        if (Ui.HasAccess) Build();
        else Ui.Post((Build));
    }

    private void EnsureMalwardFirewallAllowRules()
    {
        if (!_fwAvailable) return;
        try
        {
            var dir = AppContext.BaseDirectory;
            string[] exes = { "netmonitor.exe", "malward.exe", "mwshield.exe", "malscan.exe", "bkmonitor.exe" };

            var juzSa = Malward.FWManager.FirewallRules.RuleNamesInGroup("Malward-Self");
            foreach (var exe in exes)
            {
                try
                {
                    var p = Path.Combine(dir, exe);
                    if (!File.Exists(p)) continue;
                    if (juzSa.Contains($"Malward Self-Allow — {exe}")) continue;
                    Malward.FWManager.FirewallRules.Add(skipIfExists: false, rule: new Malward.FWManager.FirewallRule
                    {
                        Name = $"Malward Self-Allow — {exe}",
                        ApplicationName = p,
                        Description = "Malward — dostęp własnych komponentów (DNS/aktualizacje) w trybie blokady",

                        Protocol = 256, Direction = 2 , Allow = true, Enabled = true, Grouping = "Malward-Self",
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private byte[]? AssetBytes(string name)
        => (_assets != null && _assets.TryGet("assets/" + name, out var d)) ? d : null;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> _fwMalwareCache =
        new(StringComparer.OrdinalIgnoreCase);

    private void HandleBlockedConnection(Malward.FWManager.BlockedConnectionInfo info, string? malwareDet)
    {
        PostToJs("firewall.connection.blocked", new
        {
            appPath = info.AppPath, appName = info.AppName, processId = info.ProcessId,
            serviceName = info.ServiceName, direction = info.Direction,
            remoteAddress = info.RemoteAddress, remotePort = info.RemotePort,
            protocol = info.Protocol, detectedAt = info.DetectedAt.ToString("HH:mm:ss"),
            publisher = ResolvePublisher(info.AppPath),
        });

        string app = !string.IsNullOrEmpty(info.AppName) ? info.AppName! : System.IO.Path.GetFileName(info.AppPath ?? "");
        string dir = string.IsNullOrEmpty(info.Direction) ? "OUT" : info.Direction!;
        string appPath = info.AppPath ?? "";
        string? svc = info.ServiceName;

        if (malwareDet != null)
        {
            try { _fwListener?.Snooze(appPath, dir, TimeSpan.FromMinutes(30)); } catch { }
            ShowFirewallMalwareAlert(app, appPath, $"{info.RemoteAddress}:{info.RemotePort}", malwareDet);
            return;
        }

        string publisher = ResolvePublisher(appPath);
        if (IsTrustedPublisher(publisher))
        {
            FirewallAllowApp(appPath, dir, svc);
        }
        else
        {
            string proto = info.Protocol == "6" ? "TCP" : info.Protocol == "17" ? "UDP" : $"proto {info.Protocol}";
            ShowFirewallPopup(new FirewallPopupForm.Info(app, appPath, dir, proto, info.RemoteAddress,
                info.RemotePort, info.ProcessId, publisher), appPath, dir, svc);
        }
    }

    private async Task<string?> MalwareVerdictCachedAsync(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        if (_fwMalwareCache.TryGetValue(path, out var cached)) return cached;
        string? det = null;
        try
        {
            var malscan = _verify?.MalscanPath;
            if (!string.IsNullOrEmpty(malscan) && System.IO.File.Exists(path))
                det = await Task.Run(() => RunMalscanDetect(malscan!, path));
        }
        catch { }
        _fwMalwareCache[path] = det;
        return det;
    }

    private static string TsvField(string line, string key)
    {
        int i = line.IndexOf(key, StringComparison.Ordinal);
        if (i < 0) return "";
        int start = i + key.Length;
        int end = line.IndexOf('\t', start);
        return end < 0 ? line[start..] : line[start..end];
    }

    private static string? RunMalscanDetect(string malscan, string path)
        => Malward.Engine.Core.SharedPipeline.ScanFile(path);

    private void ShowFirewallMalwareAlert(string appName, string appPath, string ipPort, string detection)
    {
        ReportFirewallBlockToCentre(appName, appPath, ipPort, detection);
        if (WebMode) return;
        try
        {
            bool dark = ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");
            System.Drawing.Icon? icon = null;
            try { if (System.IO.File.Exists(appPath)) icon = System.Drawing.Icon.ExtractAssociatedIcon(appPath); } catch { }
            new FirewallAlertForm(dark, new FirewallAlertForm.Info(appName, appPath, ipPort, detection),
                AssetBytes("firewall.png"), AssetBytes("logo.png") ?? AssetBytes("ic-logo.png"), icon).Show();
        }
        catch { }
    }

    private void ShowFirewallPopup(FirewallPopupForm.Info info, string appPath, string dir, string? svc)
    {
        if (ReportFirewallToCentre(info, appPath, dir, svc)) return;

        void Build()
        {
            try
            {
                bool dark = ResolveDark((_guiSettings?.Read()?.Theme) ?? "auto");
                System.Drawing.Icon? appIcon = null;
                try { if (!string.IsNullOrEmpty(appPath) && File.Exists(appPath)) appIcon = System.Drawing.Icon.ExtractAssociatedIcon(appPath); } catch { }
                bool trustPub = false;
                void AllowWithTrust()
                {
                    FirewallAllowApp(appPath, dir, svc);
                    if (trustPub && !string.IsNullOrEmpty(info.Publisher)) AddTrustedPublisher(info.Publisher);
                }
                new FirewallPopupForm(dark, info, AssetBytes("firewall.png"), AssetBytes("hide.png"),
                    AssetBytes("logo.png") ?? AssetBytes("ic-logo.png"), appIcon,
                    onAllowTemp: m => { AllowWithTrust(); _fwListener?.Snooze(appPath, dir, TimeSpan.FromMinutes(m)); },
                    onAllowPerm: () => { AllowWithTrust(); _fwListener?.MarkAppDecided(appPath); },
                    onIgnore:    () => _fwListener?.Snooze(appPath, dir, TimeSpan.FromMinutes(5)),
                    onBlock:     () => { _fwListener?.Snooze(appPath, dir, TimeSpan.FromMinutes(30)); _fwListener?.MarkAppDecided(appPath); },
                    onWildcard:  () => FirewallAllowApp(appPath, dir, svc),
                    setTrustPublisher: v => trustPub = v).Show();
            }
            catch { }
        }
        if (Ui.HasAccess) Build();
        else Ui.Post((Build));
    }

    private void AddTrustedPublisher(string pub)
    {
        try
        {
            var cur = _networkSettings?.Read();
            var arr = (cur?["firewall_trusted_publishers"] is JsonArray a) ? (JsonArray)a.DeepClone() : new JsonArray();
            if (!arr.Any(n => string.Equals(n?.GetValue<string>(), pub, StringComparison.OrdinalIgnoreCase)))
            {
                arr.Add(pub);
                _networkSettings?.Merge(new JsonObject { ["firewall_trusted_publishers"] = arr });
            }
        }
        catch { }
    }

    private bool IsTrustedPublisher(string? pub)
    {
        if (string.IsNullOrEmpty(pub)) return false;
        try
        {
            if (_networkSettings?.Read()?["firewall_trusted_publishers"] is JsonArray arr)
                return arr.Any(n => string.Equals(n?.GetValue<string>(), pub, StringComparison.OrdinalIgnoreCase));
        }
        catch { }
        return false;
    }

    private void FirewallAllowApp(string path, string dir, string? svc)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            int direction = dir == "IN" ? 1 : 2;
            string name = $"Malward Allow — {System.IO.Path.GetFileName(path)} ({dir})";
            var (ok, err) = Malward.FWManager.FirewallRules.Add(new Malward.FWManager.FirewallRule
            {
                Name = name, ApplicationName = path,
                ServiceName = string.IsNullOrEmpty(svc) ? null : svc,
                Description = "Malward — Allow (popup zapory)",
                Protocol = 256, Direction = direction, Allow = true, Enabled = true, Grouping = "Malward",
            });
            if (ok) _fwListener?.Snooze(path, dir, TimeSpan.FromSeconds(15));
            PostToJs("toast", new { level = ok ? "info" : "error",
                msg = ok ? $"Zezwolono: {System.IO.Path.GetFileName(path)}" : $"Allow: {err}" });
        }
        catch { }
    }

    private void ApplyThemeBackground()
    {
        try
        {
            var (r, g, b) = PrefersDarkTheme() ? (0x0E, 0x11, 0x16) : (0xF4, 0xF5, 0xF7);
            Shell.SetBackgroundColor((byte)r, (byte)g, (byte)b);
        }
        catch { }
    }

    private static bool ResolveDark(string theme)
    {
        if (theme == "dark") return true;
        if (theme == "light") return false;
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return false; }
    }

    private static int UrlDatabaseEntryCount(string path)
    {
        try
        {
            if (!File.Exists(path)) return 0;
            using var fs = File.OpenRead(path);
            using var gz = new System.IO.Compression.GZipStream(fs, System.IO.Compression.CompressionMode.Decompress);
            var head = new byte[8];
            int got = 0;
            while (got < 8)
            {
                int n = gz.Read(head, got, 8 - got);
                if (n <= 0) break;
                got += n;
            }
            if (got < 8 || head[0] != (byte)'V' || head[1] != (byte)'D'
                        || head[2] != (byte)'E' || head[3] != (byte)'B') return 0;
            return BitConverter.ToInt32(head, 4);
        }
        catch { return 0; }
    }

    private void PostRawActivity(string json)
    {
        if (!WebMode)
        {
            try
            {
                WebView?.CoreWebView2?.ExecuteScriptAsync(
                    $"window.malward && window.malward.onActivity && window.malward.onActivity({json});");
            }
            catch { }
            return;
        }

        try
        {
            var node = JsonNode.Parse(json);
            if (node != null) PushToBrowser("resident.activity.raw", node);
        }
        catch { }
    }

    private (bool available, bool serviceRunning, bool enabled) ReadFirewallPower()
    {
        if (!_fwAvailable) return (false, false, false);
        bool present = false, running = false;
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("MpsSvc");
            var status = sc.Status;
            present = true;
            running = status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch { present = false; running = false; }

        return (present, running, AllFirewallProfilesEnabled());
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static bool AllFirewallProfilesEnabled()
    {
        try
        {
            var s = Malward.FWManager.FirewallProfile.GetState();
            return s.DomainEnabled && s.PrivateEnabled && s.PublicEnabled;
        }
        catch { return false; }
    }

    private static string? DetectSandboxHelper()
    {
        var bases = new List<string>();
        try { bases.Add(AppContext.BaseDirectory); } catch { }
        try { bases.Add(Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? ""); } catch { }

        var rel = new[]
        {
            Path.Combine("sandbox", "sbhelper", "SBHelper.exe"),
            Path.Combine("sandbox", "SBHelper.exe"),

            Path.Combine("..", "..", "..", "..", "..", "AutoSandoxSDK", "bin", "sbhelper", "SBHelper.exe"),
        };

        foreach (var b in bases.Where(x => !string.IsNullOrEmpty(x)).Distinct())
        {
            foreach (var r in rel)
            {
                try
                {
                    var full = Path.GetFullPath(Path.Combine(b, r));
                    if (File.Exists(full)) return full;
                }
                catch { }
            }
        }
        return null;
    }

    private async Task LaunchSandboxAsync(System.Text.Json.Nodes.JsonObject? data)
    {
        try
        {
            if (data == null) { PostToJs("sandbox.launch.done", new { ok = false, error = "brak danych" }); return; }
            string exe    = data["exe"]?.GetValue<string>() ?? "";
            string helper = data["helper"]?.GetValue<string>() ?? "";
            if (string.IsNullOrWhiteSpace(helper) || !File.Exists(helper))
            { PostToJs("sandbox.launch.done", new { ok = false, error = "Nie wskazano SBHelper.exe (sekcja Lokalizacja piaskownicy)." }); return; }
            if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            { PostToJs("sandbox.launch.done", new { ok = false, error = "Plik do uruchomienia nie istnieje." }); return; }

            bool net = data["net"]?.GetValue<bool>() ?? true;
            bool nat = data["nat"]?.GetValue<bool>() ?? true;
            bool fs  = data["fullscreen"]?.GetValue<bool>() ?? false;
            bool ht  = data["ht"]?.GetValue<bool>() ?? true;
            int mem     = Math.Clamp(data["mem"]?.GetValue<int>() ?? 2, 2, 16);
            int cores   = Math.Clamp(data["cores"]?.GetValue<int>() ?? 2, 1, 16);
            int threads = Math.Clamp(data["threads"]?.GetValue<int>() ?? 2, 1, 4);
            string cpu  = data["cpu"]?.GetValue<string>() ?? "qemu64";
            string accel = data["accel"]?.GetValue<string>() ?? "auto";

            string helperDir  = Path.GetDirectoryName(helper)!;
            string sandboxDir = Path.GetDirectoryName(helperDir) ?? helperDir;
            string seed       = Path.Combine(sandboxDir, "shared", "default.7z");

            if (!File.Exists(seed))
            {
                string? malscan = _verify?.MalscanPath;
                if (string.IsNullOrEmpty(malscan) || !File.Exists(malscan))
                { PostToJs("sandbox.launch.done", new { ok = false, error = "Brak obrazu piaskownicy, a malscan.exe jest niedostępny do pobrania." }); return; }
                PostToJs("sandbox.launch.stage", new { stage = "download", msg = "Pobieranie obrazu piaskownicy z serwera…", pct = 0 });
                bool dlOk = await Task.Run(() => RunFetchSandbox(malscan!, seed));
                if (!dlOk) { PostToJs("sandbox.launch.done", new { ok = false, error = "Nie udało się pobrać obrazu piaskownicy z serwera." }); return; }
            }

            string statusFile = Path.Combine(Path.GetTempPath(), $"mw-sbox-status-{Guid.NewGuid():N}.json");
            var psi = new ProcessStartInfo
            {
                FileName = helper, UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = helperDir,
            };
            void Arg(params string[] a) { foreach (var x in a) psi.ArgumentList.Add(x); }
            Arg("--exe", exe);
            Arg("--net", net ? "on" : "off");
            Arg("--mem", mem.ToString());
            Arg("--nat", nat ? "on" : "off");
            if (fs) Arg("--fullscreen");
            Arg("--cpu", cpu);
            Arg("--cores", cores.ToString());
            Arg("--threads", threads.ToString());
            Arg("--ht", ht ? "on" : "off");
            Arg("--accel", accel);
            Arg("--bin", sandboxDir);
            Arg("--status", statusFile);

            PostToJs("sandbox.launch.stage", new { stage = "starting", msg = "Przygotowywanie maszyny…", pct = -1 });
            var proc = Process.Start(psi);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            string lastStage = "";
            while (sw.Elapsed < TimeSpan.FromMinutes(10))
            {
                await Task.Delay(400);
                string stage = "", msg = "";
                try
                {
                    if (File.Exists(statusFile))
                    {
                        var node = JsonNode.Parse(File.ReadAllText(statusFile));
                        stage = node?["stage"]?.GetValue<string>() ?? "";
                        msg   = node?["msg"]?.GetValue<string>() ?? "";
                    }
                }
                catch { }
                if (stage.Length > 0 && stage != lastStage)
                {
                    lastStage = stage;
                    PostToJs("sandbox.launch.stage", new { stage, msg, pct = -1 });
                }
                if (stage == "running") { PostToJs("sandbox.launch.done", new { ok = true }); break; }
                if (stage == "error")   { PostToJs("sandbox.launch.done", new { ok = false, error = msg }); break; }
                if (proc != null && proc.HasExited)
                {
                    if (lastStage != "running")
                        PostToJs("sandbox.launch.done", new { ok = false, error = string.IsNullOrEmpty(msg) ? "Maszyna nie wystartowała (sprawdź akcelerację/ustawienia)." : msg });
                    break;
                }
            }
            try { File.Delete(statusFile); } catch { }
        }
        catch (Exception ex)
        {
            PostToJs("sandbox.launch.done", new { ok = false, error = ex.Message });
        }
    }

    private bool RunFetchSandbox(string malscan, string dest, string evtType = "sandbox.launch.stage")
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = malscan, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(malscan) ?? "",
            };
            psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";
            psi.ArgumentList.Add("fetch-sandbox");
            psi.ArgumentList.Add(dest);
            using var p = Process.Start(psi);
            if (p == null) return false;
            string? line;
            while ((line = p.StandardOutput.ReadLine()) != null)
            {
                if (!line.StartsWith("SBDL\t", StringComparison.Ordinal) || line.Contains("\terror=")) continue;
                double pct = 0; long done = 0, total = 0;
                foreach (var part in line.Split('\t'))
                {
                    if (part.StartsWith("pct="))   double.TryParse(part[4..], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out pct);
                    else if (part.StartsWith("done="))  long.TryParse(part[5..], out done);
                    else if (part.StartsWith("total=")) long.TryParse(part[6..], out total);
                }
                string mb = total > 0 ? $"{done / 1048576} / {total / 1048576} MB" : "";
                PostToJs(evtType, new { stage = "download", msg = $"Pobieranie modułu piaskownicy… {mb}", pct });
            }
            p.WaitForExit();
            return p.ExitCode == 0 && File.Exists(dest);
        }
        catch { return false; }
    }

    private (string? helper, string sandboxDir, bool qemu, bool disk) SandboxModuleState()
    {
        string? helper = null;
        try
        {
            var p = Path.Combine(_appDataDir, "data", "sandbox-settings.json");
            if (File.Exists(p)) helper = JsonNode.Parse(File.ReadAllText(p))?["helper"]?.GetValue<string>();
        }
        catch { }
        if (string.IsNullOrWhiteSpace(helper) || !File.Exists(helper)) helper = DetectSandboxHelper();
        if (string.IsNullOrWhiteSpace(helper)) return (null, "", false, false);

        string helperDir  = Path.GetDirectoryName(helper)!;
        string sandboxDir = Path.GetDirectoryName(helperDir) ?? helperDir;
        bool qemu = File.Exists(Path.Combine(sandboxDir, "qemu", "qemu-system-x86_64.exe"));
        bool disk = File.Exists(Path.Combine(sandboxDir, "shared", "default.7z"));
        return (helper, sandboxDir, qemu, disk);
    }

    private async Task InstallSandboxModuleAsync()
    {
        var (helper, dir, qemu, _) = SandboxModuleState();
        if (helper == null)
        { PostToJs("sandbox.module.installed", new { ok = false, error = "Nie znaleziono kontrolera piaskownicy (SBHelper.exe). Wskaż go w ustawieniach zaawansowanych." }); return; }
        if (!qemu)
        { PostToJs("sandbox.module.installed", new { ok = false, error = "Brak komponentów QEMU — wymagana ponowna instalacja programu." }); return; }
        string? malscan = _verify?.MalscanPath;
        if (string.IsNullOrEmpty(malscan) || !File.Exists(malscan))
        { PostToJs("sandbox.module.installed", new { ok = false, error = "malscan.exe niedostępny — nie można pobrać modułu." }); return; }

        string seed = Path.Combine(dir, "shared", "default.7z");
        PostToJs("sandbox.module.progress", new { msg = "Pobieranie modułu piaskownicy z serwera…", pct = 0 });
        bool ok = await Task.Run(() => RunFetchSandbox(malscan!, seed, "sandbox.module.progress"));
        PostToJs("sandbox.module.installed", new { ok, error = ok ? null : "Nie udało się pobrać modułu piaskownicy z serwera." });
    }

    private async Task ToolsAnalyzeAsync(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        { PostToJs("tools.analyze.result", new { ok = false, error = "Plik nie istnieje.", path }); return; }
        string? malscan = _verify?.MalscanPath;
        if (string.IsNullOrEmpty(malscan) || !File.Exists(malscan))
        { PostToJs("tools.analyze.result", new { ok = false, error = "malscan.exe niedostępny.", path }); return; }

        long dlugosc = 0;
        try { dlugosc = new FileInfo(path).Length; } catch { }
        if (dlugosc > AnalizaLimitBajtow)
        {
            PostToJs("tools.analyze.result", new { ok = false, path,
                error = "Plik jest za duży dla serwera analizy — maksymalny rozmiar to 1 GB." });
            return;
        }

        PostToJs("tools.analyze.progress", new { path, sent = 0L, total = dlugosc });
        var result = await Task.Run(() => RunAnalyzeScan(malscan!, path));

        if (result is AnalyzeResult ar && ar.Detected)
        {
            var (quarantined, powodAkcji) = await Task.Run(() => QuarantineViaEngine(malscan!, path, ar.Name));
            ar.Action = quarantined ? "quarantine" : "failed";
            if (!quarantined && powodAkcji.Length > 0)
                ar.ActionDetail = powodAkcji;
            Ui.Send(() =>
            {
                var evt = new Services.ResidentIpc.ShieldEvent(
                    Id: Guid.NewGuid().ToString("N"), Mode: "auto", File: path,
                    Name: Path.GetFileName(path), Detection: ar.Name ?? "zagrożenie",
                    Action: quarantined ? "quarantine" : "report",
                    Ts: DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Process: "");
                string theme = "auto";
                try { theme = _guiSettings?.Read()?.Theme ?? "auto"; } catch { }
                ShowAlertWindow("auto", new List<Services.ResidentIpc.ShieldEvent> { evt }, theme, sound: true);
                try { _statsStore?.IncDetections(1); } catch { }
            });
        }

        PostToJs("tools.analyze.result", result);
    }

    internal sealed class AnalyzeResult
    {
        public bool Ok { get; init; }
        public bool Detected { get; init; }
        public string? Name { get; init; }
        public string? Source { get; init; }
        public string? Error { get; init; }
        public string Action { get; set; } = "report";
        public string? ActionDetail { get; set; }
        public string Path { get; init; } = "";

        public string? Label { get; init; }
        public int VtDetected { get; init; }
        public int VtTotal { get; init; }
    }

    private static string WriteCustomPlan(List<string> folders)
    {
        var arr = new JsonArray();
        foreach (var f in folders)
            arr.Add(new JsonObject { ["path"] = f, ["ext"] = new JsonArray() });
        var plan = new JsonObject { ["name"] = "custom", ["folders"] = arr };
        var path = Path.Combine(Path.GetTempPath(), $"malward-plan-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, plan.ToJsonString());
        return path;
    }

    private static List<string> ExpandScanTargets(string target, string mode, JsonNode? data)
    {
        var list = new List<string>();

        if (string.Equals(mode, "full", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    list.Add(d.RootDirectory.FullName);
                }
            }
            catch {  }
        }
        else
        {
            try
            {
                if (data?["targets"] is JsonArray arr)
                    foreach (var n in arr)
                    {
                        var s = n?.GetValue<string>();
                        if (!string.IsNullOrWhiteSpace(s) && Directory.Exists(s)) list.Add(s!);
                    }
            }
            catch { }
        }

        if (list.Count == 0 && !string.IsNullOrWhiteSpace(target)) list.Add(target);
        return list;
    }

    private void RevealLocation(string location)
    {
        if (string.IsNullOrWhiteSpace(location)) return;

        var loc = location.Trim();
        int bar = loc.IndexOf('|');
        if (bar > 0) loc = loc[..bar];

        if (loc.StartsWith("Zadanie", StringComparison.OrdinalIgnoreCase))
        {
            if (loc.StartsWith("Zadanie (.job)", StringComparison.OrdinalIgnoreCase))
            {
                var legacyDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Tasks");
                if (Directory.Exists(legacyDir))
                    Process.Start(new ProcessStartInfo("explorer.exe", $"\"{legacyDir}\"") { UseShellExecute = true });
                return;
            }
            Process.Start(new ProcessStartInfo("mmc.exe", "taskschd.msc") { UseShellExecute = true });
            return;
        }

        bool looksRegistry = loc.StartsWith("HK", StringComparison.OrdinalIgnoreCase);
        if (looksRegistry)
        {
            var full = loc
                .Replace("HKLM32\\", @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\", StringComparison.OrdinalIgnoreCase)
                .Replace("HKCU32\\", @"HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\", StringComparison.OrdinalIgnoreCase)
                .Replace("HKLM\\", @"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase)
                .Replace("HKCU\\", @"HKEY_CURRENT_USER\", StringComparison.OrdinalIgnoreCase)
                .Replace("HKU\\",  @"HKEY_USERS\", StringComparison.OrdinalIgnoreCase);
            try
            {
                using var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
                k?.SetValue("LastKey", full);
            }
            catch {  }
            Process.Start(new ProcessStartInfo("regedit.exe") { UseShellExecute = true });
            return;
        }

        if (File.Exists(loc))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{loc}\"") { UseShellExecute = true });
        else if (Directory.Exists(loc))
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{loc}\"") { UseShellExecute = true });
    }

    private (bool ok, string detail) QuarantineViaEngine(string malscan, string file, string? detection)
    {
        try
        {
            var psi = new ProcessStartInfo(malscan)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            psi.ArgumentList.Add("repair");
            psi.ArgumentList.Add("quarantine");
            psi.ArgumentList.Add(file);
            psi.ArgumentList.Add("--detection");
            psi.ArgumentList.Add(string.IsNullOrWhiteSpace(detection) ? "Cloud:scan" : detection!);
            psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";

            using var p = Process.Start(psi);
            if (p == null) return (false, "nie udało się uruchomić skanera");

            string outp = p.StandardOutput.ReadToEnd();
            string err = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(120000))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return (false, "skaner nie odpowiedział w czasie");
            }

            string powod = "";
            foreach (var line in outp.Split('\n'))
            {
                var l = line.Trim();
                if (!l.StartsWith("REPAIR\t", StringComparison.Ordinal)) continue;
                foreach (var part in l.Split('\t'))
                    if (part.StartsWith("detail=", StringComparison.Ordinal))
                        powod = part["detail=".Length..];
            }
            if (powod.Length == 0 && err.Trim().Length > 0) powod = err.Trim();

            bool ok = p.ExitCode == 0;
            CrashLog.Write("tools-quarantine", null,
                $"exit={p.ExitCode} file={file} detail={powod}");
            return (ok, powod);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private const long AnalizaLimitBajtow = 1024L * 1024 * 1024;

    private const long AnalyzeStallMs = 15 * 60 * 1000;

    private AnalyzeResult RunAnalyzeScan(string malscan, string path)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = malscan, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(malscan) ?? "",
            };
            psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";

            psi.Environment["MALWARD_FORCE_UPLOAD"] = "1";
            psi.ArgumentList.Add("analyze-file");
            psi.ArgumentList.Add(path);
            using var p = Process.Start(psi);
            if (p == null) return new AnalyzeResult { Ok = false, Error = "Nie udało się uruchomić skanera.", Path = path };

            var stderr = new System.Text.StringBuilder();
            var drain = Task.Run(() =>
            {
                try
                {
                    string? e;
                    while ((e = p.StandardError.ReadLine()) != null)
                        if (stderr.Length < 4000) stderr.AppendLine(e);
                }
                catch { }
            });

            var lines = new List<string>();
            string? line;
            const string POSTEP = "ANALYZE-PROGRESS:";

            long lastLine = Environment.TickCount64;
            bool killed = false;
            using var stall = new System.Threading.Timer(_ =>
            {
                if (Environment.TickCount64 - Interlocked.Read(ref lastLine) < AnalyzeStallMs) return;
                killed = true;
                try { p.Kill(entireProcessTree: true); } catch { }
            }, null, 10_000, 10_000);

            while ((line = p.StandardOutput.ReadLine()) != null)
            {
                Interlocked.Exchange(ref lastLine, Environment.TickCount64);
                if (line.StartsWith(POSTEP, StringComparison.Ordinal))
                {
                    var czesci = line[POSTEP.Length..].Split('/');
                    if (czesci.Length == 2
                        && long.TryParse(czesci[0], out var wyslane)
                        && long.TryParse(czesci[1], out var calosc))
                        PostToJs("tools.analyze.progress", new { path, sent = wyslane, total = calosc });
                    continue;
                }
                lines.Add(line);
            }
            p.WaitForExit();
            try { drain.Wait(2000); } catch { }

            if (killed)
                return new AnalyzeResult
                {
                    Ok = false, Path = path,
                    Error = "Analiza przerwana — serwer nie odpowiadał przez dłuższy czas. "
                          + "Spróbuj ponownie dla tego pliku.",
                };

            return ParseAnalyzeOutput(lines, p.ExitCode, stderr.ToString(), path);
        }
        catch (Exception ex) { return new AnalyzeResult { Ok = false, Error = ex.Message, Path = path }; }
    }

    internal static AnalyzeResult ParseAnalyzeOutput(List<string> lines, int exitCode, string stderr, string path)
    {
        const string PM = "ANALYZE-VERDICT:malware:";
        const string PC = "ANALYZE-VERDICT:clean";
        const string PE = "ANALYZE-VERDICT:error";
        const string PL = "ANALYZE-LABEL:";   
        const string PV = "ANALYZE-VT:";
        bool sawVerdict = false, detected = false;
        string? det = null, err = null, label = null;
        int vtDetected = 0, vtTotal = 0;

        foreach (var line in lines)
        {
            if (line.StartsWith(PM, StringComparison.Ordinal))
            { sawVerdict = true; detected = true; det = line[PM.Length..].Trim(); }
            else if (line.StartsWith(PC, StringComparison.Ordinal))
            {
                sawVerdict = true;
                if (!detected) detected = false;
            }
            else if (line.StartsWith(PL, StringComparison.Ordinal)) label = line[PL.Length..].Trim();
            else if (line.StartsWith(PV, StringComparison.Ordinal))
            {
                var parts = line[PV.Length..].Trim().Split('/');
                if (parts.Length == 2) { int.TryParse(parts[0], out vtDetected); int.TryParse(parts[1], out vtTotal); }
            }
            else if (line.StartsWith(PE, StringComparison.Ordinal))
            {
                sawVerdict = true;

                var rest = line[PE.Length..];
                err = rest.StartsWith(":", StringComparison.Ordinal) ? rest[1..].Trim() : rest.Trim();
                if (err.Length == 0) err = "nieznany błąd analizy";
            }
        }

        if (err != null)
        {
            string msg = err.StartsWith("cloud-disabled", StringComparison.Ordinal)
                    ? "Skanowanie w chmurze jest niedostępne."
                : err.StartsWith("scan-inconclusive", StringComparison.Ordinal)
                    ? "Analiza nierozstrzygająca — silniki nie zwróciły jednoznacznego wyniku. Spróbuj ponownie."
                : err.StartsWith("file-not-found", StringComparison.Ordinal)
                    ? "Skaner nie znalazł pliku."
                : err.Contains("HTTP 413", StringComparison.Ordinal)
                    ? "Plik jest za duży dla serwera analizy — maksymalny rozmiar to 1 GB."
                : err.Contains("HTTP 502", StringComparison.Ordinal)
                    || err.Contains("HTTP 503", StringComparison.Ordinal)
                    || err.Contains("HTTP 504", StringComparison.Ordinal)
                    ? "Serwer analizy jest chwilowo niedostępny. Spróbuj ponownie za chwilę."
                : err.Contains("HTTP 429", StringComparison.Ordinal)
                    ? "Zbyt wiele zgłoszeń w krótkim czasie — odczekaj chwilę i spróbuj ponownie."
                : $"Błąd analizy w chmurze: {err}";
            return new AnalyzeResult { Ok = false, Error = msg, Path = path };
        }

        if (!sawVerdict)
        {
            var why = stderr.Trim();
            if (why.Length > 300) why = why[..300] + "…";
            var detail = why.Length > 0 ? $" Skaner zgłosił: {why}"
                       : $" Skaner zakończył się kodem {exitCode} bez podania wyniku.";
            return new AnalyzeResult
            {
                Ok = false,
                Error = "Analiza nie dała wyniku — pliku NIE uznano za bezpieczny." + detail,
                Path = path,
            };
        }

        return detected
            ? new AnalyzeResult { Ok = true, Detected = true, Name = det, Source = "Cloud:scan", Path = path,
                                  Label = label, VtDetected = vtDetected, VtTotal = vtTotal }
            : new AnalyzeResult { Ok = true, Detected = false, Path = path,
                                  Label = label, VtDetected = vtDetected, VtTotal = vtTotal };
    }

    private List<string> RunSysRepairRaw(string[] args)
    {
        var lines = new List<string>();
        string? malscan = _verify?.MalscanPath;
        if (string.IsNullOrEmpty(malscan) || !File.Exists(malscan)) return lines;
        try
        {
            var psi = new ProcessStartInfo(malscan)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,

                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding  = System.Text.Encoding.UTF8,
                WorkingDirectory = Path.GetDirectoryName(malscan) ?? "",
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p == null) return lines;
            string? line;
            while ((line = p.StandardOutput.ReadLine()) != null) lines.Add(line);
            p.WaitForExit(60_000);
        }
        catch (Exception ex) { Console.Error.WriteLine($"[!] sysrepair: {ex.Message}"); }
        return lines;
    }

    private object[] RunSysRepair(string[] args)
    {
        var items = new List<object>();
        foreach (var line in RunSysRepairRaw(args))
        {
            if (!line.StartsWith("SYSREPAIR-ITEM\t", StringComparison.Ordinal)) continue;
            var f = ParseKv(line);
            items.Add(new
            {
                id       = f.GetValueOrDefault("id"),
                name     = f.GetValueOrDefault("name"),
                category = f.GetValueOrDefault("cat"),
                tampered = f.GetValueOrDefault("tampered") == "1",
                auto     = f.GetValueOrDefault("auto") == "1",
                desc     = f.GetValueOrDefault("desc"),
                detail   = f.GetValueOrDefault("detail"),
            });
        }
        return items.ToArray();
    }

    private static Dictionary<string, string> ParseKv(string line)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in line.Split('\t'))
        {
            int eq = part.IndexOf('=');
            if (eq > 0) d[part[..eq]] = part[(eq + 1)..];
        }
        return d;
    }

    private DateTime _lastSysRepair = DateTime.MinValue;

    private void TriggerAutoSystemRepair()
    {
        if ((DateTime.UtcNow - _lastSysRepair).TotalSeconds < 60) return;
        _lastSysRepair = DateTime.UtcNow;

        _ = Task.Run(() =>
        {
            try
            {
                var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    if (_settings?.Read()?["sysrepair_disabled"] is JsonArray arr)
                        foreach (var n in arr) { var s = n?.GetValue<string>(); if (!string.IsNullOrEmpty(s)) disabled.Add(s!); }
                }
                catch { }

                var tamperedAuto   = new List<(string id, string name)>();
                var tamperedManual = new List<(string id, string name)>();
                foreach (var line in RunSysRepairRaw(new[] { "sysrepair", "scan" }))
                {
                    if (!line.StartsWith("SYSREPAIR-ITEM\t", StringComparison.Ordinal)) continue;
                    var f = ParseKv(line);
                    var id = f.GetValueOrDefault("id") ?? "";
                    if (f.GetValueOrDefault("tampered") != "1" || disabled.Contains(id)) continue;
                    var name = f.GetValueOrDefault("name") ?? id;
                    if (f.GetValueOrDefault("auto") == "1") tamperedAuto.Add((id, name));
                    else tamperedManual.Add((id, name));
                }

                var bootFixed = MaybeAutoRestoreBootSectors();

                if (tamperedAuto.Count == 0 && tamperedManual.Count == 0 && bootFixed == null) return;

                var fixedIds = new HashSet<string>(StringComparer.Ordinal);
                if (tamperedAuto.Count > 0)
                    foreach (var line in RunSysRepairRaw(new[] { "sysrepair", "fix", string.Join(",", tamperedAuto.Select(t => t.id)) }))
                    {
                        if (!line.StartsWith("SYSREPAIR-FIX\t", StringComparison.Ordinal)) continue;
                        var f = ParseKv(line);
                        if (f.GetValueOrDefault("ok") == "1") fixedIds.Add(f.GetValueOrDefault("id") ?? "");
                    }

                var fixedNames = tamperedAuto.Where(t => fixedIds.Contains(t.id)).Select(t => t.name).ToList();
                if (bootFixed != null) fixedNames.Add(bootFixed);
                var failed = tamperedAuto.Where(t => !fixedIds.Contains(t.id)).Select(t => t.name)
                              .Concat(tamperedManual.Select(t => t.name)).ToList();

                var repairIcon = AssetBytes("fixedwindows.png");

                if (fixedNames.Count > 0)
                {
                    PostToJs("sysrepair.autofixed", new { items = fixedNames });

                    var names = new List<string>(fixedNames);
                    void BuildFixed()
                    {
                        try
                        {
                            bool dark = ResolveDark(_guiSettings?.Read()?.Theme ?? "auto");

                            RichInfoPopupForm Zbuduj() => new(dark,
                                System.Drawing.Color.FromArgb(0x2C, 0x7B, 0xD6),
                                repairIcon, "Przywrócono domyślne ustawienia systemu",
                                "Malware zmieniło ustawienia systemu przez złośliwe oprogramowanie lub niepożądaną " +
                                "czynność. Przywrócono domyślne, bezpieczne wartości.",
                                names, "OK", null, autoDismissSec: 25,
                                logoPng: AssetBytes("logo.png") ?? AssetBytes("ic-logo.png"));

                            if (!ShieldPopupHub.Report("repair", "Przywrócono domyślne ustawienia systemu",
                                                       () => Zbuduj()))
                                Zbuduj().Show();
                        }
                        catch { }
                    }
                    if (Ui.HasAccess) BuildFixed();
                    else Ui.Post((BuildFixed));
                }

                if (failed.Count > 0)
                {
                    string bad = string.Join(", ", failed.Take(4))
                        + (failed.Count > 4 ? $" i {failed.Count - 4} więcej" : "");
                    ShowActionPopup(
                        "Wykryto zmiany w systemie wymagające uwagi",
                        $"Niektóre ustawienia systemu zostały zmienione ({bad}) i wymagają ręcznej naprawy.",
                        "Pokaż więcej", () => OpenSysRepairApplet(),
                        "Później", () => { },
                        autoDismissSec: 30, iconPng: repairIcon);
                }
            }
            catch { }
        });
    }

    private string? MaybeAutoRestoreBootSectors()
    {
        try
        {
            if (_backupClient == null) return null;
            var statusJson = _backupClient.BootStatusJsonAsync().GetAwaiter().GetResult();
            if (string.IsNullOrEmpty(statusJson)) return null;
            bool changed = false;
            using (var doc = System.Text.Json.JsonDocument.Parse(statusJson))
            {
                if (doc.RootElement.TryGetProperty("drives", out var drives)
                    && drives.ValueKind == System.Text.Json.JsonValueKind.Array)
                    foreach (var dr in drives.EnumerateArray())
                        if (dr.TryGetProperty("state", out var st) && st.GetString() == "changed") changed = true;
            }
            if (!changed) return null;

            var restoreJson = _backupClient.BootRestoreJsonAsync(null, all: true).GetAwaiter().GetResult();
            return restoreJson != null ? "Sektory rozruchowe (MBR/GPT)" : null;
        }
        catch { return null; }
    }

    private void OpenSysRepairApplet()
    {
        Ui.Send(() =>
        {
            try
            {
                _tray?.Restore();
                Navigate("#/tools");
                WebView!.CoreWebView2.ExecuteScriptAsync(
                    "setTimeout(()=>document.querySelector('[data-tools-tab=\\\"hips\\\"]')?.click(),160);");
            }
            catch { }
        });
    }

    private void PushProtectionStatus()
    {
        string state = _resident?.State() ?? "unavailable";
        bool wanted = ResidentModuleWanted();

        if (_reconfiguringModules && wanted && state is not ("not-installed" or "unavailable"))
            state = "running";
        bool available = _resident != null;
        bool running = state == "running";
        PostToJs("protection.status", new
        {
            available,
            state,
            enabled = wanted,
        });
        try { _tray?.SetProtectionState(available, wanted, running); } catch { }

        string nState = _network?.State() ?? "unavailable";
        bool nAvail = _network != null;
        bool nWanted = NetworkModuleWanted();

        if (_reconfiguringModules && nWanted && nState is not ("not-installed" or "unavailable"))
            nState = "running";
        bool nRunning = nState == "running";

        bool urlDbReady = false;
        try
        {
            var dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data");

            if (File.Exists(Path.Combine(dataDir, "urls.vdeb"))) urlDbReady = true;
            if (!urlDbReady)
            {
                foreach (var prof in new[] { "low", "low-ads", "medium", "medium-ads", "high", "high-ads" })
                {
                    if (File.Exists(Path.Combine(dataDir, $"urls-{prof}.vdeb"))) { urlDbReady = true; break; }
                }
            }
        }
        catch { }

        nRunning = nRunning && urlDbReady;

        string nStateForUi = (nState == "running" && !urlDbReady) ? "loading-db" : nState;

        PostToJs("protection.network.status", new
        {
            available = nAvail,
            state = nStateForUi,
            enabled = nWanted,
            url_db_ready = urlDbReady,
        });
        try { _tray?.SetNetworkState(nAvail, nWanted, nRunning); } catch { }

        try
        {
            bool bkAvail = _backupClient.IsAvailable;
            bool bkOn    = BackupIsEnabled();
            bool snapOn  = false;
            try { snapOn = _backupSettings.Read()["on_file_change"]?.GetValue<bool>() ?? false; } catch { }
            bool remOn   = false;
            try { remOn = _residentSettings?.Read()?["scan_removable"]?.GetValue<bool>() ?? false; } catch { }

            _tray?.SetBackupState(bkAvail, bkOn);

            _tray?.SetSnapshotsState(bkAvail && bkOn, snapOn);

            _tray?.SetRemovableState(available, remOn);
        }
        catch { }

        try
        {
            var gs = _guiSettings?.Read();
            string lu = "—";
            if (gs != null && gs.LastUpdateCheckUnix > 0)
            {
                lu = DateTimeOffset.FromUnixTimeSeconds(gs.LastUpdateCheckUnix)
                    .LocalDateTime.ToString("yyyy-MM-dd HH:mm");
            }
            string ver = System.Reflection.Assembly.GetExecutingAssembly()
                .GetName().Version?.ToString(3) ?? "—";
            string vpsDbVer = "—";
            try { vpsDbVer = _dbVersions?.VpsVersion(Path.Combine(_appDataDir, "data", "vps.vdeb")) ?? "—"; } catch { }
            _tray?.SetFooterInfo(lu, ver, vpsDbVer);
        }
        catch { }

        RefreshTrayHealth();
    }

    private void RefreshTrayHealth()
    {
        try
        {
            var h = ComputeHealth();
            _tray?.SetHealthOverlay(h.badge);
            PostToJs("health.status", new
            {
                level = h.badge == HealthBadge.Error ? "err" : (h.badge == HealthBadge.Warn ? "warn" : "ok"),
                title = h.title,
                sub   = h.sub,
            });
        }
        catch { }
    }

    private DateTime? EffectiveDbWriteTime(string vdebName, string? overlayName)
    {
        try
        {
            var dataDir = Path.Combine(_appDataDir, "data");
            var vdeb = Path.Combine(dataDir, vdebName);
            if (!File.Exists(vdeb)) return null;
            DateTime newest = File.GetLastWriteTime(vdeb);
            void Bump(string p)
            {
                try { if (File.Exists(p)) { var t = File.GetLastWriteTime(p); if (t > newest) newest = t; } }
                catch { }
            }
            if (!string.IsNullOrEmpty(overlayName)) Bump(Path.Combine(dataDir, overlayName));
            Bump(Path.Combine(dataDir, "db-seq.json"));
            return newest;
        }
        catch { return null; }
    }

    private (HealthBadge badge, string title, string sub) ComputeHealth()
    {
        try
        {
            var fresh = FileVerification.Verify();
            if (fresh.HasCritical || (_verify?.HasCritical ?? false))
            {
                _verify = fresh;

                var names = string.Join(", ", fresh.Issues.Where(i => i.Critical)
                                                          .Select(i => i.File).Take(4));
                return (HealthBadge.Error, "Program jest uszkodzony, wymagana reinstalacja",
                    string.IsNullOrEmpty(names)
                        ? "Brakuje plików programu. Zainstaluj Malward ponownie."
                        : $"Brakuje plików: {names}. Zainstaluj Malward ponownie.");
            }
            _verify = fresh;
        }
        catch
        {
            if (_verify != null && _verify.HasCritical)
                return (HealthBadge.Error, "Program jest uszkodzony, wymagana reinstalacja",
                    "Brakuje plików programu. Zainstaluj Malward ponownie.");
        }

        bool dbMissing = false;
        TimeSpan dbAge = TimeSpan.Zero;
        try
        {
            var eff = EffectiveDbWriteTime("vps.vdeb", "vps-overlay.txt");
            if (eff.HasValue) dbAge = DateTime.Now - eff.Value;
            else dbMissing = true;
        }
        catch { }

        if (!dbMissing && dbAge > TimeSpan.FromDays(7))
            return (HealthBadge.Error, "Baza definicji jest nieaktualna",
                "Baza wirusów ma ponad 7 dni. Zaktualizuj ją jak najszybciej.");
        if (dbMissing)
            return (HealthBadge.Warn, "Brak zainstalowanej bazy",
                "Pobierz i zainstaluj bazę danych wirusów, aby zwiększyć skuteczność ochrony.");
        if (dbAge > TimeSpan.FromDays(1))
            return (HealthBadge.Warn, "Zaktualizuj bazę definicji",
                "Baza wirusów jest starsza niż 1 dzień. Zalecana aktualizacja.");

        var exposure = AssessSystemExposure();
        if (exposure.critical)
            return (HealthBadge.Error, "Stan zagrożenia bezpieczeństwa systemu", exposure.sub);

        if (AnyPresentShieldDisabled())
            return (HealthBadge.Warn, "Niektóre osłony są wyłączone",
                "Włącz wszystkie dostępne moduły ochrony, aby zapewnić pełne bezpieczeństwo.");

        var offModules = DisabledResidentModules();
        if (offModules.Count > 0)
            return (HealthBadge.Warn, "Niektóre moduły osłony rezydentnej są wyłączone",
                $"Nie masz pełnej ochrony. Wyłączone: {string.Join(", ", offModules.Take(4))}" +
                (offModules.Count > 4 ? $" i {offModules.Count - 4} więcej." : "."));

        return (HealthBadge.None, "Wszystko jest w porządku", "Bazy definicji wirusów są aktualne.");
    }

    private List<string> DisabledResidentModules()
    {
        var off = new List<string>();
        try
        {
            if (_scannerEdition || _resident == null) return off;
            if (!ResidentModuleWanted() || _resident.State() != "running") return off;

            var cfg = new ResidentSettingsStore(_appDataDir).Read();
            bool On(string key, bool dflt = true)
            {
                try { return cfg[key]?.GetValue<bool>() ?? dflt; }
                catch { return dflt; }
            }

            if (!On("file_monitor"))       off.Add("monitor plików");
            if (!On("active_process_scan")) off.Add("monitor procesów");
            if (!On("behavior_monitor"))   off.Add("analiza zachowań");
            if (!On("cloud_enabled"))      off.Add("sprawdzanie w chmurze");
            if (!On("usn_journal"))        off.Add("dziennik zmian USN");
            if (!On("boot_backup"))        off.Add("kopia sektora rozruchowego");

            try
            {
                var hips = Path.Combine(_appDataDir, "data", "hips-rules.json");
                if (File.Exists(hips)
                    && System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(hips)) is System.Text.Json.Nodes.JsonObject h
                    && h["enabled"]?.GetValue<bool>() == false)
                    off.Add("ochrona składników systemu");
            }
            catch { }
        }
        catch { }
        return off;
    }

    private (int present, int on) OwnShieldTally()
    {
        int present = 0, on = 0;
        try
        {
            if (_resident != null)
            {
                present++;
                if (ResidentModuleWanted() && _resident.State() == "running") on++;
            }
            if (_network != null)
            {
                present++;
                if (NetworkModuleWanted() && _network.State() == "running") on++;
            }
            var fw = ReadFirewallPower();
            if (fw.available)
            {
                present++;
                if (fw.enabled) on++;
            }
        }
        catch { }
        return (present, on);
    }

    private bool AllOwnShieldsOff()
    {
        if (_scannerEdition) return false;
        var (present, on) = OwnShieldTally();
        return present > 0 && on == 0;
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static bool DefenderTurnedOff()
    {
        try
        {
            using (var pol = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                       @"SOFTWARE\Policies\Microsoft\Windows Defender"))
            {
                if (pol?.GetValue("DisableAntiSpyware") is int d && d == 1) return true;
            }
            using (var rtp = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                       @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"))
            {
                if (rtp?.GetValue("DisableRealtimeMonitoring") is int r && r == 1) return true;
            }
        }
        catch { }

        try
        {
            using var sc = new System.ServiceProcess.ServiceController("WinDefend");
            return sc.Status != System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch { return false; }
    }

    private const string ExposureShieldsOnly =
        "Wszystkie osłony Malward są wyłączone. Nic nie blokuje zagrożeń w czasie rzeczywistym — włącz osłony programu.";

    private const string ExposureFirewall =
        "Osłony Malward są nieaktywne, a zapora systemu Windows jest wyłączona. System pozostaje bez ochrony — włącz osłony programu albo zabezpieczenia systemu.";

    private const string ExposureDefender =
        "Osłony Malward są nieaktywne, a program Windows Defender jest wyłączony. System pozostaje bez ochrony — włącz osłony programu albo zabezpieczenia systemu.";

    private const string ExposureBoth =
        "Osłony Malward są nieaktywne, zapora systemu Windows jest wyłączona i program Windows Defender jest wyłączony. System pozostaje całkowicie bez ochrony — włącz osłony programu natychmiast.";

    private (bool critical, string sub) AssessSystemExposure()
    {
        if (!AllOwnShieldsOff()) return (false, "");

        bool defOff = DefenderTurnedOff();
        bool fwOff = false;
        try
        {
            var fw = ReadFirewallPower();
            fwOff = fw.available && !fw.enabled;
        }
        catch { }

        if (fwOff && defOff) return (true, ExposureBoth);
        if (defOff) return (true, ExposureDefender);
        if (fwOff) return (true, ExposureFirewall);
        return (true, ExposureShieldsOnly);
    }

    private bool AnyPresentShieldDisabled()
    {
        if (_scannerEdition) return false;
        try
        {
            if (_resident != null && (!ResidentModuleWanted() || _resident.State() != "running")) return true;
            if (_network  != null && (!NetworkModuleWanted()  || _network.State()  != "running")) return true;
            var fw = ReadFirewallPower();
            if (!fw.enabled) return true;
        }
        catch { }
        return false;
    }

    private JsonObject GatherSettingsBundle()
    {
        var bundle = new JsonObject
        {
            ["format"]   = "malward-settings",
            ["version"]  = 1,
            ["exported"] = DateTimeOffset.Now.ToString("o"),
            ["scanner"]  = SafeReadJson(() => _settings?.Read()),
            ["resident"] = SafeReadJson(() => _residentSettings?.Read()),
            ["network"]  = SafeReadJson(() => _networkSettings?.Read()),
            ["backup"]   = SafeReadJson(() => _backupSettings.Read()),
        };
        try
        {
            var gs = _guiSettings?.Read() ?? new GuiSettings();
            bundle["gui"] = new JsonObject
            {
                ["theme"] = gs.Theme,
                ["lang"]  = gs.Lang,
                ["auto_update_enabled"] = gs.AutoUpdateEnabled,
                ["auto_update_minutes"] = gs.AutoUpdateMinutes,
            };
        }
        catch { }
        return bundle;
    }

    private static JsonNode SafeReadJson(Func<JsonObject?> read)
    {
        try { var o = read(); return o == null ? new JsonObject() : (JsonNode.Parse(o.ToJsonString()) ?? new JsonObject()); }
        catch { return new JsonObject(); }
    }

    private void ExportSettings()
    {
        try
        {
            var docelowy = Picker.SaveFile(Loc.T("Eksportuj ustawienia Malward"),
                "Ustawienia Malward (*.json)|*.json|Wszystkie pliki (*.*)|*.*",
                $"malward-ustawienia-{DateTime.Now:yyyyMMdd}.json");
            if (docelowy == null) { PostToJs("settings.export.result", new { ok = false }); return; }
            var bundle = GatherSettingsBundle();
            using (var fs = File.Create(docelowy))
            using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true }))
                bundle.WriteTo(w);
            PostToJs("settings.export.result", new { ok = true });
        }
        catch (Exception ex) { PostToJs("settings.export.result", new { ok = false, error = ex.Message }); }
    }

    private void ImportSettings()
    {
        try
        {
            var zrodlowy = Picker.OpenFile(Loc.T("Importuj ustawienia Malward"),
                "Ustawienia Malward (*.json)|*.json|Wszystkie pliki (*.*)|*.*", mustExist: true);
            if (zrodlowy == null) { PostToJs("settings.bundle.result", new { ok = false, action = "import" }); return; }
            var raw = File.ReadAllText(zrodlowy);
            if (JsonNode.Parse(raw) is not JsonObject bundle)
            {
                PostToJs("settings.bundle.result", new { ok = false, action = "import", error = "Nieprawidłowy plik ustawień." });
                return;
            }
            ApplySettingsBundle(bundle);
            _ = ReloadModulesAfterSettingsChangeAsync();
            PostToJs("settings.bundle.result", new { ok = true, action = "import" });
        }
        catch (Exception ex) { PostToJs("settings.bundle.result", new { ok = false, action = "import", error = ex.Message }); }
    }

    private void StripMalwardExclusions(JsonObject section)
    {
        try
        {
            if (section["exclusions"] is not JsonArray arr) return;
            var own = new List<string>();
            try { if (!string.IsNullOrEmpty(_appDataDir)) own.Add(_appDataDir.TrimEnd('\\')); } catch { }
            try { own.Add(AppContext.BaseDirectory.TrimEnd('\\')); } catch { }
            if (own.Count == 0) return;

            var kept = new JsonArray();
            foreach (var node in arr.OfType<JsonObject>())
            {
                var path = node["path"]?.GetValue<string>()?.TrimEnd('\\') ?? "";
                if (own.Any(o => string.Equals(o, path, StringComparison.OrdinalIgnoreCase))) continue;
                kept.Add(node.DeepClone());
            }
            section["exclusions"] = kept;
        }
        catch { }
    }

    private void ApplySettingsBundle(JsonObject bundle)
    {
        if (bundle["scanner"]  is JsonObject sc && _settings != null)
        { var scc = (JsonObject)sc.DeepClone(); StripMalwardExclusions(scc); _settings.Write(scc); }
        if (bundle["resident"] is JsonObject rs)
        { var rsc = (JsonObject)rs.DeepClone(); StripMalwardExclusions(rsc); _residentSettings?.Write(rsc); }
        if (bundle["network"]  is JsonObject nw) _networkSettings?.Write((JsonObject)nw.DeepClone());
        if (bundle["backup"]   is JsonObject bk) _backupSettings.Merge((JsonObject)bk.DeepClone());

        if (bundle["hips"]     is JsonObject hp) ApplyHipsProfile(hp);

        if (false && bundle["gui"] is JsonObject g)
        {
            try
            {
                var cur  = _guiSettings?.Read() ?? new GuiSettings();
                string theme = g["theme"]?.GetValue<string>() ?? cur.Theme;
                string lang  = g["lang"]?.GetValue<string>() ?? cur.Lang;
                bool auto    = g["auto_update_enabled"]?.GetValue<bool>() ?? cur.AutoUpdateEnabled;
                int mins     = g["auto_update_minutes"]?.GetValue<int>() ?? cur.AutoUpdateMinutes;

                _guiSettings?.Write(new GuiSettings(theme, lang, auto, mins, cur.LastUpdateCheckUnix,
                                                    cur.ActiveProfile));
            }
            catch { }
        }
    }

    private void ApplyHipsProfile(JsonObject hp)
    {
        try
        {
            var path = Path.Combine(_appDataDir, "data", "hips-rules.json");
            JsonNode? exceptions = null;
            try
            {
                if (File.Exists(path) && JsonNode.Parse(File.ReadAllText(path)) is JsonObject cur)
                    exceptions = cur["exceptions"]?.DeepClone();
            }
            catch { }
            var o = new JsonObject
            {
                ["enabled"] = hp["enabled"]?.GetValue<bool>() ?? true,
                ["tier"]    = hp["tier"]?.GetValue<string>() ?? "medium",
            };
            if (exceptions != null) o["exceptions"] = exceptions;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, o.ToJsonString());
        }
        catch (Exception ex) { CrashLog.Write("hips-profile", ex); }
    }

    private void ApplySecurityProfile(string? name)
    {
        name = (name ?? "").Trim().ToLowerInvariant();
        if (name is not ("low" or "medium" or "high" or "paranoic"))
        {
            PostToJs("settings.bundle.result", new { ok = false, action = "profile", error = "Nieznany profil." });
            return;
        }
        try
        {
            if (_assets == null || !_assets.TryGet($"profiles/{name}.json", out var data))
            {
                PostToJs("settings.bundle.result", new { ok = false, action = "profile", error = "Brak pliku profilu w pakiecie." });
                return;
            }
            if (JsonNode.Parse(System.Text.Encoding.UTF8.GetString(data)) is not JsonObject bundle)
            {
                PostToJs("settings.bundle.result", new { ok = false, action = "profile", error = "Nieprawidłowy plik profilu." });
                return;
            }
            ApplySettingsBundle(bundle);
            _ = ReloadModulesAfterSettingsChangeAsync();
            ApplyLolbinRulesForProfile(name);
            PostToJs("settings.bundle.result", new { ok = true, action = "profile", profile = name });
        }
        catch (Exception ex)
        {
            PostToJs("settings.bundle.result", new { ok = false, action = "profile", error = ex.Message });
        }
    }

    private void ApplyLolbinRulesForProfile(string profile)
    {
        if (!_fwAvailable) return;
        if (profile == "low") return;
        bool pelny = profile is "high" or "paranoic";
        _ = Task.Run(() =>
        {
            try
            {
                var (created, skipped, err) = Malward.FWManager.FirewallRules.AddLolbinHardening(pelny);
                var zakres = pelny ? "pełny" : "zalecany";
                if (err != null && created == 0)
                {
                    Ui.Post((() => PostToJs("toast",
                        new { level = "warn", msg = $"Reguły zapory dla profilu: {err}" })));
                    return;
                }

                if (created == 0) return;
                Ui.Post((() => PostToJs("toast", new
                {
                    level = "info",
                    msg = $"Profil {profile}: dodano {created} reguł zapory ({zakres} zestaw, pominięto {skipped}).",
                })));
            }
            catch (Exception ex)
            {
                Ui.Post((() => PostToJs("toast",
                    new { level = "warn", msg = $"Reguły zapory dla profilu: {ex.Message}" })));
            }
        });
    }

    private JsonObject? DefaultProfileSection(string section)
    {
        try
        {
            if (_assets != null
                && _assets.TryGet("profiles/medium.json", out var data)
                && JsonNode.Parse(System.Text.Encoding.UTF8.GetString(data)) is JsonObject bundle)
                return bundle[section] as JsonObject;
        }
        catch (Exception ex) { CrashLog.Write("profile", ex); }
        return null;
    }

    private void SeedDefaultProfileOnFirstRun()
    {
        try
        {
            if (_guiSettings == null) return;

            var zapisane = _guiSettings.Read();
            if (_guiSettings.Exists && zapisane.ActiveProfile != null) return;
            if (_assets == null
                || !_assets.TryGet("profiles/medium.json", out var data)
                || JsonNode.Parse(System.Text.Encoding.UTF8.GetString(data)) is not JsonObject bundle)
            {
                CrashLog.Write("profile", null,
                    "first run: profiles/medium.json is missing from the asset pack, keeping the built-in defaults");
                return;
            }

            ApplySettingsBundle(bundle);
            ApplyLolbinRulesForProfile("medium");

            _guiSettings.Write(zapisane with { ActiveProfile = "medium" });
            CrashLog.Write("profile", null, "first run: applied the medium profile as the default");
        }
        catch (Exception ex) { CrashLog.Write("profile", ex); }
    }

    private void RestoreDefaultSettings()
    {
        try
        {
            if (_assets != null
                && _assets.TryGet("profiles/medium.json", out var data)
                && JsonNode.Parse(System.Text.Encoding.UTF8.GetString(data)) is JsonObject bundle)
            {
                ApplySettingsBundle(bundle);
                _ = ReloadModulesAfterSettingsChangeAsync();
                ApplyLolbinRulesForProfile("medium");
                PostToJs("settings.bundle.result", new { ok = true, action = "restore", profile = "medium" });
                return;
            }

            _settings?.Write(SettingsBridge.Defaults());
            _residentSettings?.Write(new JsonObject());
            _networkSettings?.Write(new JsonObject());
            try { if (_backupSettings.Exists) File.Delete(_backupSettings.FilePath); } catch { }
            try
            {
                var cur = _guiSettings?.Read() ?? new GuiSettings();

                _guiSettings?.Write(new GuiSettings("auto", cur.Lang, true, 360, cur.LastUpdateCheckUnix,
                                                    "medium", cur.Autostart, cur.ContextMenu));
            }
            catch { }
            _ = ReloadModulesAfterSettingsChangeAsync();
            PostToJs("settings.bundle.result", new { ok = true, action = "restore" });
        }
        catch (Exception ex) { PostToJs("settings.bundle.result", new { ok = false, action = "restore", error = ex.Message }); }
    }

    private async Task ReloadModulesAfterSettingsChangeAsync()
    {
        _reconfiguringModules = true;
        try
        {
            if (_resident != null && !_resident.IsRunning() && ResidentServiceController.ModuleEnabled())
            {
                try { await _resident.EnsureHostRunningAsync(); } catch { }
            }

            try
            {
                if (_network != null)
                {
                    bool wantNet = _networkSettings?.Read()?["enabled"]?.GetValue<bool>()
                                   ?? _network.IsModuleEnabled();
                    if (wantNet) await _network.EnableAsync();
                    else         await _network.DisableAsync();
                }
            }
            catch { }

            try { _backupSettings.RestartService(); } catch { }
        }
        finally
        {
            _reconfiguringModules = false;

            try { Ui.Send(() => { RefreshTrayHealth(); PushProtectionStatus(); }); } catch { }
        }
    }

    private void StartQuickScanInBackground()
    {
        if (_scanActive) return;
        if (_engine == null) return;
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        _scanActive = true;
        _scanStartedUtc = DateTime.UtcNow;
        _scanTarget = @"C:\Users";
        _scanMode = "quick";
        _tray?.SetBusy(BusyKind.Scan);
        PostScanStarted(_scanTarget, _scanMode);

        EnsureMiniScanPopup();
        _miniScan?.SetMode(ScanProgressForm.Mode.Running, "szybki skan", 0);
        _ = Task.Run(async () =>
        {
            try { await _engine!.RunScanAsync(_scanTarget, _scanCts.Token, profile: "quick"); }
            catch (Exception ex) { PostToJs("engine.log", new { level = "error", msg = $"scan: {ex.Message}" }); }
            finally { _scanActive = false; _tray?.SetBusy(BusyKind.None); TrimMemoryNow("scan"); }
        });
    }

    private void RestoreToScanViewIfActive()
    {
        try
        {
            _tray?.Restore();
            if (_scanActive)
            {
                Ui.Post((() =>
                {
                    try
                    {
                        PostToJs("ui.navigate", new { hash = "#/scan/progress" });
                        PostToJs("scan.is-active", new { active = true, target = _scanTarget, mode = _scanMode, token = _scanToken });
                    }
                    catch { }
                }));
            }
        }
        catch { }
    }

    private static string BackupDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data");

    private async Task RunBootBackupOnceAsync()
    {
        try
        {
            var marker = Path.Combine(BackupDataDir, ".bootbackup-done");

            if (File.Exists(marker) || File.Exists(Path.Combine(BackupDataDir, ".prebackup-done"))) return;
            Directory.CreateDirectory(BackupDataDir);
            if (_backupClient != null) await _backupClient.BootBackupJsonAsync();
            File.WriteAllText(marker, DateTimeOffset.UtcNow.ToString("o"));
        }
        catch { }
    }

    private const int InitialBackupAskSeconds = 300;

    private string InitialBackupMarker => Path.Combine(BackupDataDir, ".initial-backup-done");
    private string InitialBackupSkipMarker => Path.Combine(BackupDataDir, ".initial-backup-skipped");

    private TaskCompletionSource<string>? _backupAsk;
    private CancellationTokenSource? _initialBackupCts;

    internal void AnswerInitialBackup(string choice) => _backupAsk?.TrySetResult(choice);

    internal void CancelInitialBackup()
    {
        try { _backupClient?.RequestCancel(); } catch { }
        try { _initialBackupCts?.Cancel(); } catch { }
    }

    private async Task<string> AskInitialBackupAsync(BackupEngineClient.BackupEstimate? est)
    {
        _backupAsk = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        Ui.Send(() => PostToJs("backup.initial.ask", new
        {
            files = est?.Files ?? 0,
            bytes = est?.Bytes ?? 0,
            etaSec = est?.EtaSec ?? -1,
        }));

        var answered = await Task.WhenAny(_backupAsk.Task, Task.Delay(TimeSpan.FromMinutes(5)));
        var choice = answered == _backupAsk.Task ? _backupAsk.Task.Result : "background";
        _backupAsk = null;
        Ui.Send(() => PostToJs("backup.initial.ask.close", new { }));
        return choice;
    }

    private async Task RunFirstRunPrebackupAsync(Action<string, string> emit)
    {
        try
        {
            await RunBootBackupOnceAsync();

            if (File.Exists(InitialBackupMarker)) { emit("uptodate", "Kopia wstępna już istnieje"); return; }
            if (File.Exists(InitialBackupSkipMarker)) { emit("uptodate", "Kopia wstępna pominięta przez użytkownika"); return; }
            if (_backupClient == null || !_backupClient.IsAvailable)
            {
                emit("uptodate", "Kopia zapasowa niedostępna — krok pominięty");
                return;
            }

            Directory.CreateDirectory(BackupDataDir);

            emit("busy", "Sprawdzanie, ile danych trzeba skopiować…");
            var est = await _backupClient.EstimateAsync();

            string choice = "now";
            long eta = est?.EtaSec ?? -1;
            if (est == null || eta < 0 || eta > InitialBackupAskSeconds)
                choice = await AskInitialBackupAsync(est);

            if (choice == "skip")
            {
                try { File.WriteAllText(InitialBackupSkipMarker, DateTimeOffset.UtcNow.ToString("o")); } catch { }
                emit("uptodate", "Kopia wstępna pominięta — możesz ją uruchomić w panelu kopii zapasowej");
                return;
            }

            if (choice == "background")
            {
                StartInitialBackupInBackground();
                emit("ok", "Kopia zapasowa tworzy się w tle");
                return;
            }

            await RunInitialBackupAsync(emit);
        }
        catch (Exception ex) { emit("err", ex.Message); }
    }

    private async Task RunInitialBackupAsync(Action<string, string> emit)
    {
        _initialBackupCts?.Dispose();
        _initialBackupCts = new CancellationTokenSource();

        emit("busy", "Tworzenie wstępnej kopii danych użytkownika…");
        Ui.Send(() => PostToJs("backup.initial.started", new { }));

        var started = DateTime.UtcNow;
        var outcome = await _backupClient!.BackupNowAsync("initial", (df, tf, db, tb) =>
        {
            double pct = tb > 0 ? db * 100.0 / tb : (tf > 0 ? df * 100.0 / tf : 0);
            double elapsed = (DateTime.UtcNow - started).TotalSeconds;
            long speed = elapsed > 1 ? (long)(db / elapsed) : 0;
            long left = speed > 0 && tb > db ? (tb - db) / speed : 0;

            Ui.Send(() => PostToJs("update.bytes", new
            {
                phase = "prebackup",
                component = "prebackup",
                status = "busy",
                pct,
                speedBps = speed,
                etaSec = left,
                msg = $"Kopia zapasowa: {df}/{tf} plików",
            }));
        }, _initialBackupCts.Token);

        Ui.Send(() => PostToJs("backup.initial.finished", new { }));

        if (outcome.Cancelled)
        {
            emit("uptodate", "Tworzenie kopii przerwane — uruchomisz je w panelu kopii zapasowej");
            return;
        }
        if (!outcome.Ok)
        {
            emit("err", _backupClient.LastError ?? "Nie udało się utworzyć kopii wstępnej");
            return;
        }

        try { File.WriteAllText(InitialBackupMarker, DateTimeOffset.UtcNow.ToString("o")); } catch { }
        BackupSetLastRunNow();
        emit("ok", "Wstępna kopia zapasowa utworzona");
    }

    private void StartInitialBackupInBackground()
    {
        if (_backupRunning) return;
        _backupRunning = true;
        _initialBackupCts?.Dispose();
        _initialBackupCts = new CancellationTokenSource();

        _ = Task.Run(async () =>
        {
            try
            {
                var outcome = await _backupClient!.BackupNowAsync("initial", (df, tf, db, tb) =>
                {
                    double pct = tb > 0 ? db * 100.0 / tb : 0;
                    Ui.Send(() => PostToJs("backup.progress", new
                    {
                        doneFiles = df, totalFiles = tf, doneBytes = db, totalBytes = tb, pct,
                    }));
                }, _initialBackupCts.Token);

                if (outcome.Ok)
                {
                    try { File.WriteAllText(InitialBackupMarker, DateTimeOffset.UtcNow.ToString("o")); } catch { }
                    Ui.Send(BackupSetLastRunNow);
                }
                Ui.Send(() => PostToJs("backup.force.done", new
                {
                    ok = outcome.Ok, cancelled = outcome.Cancelled,
                    error = outcome.Ok ? null : _backupClient.LastError,
                }));
            }
            catch (Exception ex) { CrashLog.Write("initial-backup", ex, null); }
            finally
            {
                _backupRunning = false;
                Ui.Send(() => PostToJs("backup.status.refresh", new { running = false }));
            }
        });
    }

    private void StartScheduledScan(string mode, List<string> folders)
    {
        if (_scanActive || _engine == null) return;

        string target = mode?.ToLowerInvariant() switch
        {
            "full"   => @"C:\",
            "custom" => folders.Count > 0 ? folders[0] : @"C:\Users",
            _        => @"C:\Users",
        };
        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();
        _scanActive = true;
        _scanStartedUtc = DateTime.UtcNow;

        bool memoryEnabled = false;
        try { memoryEnabled = _settings?.Read()?["memory_scan"]?.GetValue<bool>() ?? false; } catch { }

        bool profileRun = mode is "quick" or "full";

        if (memoryEnabled && mode != "memory" && !profileRun)
        {
            _fsFollowupTarget  = target;
            _fsFollowupMode    = mode ?? "quick";
            _fsFollowupFolders = (mode == "custom" && folders.Count > 1) ? new List<string>(folders) : null;
            _runningMemoryScan = true;
            _scanTarget = "[procesy w pamięci]";
            _scanMode   = "memory";
            _tray?.SetBusy(BusyKind.Scan);
            PostScanStarted(_scanTarget, _scanMode);
            EnsureMiniScanPopup();
            _miniScan?.SetMode(ScanProgressForm.Mode.Running, _scanTarget, 0);
            _ = Task.Run(async () =>
            {
                try { await _engine!.RunScanMemoryAsync(_scanCts.Token); }
                catch (Exception ex) { PostToJs("engine.log", new { level = "error", msg = $"memory-scan: {ex.Message}" }); }
                finally { _runningMemoryScan = false; }

            }, _scanCts.Token);
            return;
        }

        bool wieleFolderow = mode == "custom" && folders.Count > 1;

        _scanTarget = wieleFolderow ? string.Join(", ", folders) : target;
        _scanMode = mode ?? "quick";
        _tray?.SetBusy(BusyKind.Scan);
        PostScanStarted(_scanTarget, _scanMode);
        EnsureMiniScanPopup();
        _miniScan?.SetMode(ScanProgressForm.Mode.Running, target, 0);

        _ = Task.Run(async () =>
        {
            try
            {
                if (wieleFolderow)
                {
                    await RunFoldersAsOneScanAsync(target, folders, _scanCts.Token);
                }
                else
                {
                    await _engine!.RunScanAsync(target, _scanCts.Token, profile: profileRun ? mode : null);
                }
            }
            catch (Exception ex) { PostToJs("engine.log", new { level = "error", msg = $"scheduled-scan: {ex.Message}" }); }
            finally { _scanActive = false; _tray?.SetBusy(BusyKind.None); TrimMemoryNow("scan"); }
        });
    }

    private async Task RunFoldersAsOneScanAsync(string target, List<string> folders, CancellationToken ct)
    {
        string? planFile = null;
        try
        {
            planFile = WriteCustomPlan(folders);
            await _engine!.RunScanAsync(target, ct, planFile: planFile);
        }
        finally
        {
            if (planFile != null) { try { File.Delete(planFile); } catch { } }
        }
    }

    private void StartUpdateInBackground()
    {
        if (_updateInProgress) return;
        if (_engine == null) return;
        _updateInProgress = true;
        _tray?.SetBusy(BusyKind.Update);
        EnsureMiniScanPopup();
        _miniScan?.SetMode(ScanProgressForm.Mode.Updating, "Aktualizacja baz wirusów", 0);
        _ = Task.Run(async () =>
        {
            try
            {
                var us = new UpdateService(_settings?.Read(), _engineDir, _scannerEdition);
                await us.UpdateAllAsync(ev =>
                {
                    int pct = (int)Math.Max(0, Math.Min(100, ev.OverallPct * 100));
                    Ui.Send(() =>
                    {
                        if (_miniScan != null && !_miniScan.IsDisposed)
                            _miniScan.UpdateProgressDownload(pct, ev.Phase, ev.Message);
                    });
                    PostToJs("update.bytes", new
                    {
                        phase = ev.Phase, status = ev.Status,
                        downloaded = ev.Downloaded, total = ev.Total,
                        pct = pct, speedBps = ev.SpeedBps, etaSec = ev.EtaSec, msg = ev.Message,
                    });
                });
            }
            catch (Exception ex) { PostToJs("engine.log", new { level = "error", msg = $"update: {ex.Message}" }); }
            finally
            {
                _tray?.SetBusy(BusyKind.None);
                _updateInProgress = false;
                Ui.Send(() =>
                {
                    if (_miniScan != null && !_miniScan.IsDisposed)
                        _miniScan.SetMode(ScanProgressForm.Mode.UpdatingFinished, null, 0);
                });
            }
        });
    }

    private bool NetworkModuleWanted()
    {
        try
        {
            return _network?.IsModuleEnabled() ?? false;
        }
        catch { return false; }
    }

    private void TryExitWithConfirmation()
    {
        if (_scanActive && !WebMode && !Shell.Confirm(
                "Aktywne skanowanie zostanie przerwane. Kontynuować zamykanie?",
                "Malward — potwierdzenie")) return;
        try { _engine?.CancelScanAsync().GetAwaiter().GetResult(); } catch { }
        _scanCts?.Cancel();
        _tray?.Dispose();
        Shell.Shutdown();
    }

    private void Navigate(string hash)
    {
        if (WebMode)
        {
            PushToBrowser("ui.navigate", new { hash });
            return;
        }
        try { WebView!.CoreWebView2.ExecuteScriptAsync($"window.location.hash = {JsonSerializer.Serialize(hash)};"); }
        catch { }
    }

    private void PostToJs(string type, object payload)
    {
        try
        {
            PushToBrowser(type, payload);
            if (WebMode) return;
            SendToWebView(JsonSerializer.Serialize(new { type, payload }, _jsCamel));
        }
        catch { }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private void SendToWebView(string json)
    {
        Ui.Post(() =>
        {
            try
            {
                WebView?.CoreWebView2?.ExecuteScriptAsync(
                    $"window.malward && window.malward.onEvent && window.malward.onEvent({json});");
            }
            catch { }
        });
    }

    private bool BackupIsEnabled()
    {
        try { return _backupSettings.Read()["enabled"]?.GetValue<bool>() ?? false; }
        catch { return false; }
    }

    private void BackupSetEnabled(bool on)
    {
        try { _backupSettings.Merge(new JsonObject { ["enabled"] = on }); } catch { }
    }

    private DateTime BackupLastRunLocal()
    {
        try
        {
            var v = _backupSettings.Read()["last_backup_unix"]?.GetValue<long>() ?? 0;
            return v > 0 ? DateTimeOffset.FromUnixTimeSeconds(v).LocalDateTime : DateTime.MinValue;
        }
        catch { return DateTime.MinValue; }
    }

    private void BackupSetLastRunNow()
    {
        try { _backupSettings.Merge(new JsonObject { ["last_backup_unix"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() }); } catch { }
    }

    private void StartBackupScheduler()
    {
        _backupSchedTimer?.Stop();
        _backupSchedTimer = new UiTimer
        {
            Interval = TimeSpan.FromSeconds(60),
        };
        _backupSchedTimer.Tick += async (_, __) => await ScheduledBackupTickAsync();
        _backupSchedTimer.Start();
    }

    private void StopBackupScheduler()
    {
        _backupSchedTimer?.Stop();
        _backupSchedTimer = null;
    }

    private void SyncWatchProcess()
    {
        bool want;
        try
        {
            var cfg = _backupSettings.Read();
            want = BackupIsEnabled()
                && (cfg["on_file_change"]?.GetValue<bool>() ?? false);
        }
        catch { want = false; }

        bool alive = false;
        try { alive = _backupWatchProc is { HasExited: false }; } catch { alive = false; }

        if (want && !alive)
        {
            var exe = BackupServiceController.FindBkmonitor();
            if (exe == null) return;
            try
            {
                _backupWatchProc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe)
                {
                    Arguments = "watch",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                });
                PostToJs("engine.log", new { level = "info", msg = "BackupEngine: uruchomiono obserwację zmian plików (FsWatch)." });
            }
            catch (Exception ex)
            {
                PostToJs("engine.log", new { level = "warn", msg = "BackupEngine watch start: " + ex.Message });
            }
        }
        else if (!want && alive)
        {
            try { _backupWatchProc!.Kill(entireProcessTree: true); } catch { }
            try { _backupWatchProc!.Dispose(); } catch { }
            _backupWatchProc = null;
            PostToJs("engine.log", new { level = "info", msg = "BackupEngine: zatrzymano obserwację zmian plików." });
        }
    }

    private async Task<T> WithWatchPausedAsync<T>(Func<Task<T>> op)
    {
        bool wasAlive = await Ui.RunAsync(() =>
        {
            bool alive = false;
            try { alive = _backupWatchProc is { HasExited: false }; } catch { }
            if (alive)
            {
                try { _backupWatchProc!.Kill(entireProcessTree: true); } catch { }
                try { _backupWatchProc!.WaitForExit(2500); } catch { }
                try { _backupWatchProc!.Dispose(); } catch { }
                _backupWatchProc = null;
            }
            return alive;
        });
        if (wasAlive) await Task.Delay(400);
        try { return await op(); }
        finally { if (wasAlive) await Ui.RunAsync(SyncWatchProcess); }
    }

    private async Task ScheduledBackupTickAsync()
    {
        if (!BackupIsEnabled() || _backupRunning) return;
        try
        {
            if (await TryFirstBackupWithoutWaitingAsync()) return;

            JsonObject cfg = _backupSettings.Read();
            string schedule = NormalizeBackupSchedule(cfg["schedule"]?.GetValue<string>() ?? "off");
            if (!BackupServiceController.ScheduleActive(schedule)) return;
            var last = BackupLastRunLocal();
            var next = BackupServiceController.NextFire(schedule, last == DateTime.MinValue ? null : last);
            if (DateTime.Now >= next)
                await RunManualBackupAsync(trigger: "schedule");
        }
        catch { }
    }

    private async Task<bool> TryFirstBackupWithoutWaitingAsync()
    {
        if (File.Exists(InitialBackupMarker) || File.Exists(InitialBackupSkipMarker)) return false;
        if (_backupClient == null || !_backupClient.IsAvailable) return false;

        try
        {
            var status = await _backupClient.StatusAsync();
            if (status != null && status.SnapCount > 0)
            {
                try { File.WriteAllText(InitialBackupMarker, DateTimeOffset.UtcNow.ToString("o")); } catch { }
                return false;
            }
        }
        catch { return false; }

        var est = await _backupClient.EstimateAsync();
        long eta = est?.EtaSec ?? -1;
        if (est != null && eta >= 0 && eta <= InitialBackupAskSeconds)
        {
            StartInitialBackupInBackground();
            return true;
        }

        var choice = await AskInitialBackupAsync(est);
        if (choice == "skip")
        {
            try { File.WriteAllText(InitialBackupSkipMarker, DateTimeOffset.UtcNow.ToString("o")); } catch { }
            return true;
        }

        StartInitialBackupInBackground();
        return true;
    }

    private static string NormalizeBackupSchedule(string s)
        => s switch
        {
            "5min" => "everyN:5", "15min" => "everyN:15", "1h" => "everyN:60", "6h" => "everyN:360",
            "daily-2am" => "dailyAt:02:00", "daily-3am" => "dailyAt:03:00", "weekly-sun" => "weeklyAt:0:03:00",
            _ => s ?? "off",
        };

    private async Task RunManualBackupAsync(bool initialIfEmpty = false, string trigger = "manual")
    {
        if (_backupRunning) { PostToJs("backup.force.done", new { ok = false, busy = true }); return; }
        _backupRunning = true;
        PostToJs("backup.status.refresh", new { running = true });
        try
        {
            var ok = await _backupClient.BackupNowAsync(trigger);
            if (ok) BackupSetLastRunNow();
            Ui.Send(() => PostToJs("backup.force.done", new { ok, error = ok ? null : _backupClient.LastError }));
        }
        finally
        {
            _backupRunning = false;
            Ui.Send(() => PostToJs("backup.status.refresh", new { running = false }));
        }
    }

    internal void ShellClosing(System.ComponentModel.CancelEventArgs e)
    {
        _netTimer?.Stop();
        _autoUpdateTimer?.Stop();
        _residentWatchdog?.Stop();
        _ipcTimer?.Stop();
        _scanReqTimer?.Stop();
        _trayHealthTimer?.Stop();
        try { _bgScanCts?.Cancel(); } catch { }
        _backupSchedTimer?.Stop();
        try { if (_backupWatchProc is { HasExited: false }) _backupWatchProc.Kill(entireProcessTree: true); } catch { }
        try { _alertAsk?.Close(); } catch { }
        try { _alertAuto?.Close(); } catch { }
        try { _engine?.CancelScanAsync().GetAwaiter().GetResult(); } catch { }
        _scanCts?.Cancel();

        try { _engine?.Dispose(); } catch { }

        if (_fwAvailable) DisposeFirewall();
        _tray?.Dispose();
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private void DisposeFirewall()
    {
        try { _fwListener?.Dispose(); } catch { }
        try { _fwTempRules?.Dispose(); } catch { }
    }
}
