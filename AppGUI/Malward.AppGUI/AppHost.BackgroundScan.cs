using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private CancellationTokenSource? _bgScanCts;
    private Task? _bgScanTask;
    private volatile bool _bgScanRunning;

    private readonly Dictionary<string, DateTime> _bgSeen = new(StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> BgScanExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".msi",
        ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".jar", ".wsf",
        ".zip", ".rar", ".7z",
    };

    private bool BackgroundScanAllowed()
    {
        try
        {
            if (!(_settings?.Read()?["background_scan_enabled"]?.GetValue<bool>() ?? true)) return false;
            if (_resident == null) return false;
            return ResidentModuleWanted() && _resident.State() == "running";
        }
        catch { return false; }
    }

    private void SyncBackgroundScan()
    {
        bool allowed = BackgroundScanAllowed();
        if (allowed && !_bgScanRunning)
        {
            _bgScanCts = new CancellationTokenSource();
            _bgScanRunning = true;
            var ct = _bgScanCts.Token;
            _bgScanTask = Task.Run(() => BackgroundScanLoop(ct), ct);
        }
        else if (!allowed && _bgScanRunning)
        {
            try { _bgScanCts?.Cancel(); } catch { }
            _bgScanRunning = false;
        }
    }

    private void StartBackgroundScan() => SyncBackgroundScan();

    private void BackgroundScanLoop(CancellationToken ct)
    {
        try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }
        var root = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var opts = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Device,
        };

        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!string.IsNullOrEmpty(root) && Directory.Exists(root))
                {
                    foreach (var file in Directory.EnumerateFiles(root, "*", opts))
                    {
                        if (ct.IsCancellationRequested) break;

                        while (_scanActive && !ct.IsCancellationRequested) Thread.Sleep(2000);
                        if (!BackgroundScanAllowed()) return;

                        var ext = Path.GetExtension(file);
                        if (string.IsNullOrEmpty(ext) || !BgScanExts.Contains(ext)) continue;
                        if (RecentlySeen(file)) continue;

                        ScanOneFileSilently(file);
                        MarkSeen(file);
                        Thread.Sleep(600);
                    }
                }
            }
            catch {  }

            PruneSeen();
            for (int i = 0; i < 3600 && !ct.IsCancellationRequested; i++) Thread.Sleep(1000);
        }
    }

    private bool RecentlySeen(string path)
    {
        lock (_bgSeen)
            return _bgSeen.TryGetValue(path, out var t) && (DateTime.UtcNow - t) < TimeSpan.FromHours(6);
    }

    private void MarkSeen(string path)
    {
        lock (_bgSeen) _bgSeen[path] = DateTime.UtcNow;
    }

    private void PruneSeen()
    {
        lock (_bgSeen)
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromHours(6);
            foreach (var k in new List<string>(_bgSeen.Keys))
                if (_bgSeen[k] < cutoff) _bgSeen.Remove(k);
        }
    }

    private readonly List<BackgroundHit> _bgPending = new();
    private UiTimer? _bgNotifyTimer;

    private void QueueBackgroundDetection(string fileName, string detection, string fullPath = "")
    {
        Ui.Send(() =>
        {
            lock (_bgPending)
            {
                if (_bgPending.Count < 200)
                    _bgPending.Add(new BackgroundHit(fileName, detection,
                        string.IsNullOrEmpty(fullPath) ? fileName : fullPath));
            }
            if (_bgNotifyTimer == null)
            {
                _bgNotifyTimer = new UiTimer
                { Interval = TimeSpan.FromSeconds(6) };
                _bgNotifyTimer.Tick += (_, _) => FlushBackgroundDetections();
            }

            _bgNotifyTimer.Stop();
            _bgNotifyTimer.Start();
        });
    }

    private sealed record BackgroundHit(string FileName, string Detection, string FullPath);

    private void FlushBackgroundDetections()
    {
        _bgNotifyTimer?.Stop();
        List<BackgroundHit> items;
        lock (_bgPending)
        {
            if (_bgPending.Count == 0) return;
            items = new List<BackgroundHit>(_bgPending);
            _bgPending.Clear();
        }

        try
        {
            var evts = items.Select(h => new Services.ResidentIpc.ShieldEvent(
                Id: Guid.NewGuid().ToString("N"),
                Mode: "auto",
                File: h.FullPath,
                Name: h.FileName,
                Detection: h.Detection,
                Action: "quarantine",
                Ts: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Process: "")).ToList();

            string theme = "auto";
            try { theme = _guiSettings?.Read()?.Theme ?? "auto"; } catch { }
            ShowAlertWindow("auto", evts, theme, sound: true);

            if (!_scannerEdition) PushProtectionStatus();
        }
        catch { }
    }

    private void ScanOneFileSilently(string file)
    {
        try
        {
            var malscan = _verify?.MalscanPath;
            if (string.IsNullOrEmpty(malscan) || !File.Exists(malscan) || !File.Exists(file)) return;

            var det = RunMalscanDetect(malscan!, file);
            if (string.IsNullOrEmpty(det)) return;

            var psi = new System.Diagnostics.ProcessStartInfo(malscan!,
                $"repair quarantine \"{file}\" --detection \"{det}\"")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            psi.Environment["MALWARD_MACHINE_OUTPUT"] = "1";
            using (var p = System.Diagnostics.Process.Start(psi)) { p?.WaitForExit(60000); }

            try
            {
                _statsStore?.IncDetections(1);
                Ui.Send(() =>
                {
                    QueueBackgroundDetection(Path.GetFileName(file), det!, file);
                    if (!_scannerEdition) PushProtectionStatus();
                });
            }
            catch { }
        }
        catch {  }
    }
}
