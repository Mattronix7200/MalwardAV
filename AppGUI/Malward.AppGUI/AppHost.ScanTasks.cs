using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private const string LocalScanId = "local";

    private DateTime? _scanStartedUtc;

    private string _scanToken = "";

    private void PostScanStarted(string target, string mode)
    {
        _scanToken = Guid.NewGuid().ToString("N")[..8];
        PostToJs("scan.started", new { target, mode, token = _scanToken });
    }

    private CancellationTokenSource? _attachCts;

    private List<object> CollectScanTasks()
    {
        var tasks = new List<object>();
        var serviceIds = EngineBridge.ServiceScanIds();
        var driven = _engine?.CurrentServiceScanId;

        if (_scanActive)
        {
            bool viaService = driven != null;
            tasks.Add(new
            {
                id = viaService ? driven! : LocalScanId,
                where = viaService ? "service" : "window",
                attached = true,
                target = _scanTarget,
                mode = _scanMode,
                startedUnix = ToUnix(_scanStartedUtc),
                pct = -1.0,
                file = (string?)null,
                folders = 0,
            });
        }

        foreach (var id in serviceIds)
        {
            if (string.Equals(id, driven, StringComparison.Ordinal)) continue;

            var peek = EngineBridge.PeekServiceScan(id);
            tasks.Add(new
            {
                id,
                where = "service",
                attached = false,
                target = peek.FirstFolder ?? "",
                mode = peek.Profile ?? "custom",
                startedUnix = ToUnix(EngineBridge.ServiceScanStartedUtc(id)),
                pct = peek.Pct,
                file = peek.File,
                folders = peek.FolderCount,
            });
        }

        return tasks;
    }

    private static long ToUnix(DateTime? utc)
        => utc == null ? 0 : new DateTimeOffset(DateTime.SpecifyKind(utc.Value, DateTimeKind.Utc))
                             .ToUnixTimeSeconds();

    private bool QueueBackgroundScan(string target, string mode,
                                     System.Text.Json.Nodes.JsonObject data)
    {
        string? profile = mode is "quick" or "full" ? mode : null;
        string? planFile = null;
        string first = target;

        if (profile == null)
        {
            var targets = ExpandScanTargets(target, mode, data);
            if (targets.Count == 0) return false;
            first = targets[0];
            if (targets.Count > 1) planFile = WriteCustomPlan(targets);
        }

        if (!EngineBridge.SubmitServiceScan(profile != null ? target : first, profile, planFile, out _))
        {
            if (planFile != null) { try { System.IO.File.Delete(planFile); } catch { } }
            return false;
        }

        PostToJs("toast", new { level = "ok",
            msg = "Dodano zadanie skanowania w tle — otwórz „Aktywne zadania skanera”, aby je obserwować." });
        PostToJs("scan.tasks.data", new { items = CollectScanTasks() });
        return true;
    }

    private void CancelScanTask(string id)
    {
        if (string.IsNullOrEmpty(id)) return;

        if (id == LocalScanId)
        {
            HandleMessage("engine.scan.cancel", new System.Text.Json.Nodes.JsonObject());
            return;
        }

        try
        {
            EngineBridge.CancelServiceScan(id);
        }
        catch (Exception ex)
        {
            PostToJs("toast", new { level = "err", msg = $"Nie udało się anulować skanowania: {ex.Message}" });
            return;
        }

        if (string.Equals(id, _engine?.CurrentServiceScanId, StringComparison.Ordinal))
            HandleMessage("engine.scan.cancel", new System.Text.Json.Nodes.JsonObject());
        else
            _attachCts?.Cancel();

        PostToJs("toast", new { level = "ok", msg = "Anulowanie skanowania zlecone." });
        PostToJs("scan.tasks.data", new { items = CollectScanTasks() });
    }

    private void AttachToScanTask(string id)
    {
        if (string.IsNullOrEmpty(id) || _engine == null) return;

        var driven = _engine.CurrentServiceScanId;
        if (string.Equals(driven, id, StringComparison.Ordinal))
        {
            PostToJs("ui.navigate", new { hash = "#/scan/progress" });
            return;
        }

        bool handover = _scanActive;
        if (handover && driven == null)
        {
            PostToJs("toast", new { level = "warn",
                msg = "To okno prowadzi skanowanie w swoim procesie — anuluj je, zanim przejdziesz do innego zadania." });
            return;
        }

        if (handover)
        {
            _engine.DetachRequested = true;
            _scanCts?.Cancel();
        }

        _attachCts?.Dispose();
        _attachCts = new CancellationTokenSource();
        var ct = _attachCts.Token;

        _ = Task.Run(async () =>
        {
            for (int i = 0; handover && _scanActive && i < 100; i++)
                await Task.Delay(50, CancellationToken.None);

            var peek = EngineBridge.PeekServiceScan(id);
            var started = EngineBridge.ServiceScanStartedUtc(id) ?? DateTime.UtcNow;

            Ui.Send(() =>
            {
                _scanActive = true;
                _scanTarget = peek.FirstFolder ?? "";
                _scanMode = peek.Profile ?? "custom";
                _scanStartedUtc = started;
                lock (_currentScanResults) _currentScanResults.Clear();
                _tray?.SetBusy(BusyKind.Scan);
                PostScanStarted(_scanTarget, _scanMode);
                PostToJs("ui.navigate", new { hash = "#/scan/progress" });
            });

            try { await _engine.AttachToServiceScanAsync(id, ct); }
            catch (Exception ex) { CrashLog.Write("scan-attach", ex, id); }
            finally
            {
                _scanActive = false;
                Ui.Send(() => _tray?.SetBusy(BusyKind.None));
            }
        }, CancellationToken.None);
    }
}
