using System;
using System.Linq;
using Malward.AppGUI.Services;

namespace Malward.AppGUI;

public partial class AppHost
{
    private UiTimer? _memTrimTimer;
    private long _memTrimLast;

    private static readonly TimeSpan MemTrimEvery = TimeSpan.FromMinutes(1);

    private void StartIdleMemoryTrim()
    {
        if (!WebMode || _memTrimTimer != null) return;

        _memTrimTimer = new UiTimer { Interval = MemTrimEvery };
        _memTrimTimer.Tick += (_, _) => TrimMemoryIfIdle();
        _memTrimTimer.Start();

        ReportMemoryFootprint();
        TrimMemoryNow("startup");
    }

    private static void ReportMemoryFootprint()
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetCurrentProcess();
            proc.Refresh();

            var nazwy = AppDomain.CurrentDomain.GetAssemblies()
                .Select(a => a.GetName().Name ?? "")
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            string Czy(string n) => nazwy.Contains(n) ? "tak" : "nie";

            CrashLog.Write("memory", null,
                $"web mode: working set {proc.WorkingSet64 / (1024 * 1024)} MB, "
              + $"private {proc.PrivateMemorySize64 / (1024 * 1024)} MB, "
              + $"assemblies {nazwy.Count}; "
              + $"WPF={Czy("PresentationFramework")} "
              + $"WinForms={Czy("System.Windows.Forms")} "
              + $"WebView2={Czy("Microsoft.Web.WebView2.Wpf")}");
        }
        catch { }
    }

    private void TrimMemoryIfIdle()
    {
        if (_scanActive || _updateInProgress) return;
        TrimMemoryNow("idle");
    }

    internal void TrimMemoryNow(string reason)
    {
        if (!WebMode) return;

        var now = Environment.TickCount64;
        if (now - _memTrimLast < 20_000) return;
        _memTrimLast = now;

        try
        {
            long freed = Malward.Engine.Util.MemoryTrim.AfterLongRun();
            if (freed > 4L * 1024 * 1024)
                CrashLog.Write("memory", null,
                    $"working set trimmed after {reason}: {freed / (1024 * 1024)} MB released");
        }
        catch { }
    }
}
