using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;

namespace Malward.AppGUI.Services;

public static class BackupServiceController
{
    public const string LegacyServiceName = "MalwardBackupEngine";

    public static string? FindBkmonitor()
    {
        var dirs = new[] { EngineLocator.GuiExeDir, EngineLocator.EngineDir() };
        foreach (var d in dirs)
        {
            if (string.IsNullOrEmpty(d)) continue;
            try
            {
                var p = Path.Combine(d, "bkmonitor.exe");
                if (File.Exists(p)) return Path.GetFullPath(p);
            }
            catch { }
        }
        return null;
    }

    public static async Task CleanupLegacyAsync()
    {
        try
        {
            await RunSc("stop " + LegacyServiceName);
            await RunSc("delete " + LegacyServiceName);
        }
        catch { }

        try
        {
            foreach (var p in Process.GetProcessesByName("bkmonitor"))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                try { p.Dispose(); } catch { }
            }
        }
        catch { }
    }

    private static async Task RunSc(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", args)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = Process.Start(psi);
            if (p != null) await Task.Run(() => p.WaitForExit(6000));
        }
        catch { }
    }

    public static bool ScheduleActive(string schedule)
        => !string.IsNullOrWhiteSpace(schedule) && !schedule.Equals("off", StringComparison.OrdinalIgnoreCase);

    public static DateTime NextFire(string schedule, DateTime? lastFireLocal)
    {
        var now = DateTime.Now;
        if (!ScheduleActive(schedule)) return DateTime.MaxValue;
        try
        {
            if (schedule.StartsWith("everyN:", StringComparison.OrdinalIgnoreCase))
            {
                int mins = int.Parse(schedule["everyN:".Length..], CultureInfo.InvariantCulture);
                if (mins < 1) mins = 1;
                var basis = lastFireLocal ?? now;
                var next = basis.AddMinutes(mins);
                return next <= now ? now.AddMinutes(mins) : next;
            }
            if (schedule.StartsWith("dailyAt:", StringComparison.OrdinalIgnoreCase))
            {
                var (h, m) = Hm(schedule["dailyAt:".Length..]);
                var t = new DateTime(now.Year, now.Month, now.Day, h, m, 0);
                if (t <= now) t = t.AddDays(1);
                return t;
            }
            if (schedule.StartsWith("weeklyAt:", StringComparison.OrdinalIgnoreCase))
            {
                var rest = schedule["weeklyAt:".Length..];
                int c = rest.IndexOf(':');
                int dow = int.Parse(rest[..c], CultureInfo.InvariantCulture);
                var (h, m) = Hm(rest[(c + 1)..]);
                var t = new DateTime(now.Year, now.Month, now.Day, h, m, 0);
                int delta = ((dow % 7) - (int)now.DayOfWeek + 7) % 7;
                t = t.AddDays(delta);
                if (t <= now) t = t.AddDays(7);
                return t;
            }
        }
        catch { }
        return DateTime.MaxValue;
    }

    private static (int, int) Hm(string hm)
    {
        var p = hm.Split(':');
        int h = p.Length > 0 && int.TryParse(p[0], out var hv) ? hv : 0;
        int m = p.Length > 1 && int.TryParse(p[1], out var mv) ? mv : 0;
        return (Math.Clamp(h, 0, 23), Math.Clamp(m, 0, 59));
    }
}
